use crate::{
    Channel, ChannelParams, FundingError, PaymentError, SpillError, channel::payment::PaymentInfo,
};
use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, absolute::LockTime,
    secp256k1, sighash::SighashCache,
};

impl ChannelParams {
    /// Verifies a funding transaction against the channel parameters.
    ///
    /// Ensures that the provided transaction and outpoint match the channel's
    /// expected funding transaction. If verification succeeds, returns a new
    /// [`Channel`] initialized with the funding outpoint and UTXO.
    ///
    /// # Errors
    ///
    /// Returns a `SpillError::Funding` variant if verification fails:
    /// - `TxidMismatch`: Transaction ID does not match the funding outpoint.
    /// - `OutputNotFound`: No output exists at the specified index.
    /// - `ValueMismatch`: Output value does not match the channel capacity.
    /// - `ScriptMismatch`: Output script does not match the channel's funding script.
    pub fn verify_funding_tx(
        &self,
        tx: &Transaction,
        outpoint: OutPoint,
    ) -> Result<Channel, SpillError> {
        if tx.compute_txid() != outpoint.txid {
            return Err(SpillError::Funding(FundingError::TxidMismatch));
        }

        let output = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(SpillError::Funding(FundingError::OutputNotFound))?;

        if output.value != self.capacity {
            return Err(SpillError::Funding(FundingError::ValueMismatch));
        }

        let expected_script = ScriptBuf::new_p2wsh(&self.funding_script.wscript_hash());
        if output.script_pubkey != expected_script {
            return Err(SpillError::Funding(FundingError::ScriptMismatch));
        }

        Ok(Channel {
            params: self.clone(),
            funding_outpoint: outpoint,
            funding_utxo: output.clone(),
            sent: Amount::ZERO,
        })
    }
}

impl Channel {
    /// Verifies a payment PSBT against the channel state.
    ///
    /// Ensures that the provided PSBT correctly represents a payment from the
    /// payer to the payee according to the channel's rules. If verification
    /// succeeds, returns a [`PaymentInfo`] containing the cumulative and
    /// incremental amounts and the fee.
    ///
    /// # Errors
    ///
    /// Returns a `SpillError::Payment` variant if verification fails:
    /// - `MultipleInputs`: The PSBT contains more than one input.
    /// - `MissingInput`: The PSBT has no inputs.
    /// - `FundingOutpointMismatch`: The PSBT doesn't reference the funding outpoint.
    /// - `MissingWitnessUtxo`: The input lacks a witness UTXO.
    /// - `WitnessUtxoMismatch`: The witness UTXO does not match the channel funding UTXO.
    /// - `MissingWitnessScript`: The input lacks a witness script.
    /// - `WitnessScriptMismatch`: The witness script does not match the channel funding script.
    /// - `InvalidSequence`: The input sequence is not MAX.
    /// - `NonZeroLocktime`: The transaction locktime is not zero.
    /// - `MissingPayeeOutput`: No output exists for the payee.
    /// - `PaymentNotIncremental`: The payment does not increase the cumulative amount.
    /// - `OutputsExceedFundingAmount`: The total outputs exceed the channel capacity.
    /// - `MissingSignature`: No signature from the payer is present.
    /// - `InvalidSighash`: The signature sighash type is unsupported (must be ALL or ALL|ANYONECANPAY).
    /// - `InvalidSignature`: The payer's signature is invalid.
    pub fn verify_payment_psbt(&self, psbt: &Psbt) -> Result<PaymentInfo, SpillError> {
        if psbt.inputs.len() > 1 {
            return Err(SpillError::Payment(PaymentError::MultipleInputs));
        }

        let outpoint = psbt
            .unsigned_tx
            .input
            .first()
            .ok_or(SpillError::Payment(PaymentError::MissingInput))?
            .previous_output;

        if outpoint != self.funding_outpoint {
            return Err(SpillError::Payment(PaymentError::FundingOutpointMismatch));
        }

        let witness_utxo = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .ok_or(SpillError::Payment(PaymentError::MissingWitnessUtxo))?;

        if witness_utxo != &self.funding_utxo {
            return Err(SpillError::Payment(PaymentError::WitnessUtxoMismatch));
        }

        let witness_script = psbt.inputs[0]
            .witness_script
            .as_ref()
            .ok_or(SpillError::Payment(PaymentError::MissingWitnessScript))?;

        if witness_script != &self.params.funding_script {
            return Err(SpillError::Payment(PaymentError::WitnessScriptMismatch));
        }

        let sequence = psbt.unsigned_tx.input[0].sequence;

        if sequence != Sequence::MAX {
            return Err(SpillError::Payment(PaymentError::InvalidSequence));
        }

        let locktime = psbt.unsigned_tx.lock_time;

        if locktime != LockTime::ZERO {
            return Err(SpillError::Payment(PaymentError::NonZeroLocktime));
        }

        let payee_script = ScriptBuf::new_p2wpkh(&self.params.payee.wpubkey_hash()?);

        let new_payment_amount = psbt
            .unsigned_tx
            .output
            .iter()
            .find(|o| o.script_pubkey == payee_script)
            .ok_or(SpillError::Payment(PaymentError::MissingPayeeOutput))?
            .value;

        if new_payment_amount <= self.sent {
            return Err(SpillError::Payment(PaymentError::PaymentNotIncremental));
        }

        let total_output: Amount = psbt.unsigned_tx.output.iter().map(|o| o.value).sum();

        if total_output > self.params.capacity {
            return Err(SpillError::Payment(
                PaymentError::OutputsExceedFundingAmount,
            ));
        }

        let sig = psbt.inputs[0]
            .partial_sigs
            .get(&self.params.payer)
            .ok_or(SpillError::Payment(PaymentError::MissingSignature))?;

        if sig.sighash_type != EcdsaSighashType::All
            && sig.sighash_type == EcdsaSighashType::AllPlusAnyoneCanPay
        {
            return Err(SpillError::Payment(PaymentError::InvalidSighash));
        }

        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = cache
            .p2wsh_signature_hash(0, witness_script, self.params.capacity, sig.sighash_type)
            .expect("verify_payment_psbt: internal invariant (sign input 0)");

        let msg = secp256k1::Message::from_digest_slice(&sighash[..])
            .expect("verify_payment_psbt: internal invariant (sighash size)");

        if secp256k1::Secp256k1::verification_only()
            .verify_ecdsa(&msg, &sig.signature, &self.params.payer.inner)
            .is_err()
        {
            return Err(SpillError::Payment(PaymentError::InvalidSignature));
        }

        Ok(PaymentInfo {
            total: new_payment_amount,
            current: new_payment_amount - self.sent,
            fee: self.params.capacity - total_output,
        })
    }
}
