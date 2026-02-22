use crate::{
    Channel, ChannelParams, FundingError, PaymentError, SpillError,
    channel::{backend::ChannelBackend, payment::PaymentInfo},
};
use bitcoin::{Amount, NumOpResult, OutPoint, Psbt, Sequence, Transaction, absolute::LockTime};

impl<B: ChannelBackend + Clone> ChannelParams<B> {
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
    ) -> Result<Channel<B>, SpillError> {
        if tx.compute_txid() != outpoint.txid {
            return Err(FundingError::TxidMismatch.into());
        }

        let output = tx
            .outputs
            .get(outpoint.vout as usize)
            .ok_or(FundingError::OutputNotFound)?;

        if output.amount != self.capacity {
            return Err(FundingError::ValueMismatch.into());
        }

        if output.script_pubkey != self.script_pubkey {
            return Err(FundingError::ScriptMismatch.into());
        }

        Ok(Channel {
            params: self.clone(),
            funding_outpoint: outpoint,
            funding_utxo: output.clone(),
            sent: Amount::ZERO,
        })
    }
}

impl<B: ChannelBackend + Clone> Channel<B> {
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
    /// - `NonZeroLockTime`: The transaction lock time is not zero.
    /// - `MissingPayeeOutput`: No output exists for the payee.
    /// - `PaymentNotIncremental`: The payment does not increase the cumulative amount.
    /// - `OutputsExceedFundingAmount`: The total outputs exceed the channel capacity.
    /// - `MissingSignature`: No signature from the payer is present.
    /// - `InvalidSighash`: The signature sighash type is unsupported (must be ALL or ALL|ANYONECANPAY).
    /// - `InvalidSignature`: The payer's signature is invalid.
    /// - `AmountOverflow`: Amount operation errored.
    /// - `ScriptPubKeyMismatch`: The input's script_pubkey does not match the channel funding
    ///   script_pubkey.
    pub fn verify_payment_psbt(&self, psbt: &Psbt) -> Result<PaymentInfo, SpillError> {
        if psbt.inputs.len() > 1 {
            return Err(PaymentError::MultipleInputs.into());
        }

        let outpoint = psbt
            .unsigned_tx
            .inputs
            .first()
            .ok_or(PaymentError::MissingInput)?
            .previous_output;

        if outpoint != self.funding_outpoint {
            return Err(PaymentError::FundingOutpointMismatch.into());
        }

        let witness_utxo = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .ok_or(PaymentError::MissingWitnessUtxo)?;

        if witness_utxo != &self.funding_utxo {
            return Err(PaymentError::WitnessUtxoMismatch.into());
        }

        if witness_utxo.script_pubkey != self.params.script_pubkey {
            return Err(PaymentError::ScriptPubKeyMismatch.into());
        }

        let sequence = psbt.unsigned_tx.inputs[0].sequence;

        if sequence != Sequence::MAX {
            return Err(PaymentError::InvalidSequence.into());
        }

        let lock_time = psbt.unsigned_tx.lock_time;

        if lock_time != LockTime::ZERO {
            return Err(PaymentError::NonZeroLockTime.into());
        }

        let payee_script = self.params.backend.payee_script(&self.params.payee)?;

        let new_payment_amount = psbt
            .unsigned_tx
            .outputs
            .iter()
            .find(|o| o.script_pubkey == payee_script)
            .ok_or(PaymentError::MissingPayeeOutput)?
            .amount;

        if new_payment_amount <= self.sent {
            return Err(PaymentError::PaymentNotIncremental.into());
        }

        let total_output: Amount = psbt
            .unsigned_tx
            .outputs
            .iter()
            .map(|o| o.amount)
            .fold(NumOpResult::Valid(Amount::ZERO), |acc, item| acc + item)
            .into_result()
            .map_err(|_| PaymentError::AmountOverflow)?;

        if total_output > self.params.capacity {
            return Err(PaymentError::OutputsExceedFundingAmount.into());
        }

        self.params
            .backend
            .verify_payment(psbt, &self.params.payer, self.params.capacity)?;

        Ok(PaymentInfo {
            total: new_payment_amount,
            current: (new_payment_amount - self.sent)
                .into_result()
                .expect("verify_payment_psbt: internal invariant violated (Amount calculation must be valid)"),
            fee: (self.params.capacity - total_output)
                .into_result()
                .expect("verify_payment_psbt: internal invariant violated (Amount calculation must be valid)"),
        })
    }
}
