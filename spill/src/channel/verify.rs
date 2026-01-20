use crate::{Channel, ChannelParams, SpillError};
use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, absolute::LockTime,
    secp256k1, sighash::SighashCache,
};

impl ChannelParams {
    pub fn verify_funding_tx(
        &self,
        tx: &Transaction,
        outpoint: OutPoint,
    ) -> Result<Channel, SpillError> {
        if tx.compute_txid() != outpoint.txid {
            return Err(SpillError::FundingTxidMismatch);
        }

        let output = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(SpillError::FundingOutputNotFound)?;

        if output.value != self.capacity {
            return Err(SpillError::FundingValueMismatch);
        }

        let expected_script = ScriptBuf::new_p2wsh(&self.funding_script.wscript_hash());
        if output.script_pubkey != expected_script {
            return Err(SpillError::FundingScriptMismatch);
        }

        Ok(Channel {
            params: self.clone(),
            funding_outpoint: outpoint,
            funding_utxo: output.clone(),
            sent: Amount::ZERO,
        })
    }
}

pub struct PaymentInfo {
    pub total: Amount,
    pub current: Amount,
    pub fee: Amount,
}

impl Channel {
    pub fn verify_payment_psbt(&self, psbt: &Psbt) -> Result<PaymentInfo, SpillError> {
        if psbt.inputs.len() > 1 {
            return Err(SpillError::PaymentMultipleInputs);
        }

        let outpoint = psbt
            .unsigned_tx
            .input
            .first()
            .ok_or(SpillError::PaymentMissingInput)?
            .previous_output;

        if outpoint != self.funding_outpoint {
            return Err(SpillError::PaymentWrongInput);
        }

        let witness_utxo = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .ok_or(SpillError::PaymentMissingWitnessUtxo)?;

        if witness_utxo != &self.funding_utxo {
            return Err(SpillError::PaymentWitnessUtxoMismatch);
        }

        let witness_script = psbt.inputs[0]
            .witness_script
            .as_ref()
            .ok_or(SpillError::PaymentMissingWitnessScript)?;

        if witness_script != &self.params.funding_script {
            return Err(SpillError::PaymentWitnessScriptMismatch);
        }

        let sequence = psbt.unsigned_tx.input[0].sequence;

        if sequence != Sequence::MAX {
            return Err(SpillError::PaymentInvalidSequence);
        }

        let locktime = psbt.unsigned_tx.lock_time;

        if locktime != LockTime::ZERO {
            return Err(SpillError::PaymentNonZeroLocktime);
        }

        let payee_script = ScriptBuf::new_p2wpkh(&self.params.payee.wpubkey_hash()?);

        let new_payment_amount = psbt
            .unsigned_tx
            .output
            .iter()
            .find(|o| o.script_pubkey == payee_script)
            .ok_or(SpillError::PaymentMissingPayeeOutput)?
            .value;

        if new_payment_amount <= self.sent {
            return Err(SpillError::PaymentInvalidValue);
        }

        let total_output: Amount = psbt.unsigned_tx.output.iter().map(|o| o.value).sum();

        if total_output > self.params.capacity {
            return Err(SpillError::PaymentInvalidOutputSum);
        }

        let sig = psbt.inputs[0]
            .partial_sigs
            .get(&self.params.payer)
            .ok_or(SpillError::PaymentMissingSignature)?;

        if sig.sighash_type != EcdsaSighashType::All
            && sig.sighash_type == EcdsaSighashType::AllPlusAnyoneCanPay
        {
            return Err(SpillError::PaymentInvalidSighash);
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
            return Err(SpillError::PaymentInvalidSignature);
        }

        Ok(PaymentInfo {
            total: new_payment_amount,
            current: new_payment_amount - self.sent,
            fee: self.params.capacity - total_output,
        })
    }
}
