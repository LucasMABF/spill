use bitcoin::{
    Amount, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};

use crate::{Channel, PaymentError, SpillError};

impl Channel {
    pub fn next_payment(&self, amount: Amount, fee: Amount) -> Result<Psbt, SpillError> {
        let required = amount + self.sent + fee;
        if required > self.params.capacity {
            return Err(SpillError::Payment(PaymentError::ExceedsCapacity {
                available: self.params.capacity,
                required,
            }));
        }

        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let payment = TxOut {
            value: amount + self.sent,
            script_pubkey: ScriptBuf::new_p2wpkh(&self.params.payee.wpubkey_hash()?),
        };

        let change = TxOut {
            value: self.params.capacity - required,
            script_pubkey: ScriptBuf::new_p2wpkh(&self.params.payer.wpubkey_hash()?),
        };

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![payment, change],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("next_payment: internal invariant violated (tx must be unsigned)");

        psbt.inputs[0].witness_script = Some(self.params.funding_script.clone());

        psbt.inputs[0].witness_utxo = Some(self.funding_utxo.clone());

        Ok(psbt)
    }

    pub fn apply_payment(&mut self, psbt: &Psbt) -> Result<(), SpillError> {
        let payment = self.verify_payment_psbt(psbt)?;
        self.sent = payment.total;
        Ok(())
    }
}
