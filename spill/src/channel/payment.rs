use bitcoin::{
    Amount, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};

use crate::{Channel, PaymentError, SpillError};

/// Information about a verified payment.
///
/// `PaymentInfo` summarizes the effects of a payment after successful
/// verification, allowing callers to inspect the payment before applying
/// it to the channel state.
pub struct PaymentInfo {
    /// Total amount paid to the payee after this payment.
    pub total: Amount,
    /// Amount transfered in this payment.
    pub current: Amount,
    /// Fee paid by the payer for this payment.
    pub fee: Amount,
}

impl Channel {
    /// Constructs a PSBT for the next payment in the channel.
    ///
    /// The returned PSBT represents a payment from the payer to the payee
    /// for the specified `amount` with an included `fee`. The PSBT can be
    /// signed by the payer and then broadcast, or further inspected before signing.
    ///
    /// # Errors
    ///
    /// Returns `SpillError::Payment(PaymentError::ExceedsCapacity)` if the requested
    /// amount plus previously sent amounts and fee exceeds the channel capacity.
    ///
    /// # Details
    ///
    /// - The PSBT contains a single input referencing the channel's funding outpoint.
    /// - The input's witness UTXO and witness script are set according to the
    ///   channel's funding transaction.
    /// - The PSBT has two outputs:
    ///     1. The payment to the payee (cumulative amount).
    ///     2. The change back to the payer.
    /// - The transaction has version 2, sequence `MAX`, and locktime 0.
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

    /// Applies a payment to the channel state.
    ///
    /// This method first verifies the provided PSBT using
    /// [`Channel::verify_payment_psbt`]. If verification succeeds, the channel's
    /// `sent` amount is updated to reflect the cumulative total in the PSBT.
    ///
    /// # Errors
    ///
    /// Returns a `SpillError::Payment` variant if the PSBT fails verification
    /// (e.g., missing outputs, invalid signatures, etc.).
    pub fn apply_payment(&mut self, psbt: &Psbt) -> Result<(), SpillError> {
        let payment = self.verify_payment_psbt(psbt)?;
        self.sent = payment.total;
        Ok(())
    }
}
