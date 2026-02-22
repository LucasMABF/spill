use bitcoin::Psbt;

use crate::{Channel, SpillError, channel::backend::ChannelBackend};

impl<B: ChannelBackend + Clone> Channel<B> {
    /// Finalizes a refund PSBT for broadcast.
    ///
    /// Takes a mutable refund PSBT containing the payer's signature
    /// and sets the proper witness for the payer to claim the funds.
    /// After calling this method, the PSBT is ready to be converted
    /// into a valid transaction for broadcast.
    ///
    /// # Errors
    ///
    /// Returns `SpillError::Finalize` if:
    /// - `MissingSignature`: The payer's signature is missing from the PSBT.
    /// - `MissingWitnessScript`: The PSBT input lacks a witness script.
    pub fn finalize_refund_tx(&self, psbt: &mut Psbt) -> Result<(), SpillError> {
        self.params
            .backend
            .finalize_refund_tx(psbt, &self.params.payer)
    }

    /// Finalizes a payment PSBT for broadcast.
    ///
    /// Takes a mutable payment PSBT containing the payer's and payee's signatures
    /// and sets the proper witness for the payee to claim the last payment.
    /// After calling this method, the PSBT is ready to be converted into a valid
    /// transaction for broadcast.
    ///
    /// # Errors
    ///
    /// Returns `SpillError::Finalize` if:
    /// - `MissingSignature`: The PSBT is missing the payer's or payee's signature.
    /// - `MissingWitnessScript`: The PSBT input lacks a witness script.
    pub fn finalize_payment_tx(&self, psbt: &mut Psbt) -> Result<(), SpillError> {
        self.params
            .backend
            .finalize_payment_tx(psbt, &self.params.payer, &self.params.payee)
    }
}
