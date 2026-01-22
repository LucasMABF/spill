use bitcoin::{Psbt, Witness};

use crate::{Channel, FinalizeError, SpillError};

impl Channel {
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
    ///
    /// # Details
    ///
    /// - The witness stack is constructed according to the channel's funding script:
    ///     1. The payer's signature (DER + sighash byte)
    ///     2. OP_FALSE to select the refund branch
    ///     3. The witness script
    /// - Clears `partial_sigs` after finalizing.
    pub fn finalize_refund_tx(&self, psbt: &mut Psbt) -> Result<(), SpillError> {
        let mut witness = Witness::new();
        let input = &mut psbt.inputs[0];

        let sig_payer = input
            .partial_sigs
            .get(&self.params.payer)
            .ok_or(SpillError::Finalize(FinalizeError::MissingSignature {
                public_key: self.params.payer,
            }))?;
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        witness.push(vec![0]); // OP_FALSE take OP_ELSE branch

        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or(SpillError::Finalize(FinalizeError::MissingWitnessScript))?;
        witness.push(witness_script.to_bytes());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();

        Ok(())
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
    ///
    /// # Details
    ///
    /// - The witness stack is constructed according to the channel's funding script:
    ///     1. OP_0 (dummy for CHECKMULTISIG)
    ///     2. Payer's signature (DER + sighash byte)
    ///     3. Payee's signature (DER + sighash byte)
    ///     4. OP_TRUE to select the payment branch
    ///     5. The witness script
    /// - Clears `partial_sigs` after finalizing.
    pub fn finalize_payment_tx(&self, psbt: &mut Psbt) -> Result<(), SpillError> {
        let mut witness = Witness::new();
        witness.push(vec![]);

        let input = &mut psbt.inputs[0];

        let sig_payer = input
            .partial_sigs
            .get(&self.params.payer)
            .ok_or(SpillError::Finalize(FinalizeError::MissingSignature {
                public_key: self.params.payer,
            }))?;
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        let sig_payee = input
            .partial_sigs
            .get(&self.params.payee)
            .ok_or(SpillError::Finalize(FinalizeError::MissingSignature {
                public_key: self.params.payee,
            }))?;
        let mut sig_payee_bytes = sig_payee.signature.serialize_der().to_vec();
        sig_payee_bytes.push(sig_payee.sighash_type.to_u32() as u8);
        witness.push(sig_payee_bytes);

        witness.push(vec![1]); // OP_TRUE take OP_IF branch

        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or(SpillError::Finalize(FinalizeError::MissingWitnessScript))?;
        witness.push(witness_script.to_bytes());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();

        Ok(())
    }
}
