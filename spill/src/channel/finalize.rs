use bitcoin::{Psbt, Witness};

use crate::{Channel, SpillError};

impl Channel {
    pub fn finalize_refund_tx(&self, psbt: &mut Psbt) -> Result<(), SpillError> {
        let mut witness = Witness::new();
        let input = &mut psbt.inputs[0];

        let sig_payer =
            input
                .partial_sigs
                .get(&self.params.payer)
                .ok_or(SpillError::PsbtMissingSignature {
                    public_key: self.params.payer,
                })?;
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        witness.push(vec![0]); // OP_FALSE take OP_ELSE branch

        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or(SpillError::PsbtMissingWitnessScript)?;
        witness.push(witness_script.to_bytes());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();

        Ok(())
    }

    pub fn finalize_payment_tx(&self, psbt: &mut Psbt) -> Result<(), SpillError> {
        let mut witness = Witness::new();
        witness.push(vec![]);

        let input = &mut psbt.inputs[0];

        let sig_payer =
            input
                .partial_sigs
                .get(&self.params.payer)
                .ok_or(SpillError::PsbtMissingSignature {
                    public_key: self.params.payer,
                })?;
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        let sig_payee =
            input
                .partial_sigs
                .get(&self.params.payee)
                .ok_or(SpillError::PsbtMissingSignature {
                    public_key: self.params.payee,
                })?;
        let mut sig_payee_bytes = sig_payee.signature.serialize_der().to_vec();
        sig_payee_bytes.push(sig_payee.sighash_type.to_u32() as u8);
        witness.push(sig_payee_bytes);

        witness.push(vec![1]); // OP_TRUE take OP_IF branch

        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or(SpillError::PsbtMissingWitnessScript)?;
        witness.push(witness_script.to_bytes());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();

        Ok(())
    }
}
