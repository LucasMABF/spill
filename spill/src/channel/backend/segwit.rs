use bitcoin::{
    Amount, EcdsaSighashType, Psbt, PublicKey, ScriptPubKeyBuf, TxOut, Witness, WitnessScriptBuf,
    opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF},
    primitives::relative,
    script::{self, ScriptBufExt, WitnessScriptExt},
    secp256k1,
    sighash::SighashCache,
};

use crate::{FinalizeError, PaymentError, SpillError, channel::backend::ChannelBackend};

/// SegWit v0 (P2WSH) backend for the channel.
///
/// `SegwitBackend` implements the channel using a native SegWit v0
/// P2WSH funding output. The witness script encodes the channel rules
/// as two spending paths:
///
/// - **Cooperative payment path**:
///   A 2-of-2 multisig between payer and payee.
///   When both signatures are provided, the payee can claim
///   the latest signed payment.
///
/// - **Refund path**:
///   After the agreed relative lock time (`OP_CSV`), the payer
///   may unilaterally recover the channel funds with a single signature.
#[derive(Clone, Default)]
pub struct SegwitBackend {
    funding_script: Option<WitnessScriptBuf>,
}

impl SegwitBackend {
    pub fn new() -> SegwitBackend {
        SegwitBackend::default()
    }
}

impl ChannelBackend for SegwitBackend {
    fn script_pubkey(
        &mut self,
        payer: &PublicKey,
        payee: &PublicKey,
        refund_lock_time: relative::LockTime,
    ) -> Result<ScriptPubKeyBuf, SpillError> {
        let funding_script: WitnessScriptBuf = script::Builder::new()
            .push_opcode(OP_IF)
            .push_int(2)
            .expect(
                "Segwit funding_script: internal invariant violated (integer must be valid in scipt)",
            )
            .push_key(*payer)
            .push_key(*payee)
            .push_int(2)
            .expect(
                "Segwit funding_script: internal invariant violated (integer must be valid in scipt)",
            )
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_relative_lock_time(refund_lock_time)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(*payer)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script();

        self.funding_script = Some(funding_script.clone());

        Ok(funding_script.to_p2wsh().expect("Segwit funding_script: internal invariant violated (funding script must be valid p2wsh)"))
    }

    fn populate_funding_psbt(&self, psbt: &mut bitcoin::Psbt) {
        psbt.outputs[0].witness_script = Some(self.funding_script.clone().expect("Segwit funding_script: internal invariant violated (funding_script must be built at this point)"));
    }

    fn populate_refund_psbt(&self, psbt: &mut bitcoin::Psbt, funding_utxo: TxOut) {
        psbt.inputs[0].witness_utxo = Some(funding_utxo);
        psbt.inputs[0].witness_script = Some(self.funding_script.clone().expect("Segwit funding_script: internal invariant violated (funding_script must be built at this point)"));
    }

    fn populate_payment_psbt(&self, psbt: &mut bitcoin::Psbt, funding_utxo: TxOut) {
        psbt.inputs[0].witness_script = Some(self.funding_script.clone().expect("Segwit funding_script: internal invariant violated (funding_script must be built at this point)"));
        psbt.inputs[0].witness_utxo = Some(funding_utxo.clone());
    }

    fn payee_script(&self, payee: &PublicKey) -> Result<ScriptPubKeyBuf, SpillError> {
        Ok(ScriptPubKeyBuf::new_p2wpkh(payee.wpubkey_hash()?))
    }

    fn verify_payment(
        &self,
        psbt: &Psbt,
        payer: &PublicKey,
        capacity: Amount,
    ) -> Result<(), SpillError> {
        let witness_script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(PaymentError::MissingWitnessScript)?;

        let witness_script = WitnessScriptBuf::from_bytes(witness_script.into_bytes());

        if witness_script != self.funding_script.clone().expect("Segwit funding_script: internal invariant violated (funding_script must be built at this point)") {
            return Err(PaymentError::WitnessScriptMismatch.into());
        }

        let sig = psbt.inputs[0]
            .partial_sigs
            .get(payer)
            .ok_or(PaymentError::MissingSignature)?;

        if sig.sighash_type != EcdsaSighashType::All
            && sig.sighash_type != EcdsaSighashType::AllPlusAnyoneCanPay
        {
            return Err(PaymentError::InvalidSighash.into());
        }

        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = cache
            .p2wsh_signature_hash(
                0,
                self.funding_script.as_ref().expect("Segwit funding_script: internal invariant violated (funding_script must be built at this point)"),
                capacity,
                sig.sighash_type,
            )
            .expect("verify_payment_psbt: internal invariant (sign input 0)");

        let msg = secp256k1::Message::from_digest(sighash.to_byte_array());

        if secp256k1::ecdsa::verify(&sig.signature, msg, &payer.inner).is_err() {
            return Err(PaymentError::InvalidSignature.into());
        }

        Ok(())
    }

    fn finalize_refund_tx(&self, psbt: &mut Psbt, payer: &PublicKey) -> Result<(), SpillError> {
        let mut witness = Witness::new();
        let input = &mut psbt.inputs[0];

        let sig_payer = input
            .partial_sigs
            .get(payer)
            .ok_or(FinalizeError::MissingSignature { public_key: *payer })?;
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        witness.push(vec![0]); // OP_FALSE take OP_ELSE branch

        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or(FinalizeError::MissingWitnessScript)?;
        witness.push(witness_script.to_vec());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();

        Ok(())
    }

    fn finalize_payment_tx(
        &self,
        psbt: &mut Psbt,
        payer: &PublicKey,
        payee: &PublicKey,
    ) -> Result<(), SpillError> {
        let mut witness = Witness::new();
        witness.push(vec![]);

        let input = &mut psbt.inputs[0];

        let sig_payer = input
            .partial_sigs
            .get(payer)
            .ok_or(FinalizeError::MissingSignature { public_key: *payer })?;
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        let sig_payee = input
            .partial_sigs
            .get(payee)
            .ok_or(FinalizeError::MissingSignature { public_key: *payee })?;
        let mut sig_payee_bytes = sig_payee.signature.serialize_der().to_vec();
        sig_payee_bytes.push(sig_payee.sighash_type.to_u32() as u8);
        witness.push(sig_payee_bytes);

        witness.push(vec![1]); // OP_TRUE take OP_IF branch

        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or(FinalizeError::MissingWitnessScript)?;
        witness.push(witness_script.to_vec());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();

        Ok(())
    }
}
