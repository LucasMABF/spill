use bitcoin::{
    Amount, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute,
    key::UncompressedPublicKeyError,
    opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF},
    script, transaction,
};
use std::{error::Error, fmt};

#[non_exhaustive]
#[derive(Debug)]
pub enum SpillError {
    UncompressedPublicKey,
    InvalidRefundLocktime,
    InvalidCapacity,
    SpendExceedsCapacity { available: Amount, required: Amount },
    PsbtMissingSignature { public_key: PublicKey },
    PsbtMissingWitnessScript,
}

impl From<UncompressedPublicKeyError> for SpillError {
    fn from(_value: UncompressedPublicKeyError) -> Self {
        Self::UncompressedPublicKey
    }
}

impl fmt::Display for SpillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpillError::UncompressedPublicKey => write!(f, "public key must be compressed"),
            SpillError::InvalidRefundLocktime => {
                write!(f, "invalid refund locktime (must be greater than 0)")
            }
            SpillError::InvalidCapacity => write!(f, "channel capacity must be non-zero."),
            SpillError::SpendExceedsCapacity {
                available,
                required,
            } => write!(
                f,
                "spend exceeds channel capacity (available: {}, required: {})",
                available, required
            ),
            SpillError::PsbtMissingSignature { public_key } => {
                write!(f, "PSBT is missing signature for public key {}", public_key)
            }
            SpillError::PsbtMissingWitnessScript => write!(f, "PSBT is missing witness script"),
        }
    }
}

impl Error for SpillError {}

#[derive(Clone)]
pub struct ChannelParams {
    payer: PublicKey,
    payee: PublicKey,
    capacity: Amount,
    funding_script: ScriptBuf,
    refund_locktime: Sequence,
}

impl ChannelParams {
    pub fn new(
        payer: PublicKey,
        payee: PublicKey,
        capacity: Amount,
        refund_locktime: Sequence,
    ) -> Result<ChannelParams, SpillError> {
        if capacity == Amount::ZERO {
            return Err(SpillError::InvalidCapacity);
        }

        if !(payer.compressed && payee.compressed) {
            return Err(SpillError::UncompressedPublicKey);
        }

        if refund_locktime == Sequence::ZERO
            || refund_locktime == Sequence::from_height(0)
            || refund_locktime == Sequence::from_512_second_intervals(0)
        {
            return Err(SpillError::InvalidRefundLocktime);
        }

        let funding_script = script::Builder::new()
            .push_opcode(OP_IF)
            .push_int(2)
            .push_key(&payer)
            .push_key(&payee)
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_sequence(refund_locktime)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&payer)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script();

        Ok(ChannelParams {
            payer,
            payee,
            capacity,
            funding_script,
            refund_locktime,
        })
    }

    pub fn funding_psbt(&self) -> Psbt {
        let script_hash = self.funding_script.wscript_hash();

        let output = TxOut {
            value: self.capacity,
            script_pubkey: ScriptBuf::new_p2wsh(&script_hash),
        };

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![output],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("funding_psbt: internal invariant violated (tx must be unsigned)");
        psbt.outputs[0].witness_script = Some(self.funding_script.clone());

        psbt
    }
}

#[derive(Clone)]
pub struct Channel {
    params: ChannelParams,
    funding_outpoint: OutPoint,
    funding_utxo: TxOut,
    sent: Amount,
}

impl Channel {
    pub fn new(params: ChannelParams, funding_outpoint: OutPoint, funding_utxo: TxOut) -> Channel {
        Channel {
            params,
            funding_outpoint,
            funding_utxo,
            sent: Amount::ZERO,
        }
    }

    pub fn next_spend(&self, amount: Amount, fee: Amount) -> Result<(Psbt, Channel), SpillError> {
        let required = amount + self.sent + fee;
        if required > self.params.capacity {
            return Err(SpillError::SpendExceedsCapacity {
                available: self.params.capacity,
                required,
            });
        }

        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let spend = TxOut {
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
            output: vec![spend, change],
        };

        let mut next_channel_state = self.clone();
        next_channel_state.sent += amount;

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("next_spend: internal invariant violated (tx must be unsigned)");

        psbt.inputs[0].witness_script = Some(self.params.funding_script.clone());

        psbt.inputs[0].witness_utxo = Some(self.funding_utxo.clone());

        Ok((psbt, next_channel_state))
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

    pub fn refund_psbt(&self) -> Psbt {
        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: self.params.refund_locktime,
            witness: Witness::new(),
        };

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("refund_psbt: internal invariant violated (tx must be unsigned)");

        psbt.inputs[0].witness_utxo = Some(self.funding_utxo.clone());
        psbt.inputs[0].witness_script = Some(self.params.funding_script.clone());

        psbt
    }

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
}
