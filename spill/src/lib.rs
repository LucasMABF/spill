use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
    absolute::{self, LockTime},
    key::UncompressedPublicKeyError,
    opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF},
    script, secp256k1,
    sighash::SighashCache,
    transaction,
};
use std::{error::Error, fmt};

#[non_exhaustive]
#[derive(Debug)]
pub enum SpillError {
    UncompressedPublicKey,
    InvalidRefundLocktime,
    InvalidCapacity,
    PaymentExceedsCapacity { available: Amount, required: Amount },
    PsbtMissingSignature { public_key: PublicKey },
    PsbtMissingWitnessScript,
    FundingTxidMismatch,
    FundingOutputNotFound,
    FundingValueMismatch,
    FundingScriptMismatch,
    PaymentMultipleInputs,
    PaymentMissingInput,
    PaymentWrongInput,
    PaymentMissingWitnessUtxo,
    PaymentWitnessUtxoMismatch,
    PaymentMissingWitnessScript,
    PaymentWitnessScriptMismatch,
    PaymentInvalidSequence,
    PaymentNonZeroLocktime,
    PaymentMissingPayeeOutput,
    PaymentInvalidValue,
    PaymentInvalidOutputSum,
    PaymentMissingSignature,
    PaymentInvalidSighash,
    PaymentInvalidSignature,
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
            SpillError::PaymentExceedsCapacity {
                available,
                required,
            } => write!(
                f,
                "payment exceeds channel capacity (available: {}, required: {})",
                available, required
            ),
            SpillError::PsbtMissingSignature { public_key } => {
                write!(f, "PSBT is missing signature for public key {}", public_key)
            }
            SpillError::PsbtMissingWitnessScript => write!(f, "PSBT is missing witness script"),
            SpillError::FundingTxidMismatch => {
                write!(f, "funding transaction id does not match expected ")
            }
            SpillError::FundingOutputNotFound => write!(f, "funding transaction output not found"),
            SpillError::FundingValueMismatch => write!(
                f,
                "funding transaction output value does not match expected"
            ),
            SpillError::FundingScriptMismatch => {
                write!(f, "funding transaction output does not match expected")
            }
            SpillError::PaymentMultipleInputs => {
                write!(f, "payment transaction has more than one input")
            }
            SpillError::PaymentMissingInput => write!(f, "payment transaction is missing input"),
            SpillError::PaymentWrongInput => write!(
                f,
                "payment transaction does not reference funding transaction"
            ),
            SpillError::PaymentMissingWitnessUtxo => {
                write!(f, "payment transaction missing witness utxo")
            }
            SpillError::PaymentWitnessUtxoMismatch => {
                write!(f, "wrong payment transaction witness utxo")
            }
            SpillError::PaymentMissingWitnessScript => {
                write!(f, "payment transaction missing witness script")
            }
            SpillError::PaymentWitnessScriptMismatch => {
                write!(f, "wrong payment transaction witness script")
            }
            SpillError::PaymentInvalidSequence => {
                write!(f, "payment transaction sequence must be MAX")
            }
            SpillError::PaymentNonZeroLocktime => {
                write!(f, "payment transaction locktime must be zero")
            }
            SpillError::PaymentMissingPayeeOutput => {
                write!(f, "payment transaction missing output to payee")
            }
            SpillError::PaymentInvalidValue => {
                write!(
                    f,
                    "payee output value must be greater than previous payment"
                )
            }
            SpillError::PaymentInvalidOutputSum => {
                write!(f, "payment transaction outputs' values exceed input")
            }
            SpillError::PaymentMissingSignature => {
                write!(f, "payment transaction missing payer's signature")
            }
            SpillError::PaymentInvalidSighash => {
                write!(f, "payment transaction signature has invalid sighash")
            }
            SpillError::PaymentInvalidSignature => {
                write!(f, "payment transaction signature is invalid")
            }
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

#[derive(Clone)]
pub struct Channel {
    params: ChannelParams,
    funding_outpoint: OutPoint,
    funding_utxo: TxOut,
    sent: Amount,
}

pub struct PaymentInfo {
    pub total: Amount,
    pub current: Amount,
    pub fee: Amount,
}

impl Channel {
    pub fn next_payment(&self, amount: Amount, fee: Amount) -> Result<Psbt, SpillError> {
        let required = amount + self.sent + fee;
        if required > self.params.capacity {
            return Err(SpillError::PaymentExceedsCapacity {
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

    pub fn apply_payment(&mut self, psbt: &Psbt) -> Result<(), SpillError> {
        let payment = self.verify_payment_psbt(psbt)?;
        self.sent = payment.total;
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
