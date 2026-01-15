use bitcoin::{
    Amount, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute,
    opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF},
    script, transaction,
};

#[derive(Debug)]
pub enum SpillError {
    InvalidParams,
}

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
        if !(payer.compressed && payee.compressed) {
            return Err(SpillError::InvalidParams);
        }

        if refund_locktime == Sequence::ZERO
            || refund_locktime == Sequence::from_height(0)
            || refund_locktime == Sequence::from_512_second_intervals(0)
        {
            return Err(SpillError::InvalidParams);
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

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
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

    pub fn next_spend(&self, amount: Amount, fee: Amount) -> (Psbt, Channel) {
        assert!(amount + self.sent + fee <= self.params.capacity);

        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let spend = TxOut {
            value: amount + self.sent,
            script_pubkey: ScriptBuf::new_p2wpkh(&self.params.payee.wpubkey_hash().unwrap()),
        };

        let change = TxOut {
            value: self.params.capacity - (self.sent + amount + fee),
            script_pubkey: ScriptBuf::new_p2wpkh(&self.params.payer.wpubkey_hash().unwrap()),
        };

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![spend, change],
        };

        let mut next_channel_state = self.clone();
        next_channel_state.sent += amount;

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].witness_script = Some(self.params.funding_script.clone());

        psbt.inputs[0].witness_utxo = Some(self.funding_utxo.clone());

        (psbt, next_channel_state)
    }

    pub fn finalize_payment_tx(&self, psbt: &mut Psbt) {
        let mut witness = Witness::new();
        witness.push(vec![]);

        let input = &mut psbt.inputs[0];

        let sig_payer = input.partial_sigs.get(&self.params.payer).unwrap();
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        let sig_payee = input.partial_sigs.get(&self.params.payee).unwrap();
        let mut sig_payee_bytes = sig_payee.signature.serialize_der().to_vec();
        sig_payee_bytes.push(sig_payee.sighash_type.to_u32() as u8);
        witness.push(sig_payee_bytes);

        witness.push(vec![1]); // OP_TRUE take OP_IF branch

        let witness_script = input.witness_script.as_ref().unwrap();
        witness.push(witness_script.to_bytes());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();
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

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].witness_utxo = Some(self.funding_utxo.clone());
        psbt.inputs[0].witness_script = Some(self.params.funding_script.clone());

        psbt
    }

    pub fn finalize_refund_tx(&self, psbt: &mut Psbt) {
        let mut witness = Witness::new();
        let input = &mut psbt.inputs[0];

        let sig_payer = input.partial_sigs.get(&self.params.payer).unwrap();
        let mut sig_payer_bytes = sig_payer.signature.serialize_der().to_vec();
        sig_payer_bytes.push(sig_payer.sighash_type.to_u32() as u8);
        witness.push(sig_payer_bytes);

        witness.push(vec![0]); // OP_FALSE take OP_ELSE branch

        let witness_script = input.witness_script.as_ref().unwrap();
        witness.push(witness_script.to_bytes());

        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();
    }
}
