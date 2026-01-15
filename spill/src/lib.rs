use bitcoin::{
    Amount, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute,
    opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF},
    script, transaction,
};

pub enum SpillError {
    InvalidParams,
}

#[derive(Clone)]
pub struct ChannelParams {
    payer: PublicKey,
    payee: PublicKey,
    capacity: Amount,
    funding_script: ScriptBuf,
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
        })
    }
}

impl ChannelParams {
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

    pub fn next_spend(&self, amount: Amount) -> (Psbt, Channel) {
        assert!(amount <= self.params.capacity - self.sent);

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
            value: self.params.capacity - (self.sent + amount),
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
}
