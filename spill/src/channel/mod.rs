use bitcoin::{
    Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TxOut,
    opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF},
    script,
};

use crate::{ConfigError, SpillError};

mod finalize;
mod payment;
mod psbt;
mod verify;

#[derive(Clone)]
pub struct ChannelParams {
    payer: PublicKey,
    payee: PublicKey,
    capacity: Amount,
    funding_script: ScriptBuf,
    refund_locktime: Sequence,
}

#[derive(Clone)]
pub struct Channel {
    params: ChannelParams,
    funding_outpoint: OutPoint,
    funding_utxo: TxOut,
    sent: Amount,
}

impl ChannelParams {
    pub fn new(
        payer: PublicKey,
        payee: PublicKey,
        capacity: Amount,
        refund_locktime: Sequence,
    ) -> Result<ChannelParams, SpillError> {
        if capacity == Amount::ZERO {
            return Err(SpillError::Config(ConfigError::InvalidCapacity));
        }

        if !(payer.compressed && payee.compressed) {
            return Err(SpillError::Config(ConfigError::UncompressedPublicKey));
        }

        if refund_locktime == Sequence::ZERO
            || refund_locktime == Sequence::from_height(0)
            || refund_locktime == Sequence::from_512_second_intervals(0)
        {
            return Err(SpillError::Config(ConfigError::InvalidRefundLocktime));
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
}
