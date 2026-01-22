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

pub use payment::PaymentInfo;

/// Immutable channel configuration agreed upon by both peers.
///
/// `ChannelParams` captures all parameters that define the structure
/// and expected behavior of a Spillman channel.
///
/// These parameters are fixed for the lifetime of the channel. They do not
/// represent dynamic state, but rather the agreed-upon channel specification
/// against which all transactions are constructed and verified,
/// allowing the value to be safely cloned and reused.
///
/// # Role in the API
///
/// `ChannelParams` is used to initialize a channel and defines the rules under
/// which all channel transactions are constructed and verified. It provides
/// methods for the payer to construct the funding transaction and for the payee
/// to verify that a received funding transaction is valid
/// under the agreed channel parameters.
#[derive(Clone)]
pub struct ChannelParams {
    payer: PublicKey,
    payee: PublicKey,
    capacity: Amount,
    funding_script: ScriptBuf,
    refund_locktime: Sequence,
}

/// Runtime state of an established Spillman channel.
///
/// `Channel` represents a funded channel whose parameters have already
/// been agreed upon by both peers. It combines the immutable channel rules
/// ([`ChannelParams`]) with the dynamic state required to track payments
/// and construct or verify subsequent channel transactions.
///
/// The channel state advances only through an explicit state transition method,
/// ensuring callers can inspect verification results before applying them.
///
/// # Role in the API
///
/// `Channel` exposes methods for the payer to construct payment PSBTs
/// and refund transactions, and for the payee to verify and inspect received payments.
pub struct Channel {
    params: ChannelParams,
    funding_outpoint: OutPoint,
    funding_utxo: TxOut,
    sent: Amount,
}

impl ChannelParams {
    /// Creates a new channel configuration for a unidirectional Spillman channel.
    ///
    /// Returns a `ChannelParams` struct if all parameters are valid, or a
    /// `SpillError::Config` variant if any parameter is invalid.
    ///
    /// # Parameters
    /// - `payer`: The payer's compressed public key.
    /// - `payee`: The payee's compressed public key.
    /// - `capacity`: The total channel capacity (must be non-zero).
    /// - `refund_locktime`: Locktime used for the refund path (must be non-zero).
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
