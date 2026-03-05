use bitcoin::{
    Amount, OutPoint, PublicKey, ScriptPubKeyBuf, ScriptPubKeyTag, TxOut, primitives::relative,
    script::ScriptBuf,
};

use crate::{ConfigError, SpillError, channel::backend::ChannelBackend};

pub mod backend;
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
pub struct ChannelParams<B: ChannelBackend + Clone> {
    payer: PublicKey,
    payee: PublicKey,
    capacity: Amount,
    script_pubkey: ScriptBuf<ScriptPubKeyTag>,
    refund_lock_time: relative::LockTime,
    backend: B,
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
pub struct Channel<B: ChannelBackend + Clone> {
    params: ChannelParams<B>,
    funding_outpoint: OutPoint,
    funding_utxo: TxOut,
    sent: Amount,
}

impl<B: ChannelBackend + Clone> ChannelParams<B> {
    /// Creates a new channel configuration for a unidirectional Spillman channel.
    ///
    /// Returns a `ChannelParams` struct if all parameters are valid, or a
    /// `SpillError::Config` variant if any parameter is invalid.
    ///
    /// # Parameters
    /// - `payer`: The payer's compressed public key.
    /// - `payee`: The payee's compressed public key.
    /// - `capacity`: The total channel capacity (must be non-zero).
    /// - `refund_lock_time`: Lock time used for the refund path (must be non-zero).
    /// - `backend`: The type of transaction to be used. Implements trait [`ChannelBackend`].
    pub fn new(
        payer: PublicKey,
        payee: PublicKey,
        capacity: Amount,
        refund_lock_time: relative::LockTime,
        mut backend: B,
    ) -> Result<ChannelParams<B>, SpillError> {
        if capacity == Amount::ZERO {
            return Err(ConfigError::InvalidCapacity.into());
        }

        if !(payer.compressed() && payee.compressed()) {
            return Err(ConfigError::UncompressedPublicKey.into());
        }

        if refund_lock_time == relative::LockTime::ZERO
            || refund_lock_time == relative::LockTime::from_height(0)
            || refund_lock_time == relative::LockTime::from_512_second_intervals(0)
        {
            return Err(ConfigError::InvalidRefundLockTime.into());
        }

        let script_pubkey = backend.script_pubkey(&payer, &payee, refund_lock_time)?;

        Ok(ChannelParams {
            payer,
            payee,
            capacity,
            script_pubkey,
            refund_lock_time,
            backend,
        })
    }

    pub fn script_pubkey(&self) -> &ScriptPubKeyBuf {
        &self.script_pubkey
    }
}
