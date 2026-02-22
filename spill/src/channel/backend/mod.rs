use bitcoin::{Amount, Psbt, PublicKey, ScriptPubKeyBuf, TxOut, primitives::relative};

use crate::SpillError;

/// Abstraction for different channel implementations (e.g., SegWit, Taproot).
///
/// `ChannelBackend` defines the low-level script generation and transaction
/// manipulation logic required for a specific channel type. It handles the
/// construction of scripts, population of PSBT fields, and verification of
/// transaction structures specific to the backend's consensus rules.
///
/// Implementing this trait allows `ChannelParams` and `Channel` to remain
/// agnostic to the underlying script mechanics (e.g., P2WSH vs P2TR).
pub trait ChannelBackend {
    /// Builds the funding `script_pubkey` for this channel type.
    ///
    /// This method constructs the locking script that defines the channel’s
    /// spending conditions (payment path and refund path) according to the
    /// backend’s rules.
    fn script_pubkey(
        &mut self,
        payer: &PublicKey,
        payee: &PublicKey,
        refund_lock_time: relative::LockTime,
    ) -> Result<ScriptPubKeyBuf, SpillError>;

    /// Populates backend-specific fields in the funding PSBT.
    ///
    /// This method fills any script, witness, or proprietary fields required
    /// for the funding transaction to be valid under this backend.
    fn populate_funding_psbt(&self, psbt: &mut Psbt);

    /// Populates backend-specific fields in the refund PSBT.
    ///
    /// Uses the provided funding UTXO to set the appropriate witness or
    /// redeem data required to spend the channel via the refund path.
    fn populate_refund_psbt(&self, psbt: &mut Psbt, funding_utxo: TxOut);

    /// Populates backend-specific fields in the payment PSBT.
    ///
    /// Uses the provided funding UTXO to configure the PSBT for a
    /// payment under this backend.
    fn populate_payment_psbt(&self, psbt: &mut Psbt, funding_utxo: TxOut);

    /// Builds the script that pays directly to the payee.
    ///
    /// This is used to construct the payment output that transfers value
    /// to the payee outside the channel.
    fn payee_script(&self, payee: &PublicKey) -> Result<ScriptPubKeyBuf, SpillError>;

    /// Verifies that a payment PSBT is valid under this backend.
    ///
    /// Checks that the transaction structure, outputs, and amounts
    /// respect the channel rules and do not exceed the channel capacity.
    fn verify_payment(
        &self,
        psbt: &Psbt,
        payer: &PublicKey,
        capacity: Amount,
    ) -> Result<(), SpillError>;

    /// Finalizes the refund PSBT.
    ///
    /// Completes any backend-specific witness or script data
    /// required to produce a fully valid refund transaction, ready to be broadcast.
    fn finalize_refund_tx(&self, psbt: &mut Psbt, payer: &PublicKey) -> Result<(), SpillError>;

    /// Finalizes the payment PSBT.
    ///
    /// Completes any backend-specific witness or script data
    /// required to produce a fully valid payment transaction, ready to be broadcast.
    fn finalize_payment_tx(
        &self,
        psbt: &mut Psbt,
        payer: &PublicKey,
        payee: &PublicKey,
    ) -> Result<(), SpillError>;
}

mod segwit;

pub use segwit::SegwitBackend;
