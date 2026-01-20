use bitcoin::{Amount, PublicKey, key::UncompressedPublicKeyError};
use core::fmt;
use std::error::Error;

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
