use bitcoin::{Amount, PublicKey, key::UncompressedPublicKeyError};
use core::fmt;
use std::error::Error;

/// Errors related to invalid channel configuration.
///
/// These errors indicate that provided channel parameters are invalid
/// and prevent a channel from being constructed.
#[non_exhaustive]
#[derive(Debug)]
pub enum ConfigError {
    /// The channel capacity is invalid (zero).
    InvalidCapacity,
    /// A provided public key is not in compressed form.
    UncompressedPublicKey,
    /// The refund locktime is invalid (zero).
    InvalidRefundLocktime,
}

/// Errors that can occur when constructing or verifying the funding transaction.
///
/// These errors indicate that the funding transaction is invalid or does not match
/// the expected channel parameters.
#[non_exhaustive]
#[derive(Debug)]
pub enum FundingError {
    /// The funding transaction ID does not match the expected outpoint.
    TxidMismatch,
    /// The expected output was not found in the funding transaction.
    OutputNotFound,
    /// The value of the funding output does not match the channel capacity.
    ValueMismatch,
    /// The script of the funding output does not match the expected funding script.
    ScriptMismatch,
}

/// Errors that can occur when constructing or verifying a payment.
///
/// These errors indicate that a payment PSBT or transaction is invalid or does
/// not conform to the rules defined by the channel parameters.
#[non_exhaustive]
#[derive(Debug)]
pub enum PaymentError {
    /// The payment exceeds the remaining channel capacity.
    ExceedsCapacity { available: Amount, required: Amount },
    /// The payment PSBT has multiple inputs (unsupported).
    MultipleInputs,
    /// The payment PSBT is missing an input.
    MissingInput,
    /// The outpoint eferenced by the payment does not match the funding outpoint.
    FundingOutpointMismatch,
    /// The witness UTXO is missing from the PSBT input.
    MissingWitnessUtxo,
    /// The witness UTXO in the PSBT does not match the expected funding UTXO.
    WitnessUtxoMismatch,
    /// The witness script is missing from the PSBT input.
    MissingWitnessScript,
    /// The witness script does not match the expected funding script.
    WitnessScriptMismatch,
    /// The input sequence number is invalid (expected MAX).
    InvalidSequence,
    /// The locktime is non-zero, unexpected for payment transactions.
    NonZeroLocktime,
    /// The payee output is missing from the PSBT outputs.
    MissingPayeeOutput,
    /// The total output decreases (negative payment).
    PaymentNotIncremental,
    /// The sum of outputs exceeds the funding transaction value.
    OutputsExceedFundingAmount,
    /// The payment PSBT is missing the payer's signature.
    MissingSignature,
    /// The PSBT uses an unsupported sighash type (expected ALL or ALL|ANYONECANPAY).
    InvalidSighash,
    /// The provided signature is invalid.
    InvalidSignature,
}

/// Errors that can occur when finalizing channel transactions.
///
/// These errors indicate that required data is missing to construct a
/// fully valid, broadcastable transaction.
#[non_exhaustive]
#[derive(Debug)]
pub enum FinalizeError {
    /// A required signature from the given public key is missing.
    MissingSignature { public_key: PublicKey },
    /// The witness script required to finalize the transaction is missing.
    MissingWitnessScript,
}

/// Top-level error type for this crate.
///
/// `SpillError` represents all errors that can occur when constructing,
/// verifying, or finalizing channel-related transactions. It groups errors
/// by domain while providing a single public error type.
#[non_exhaustive]
#[derive(Debug)]
pub enum SpillError {
    /// Errors related to invalid channel configuration.
    Config(ConfigError),
    /// Errors encountered when constructing or verifying the funding transaction.
    Funding(FundingError),
    /// Errors related to payment construction or verification.
    Payment(PaymentError),
    /// Errors that can occur when finalizing transactions.
    Finalize(FinalizeError),
}

impl From<UncompressedPublicKeyError> for SpillError {
    fn from(_value: UncompressedPublicKeyError) -> Self {
        Self::Config(ConfigError::UncompressedPublicKey)
    }
}

impl fmt::Display for SpillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpillError::Config(config_error) => match config_error {
                ConfigError::InvalidCapacity => write!(f, "channel capacity must be non-zero."),
                ConfigError::UncompressedPublicKey => write!(f, "public key must be compressed"),
                ConfigError::InvalidRefundLocktime => {
                    write!(f, "invalid refund locktime (must be greater than 0)")
                }
            },
            SpillError::Funding(fundin_error) => match fundin_error {
                FundingError::TxidMismatch => {
                    write!(f, "funding transaction does not match expected id")
                }
                FundingError::OutputNotFound => write!(f, "funding transaction output not found"),
                FundingError::ValueMismatch => write!(
                    f,
                    "funding transaction output value does not match expected"
                ),
                FundingError::ScriptMismatch => {
                    write!(
                        f,
                        "funding transaction output script does not match expected"
                    )
                }
            },
            SpillError::Payment(payment_error) => match payment_error {
                PaymentError::ExceedsCapacity {
                    available,
                    required,
                } => write!(
                    f,
                    "payment exceeds channel capacity (available: {}, required: {})",
                    available, required
                ),
                PaymentError::MultipleInputs => {
                    write!(f, "payment transaction has more than one input")
                }
                PaymentError::MissingInput => write!(f, "payment transaction is missing input"),
                PaymentError::FundingOutpointMismatch => write!(
                    f,
                    "payment transaction does not reference funding transaction"
                ),
                PaymentError::MissingWitnessUtxo => {
                    write!(f, "payment transaction missing witness utxo")
                }
                PaymentError::WitnessUtxoMismatch => {
                    write!(
                        f,
                        "payment transaction witness utxo does not match expected"
                    )
                }
                PaymentError::MissingWitnessScript => {
                    write!(f, "payment transaction missing witness script")
                }
                PaymentError::WitnessScriptMismatch => {
                    write!(
                        f,
                        "payment transaction witness script does not match expected"
                    )
                }
                PaymentError::InvalidSequence => {
                    write!(f, "payment transaction sequence is not MAX")
                }
                PaymentError::NonZeroLocktime => {
                    write!(f, "payment transaction uses non-final locktime")
                }
                PaymentError::MissingPayeeOutput => {
                    write!(f, "payment transaction missing output to payee")
                }
                PaymentError::PaymentNotIncremental => {
                    write!(
                        f,
                        "payee output value must be greater than previous payment"
                    )
                }
                PaymentError::OutputsExceedFundingAmount => {
                    write!(f, "payment transaction outputs exceed funding amount")
                }
                PaymentError::MissingSignature => {
                    write!(f, "payment transaction missing payer's signature")
                }
                PaymentError::InvalidSighash => {
                    write!(f, "payment transaction signature has invalid sighash")
                }
                PaymentError::InvalidSignature => {
                    write!(f, "payment transaction signature is invalid")
                }
            },
            SpillError::Finalize(finalize_error) => match finalize_error {
                FinalizeError::MissingSignature { public_key } => {
                    write!(f, "PSBT is missing signature for public key {}", public_key)
                }
                FinalizeError::MissingWitnessScript => write!(f, "PSBT is missing witness script"),
            },
        }
    }
}

impl Error for SpillError {}
