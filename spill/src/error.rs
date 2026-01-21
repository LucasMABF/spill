use bitcoin::{Amount, PublicKey, key::UncompressedPublicKeyError};
use core::fmt;
use std::error::Error;

#[non_exhaustive]
#[derive(Debug)]
pub enum ConfigError {
    InvalidCapacity,
    UncompressedPublicKey,
    InvalidRefundLocktime,
}

#[non_exhaustive]
#[derive(Debug)]
pub enum FundingError {
    TxidMismatch,
    OutputNotFound,
    ValueMismatch,
    ScriptMismatch,
}

#[non_exhaustive]
#[derive(Debug)]
pub enum PaymentError {
    ExceedsCapacity { available: Amount, required: Amount },
    MultipleInputs,
    MissingInput,
    FundingOutpointMismatch,
    MissingWitnessUtxo,
    WitnessUtxoMismatch,
    MissingWitnessScript,
    WitnessScriptMismatch,
    InvalidSequence,
    NonZeroLocktime,
    MissingPayeeOutput,
    PaymentNotIncremental,
    OutputsExceedFundingAmount,
    MissingSignature,
    InvalidSighash,
    InvalidSignature,
}

#[non_exhaustive]
#[derive(Debug)]
pub enum FinalizeError {
    MissingSignature { public_key: PublicKey },
    MissingWitnessScript,
}

#[non_exhaustive]
#[derive(Debug)]
pub enum SpillError {
    Config(ConfigError),
    Funding(FundingError),
    Payment(PaymentError),
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
