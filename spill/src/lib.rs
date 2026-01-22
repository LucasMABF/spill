//! # Spillman Payment Channels
//!
//! This crate provides an API for constructing and using
//! a Spillman-style Bitcoin payment channel.
//!
//! The library is designed to help both payer and payee independently
//! create and verify the transactions involved in a Spillman channel.
//! This allows each party to use the channel safely, without relying
//! on trust in the counterparty.
//!
//! ## Scope and goals
//!
//! This crate focuses on constructing channel-related transactions and
//! verifying their correctness and safety properties, while leaving wallet
//! functionality and transaction broadcasting entirely to the user.
//!
//! Specifically, the library helps to:
//!
//! - construct the channel funding transaction
//! - construct payment PSBTs
//! - construct the refund transaction
//! - verify transactions and PSBTs received from the counterparty
//! - finalize transactions once all required signatures are present
//!
//! ## High-level workflow
//!
//! A typical usage pattern looks like this:
//!
//! 1. Both peers agree on the channel specifications ([`ChannelParams`])
//! 2. The payer creates the funding transaction
//! 3. The payee verifies the funding transaction and initializes a [`Channel`]
//! 4. For each payment:
//!   - The payer creates a payment PSBT
//!   - The payee verifies the PSBT
//!   - Inspects the returned payment information
//!   - Explicitly applies the payment to advance the channel state
//! 5. Either the payee finalizes a transaction for on-chain settlement,
//!    or the payer may claim the refund

mod channel;
mod error;

pub use channel::PaymentInfo;
pub use channel::{Channel, ChannelParams};
pub use error::{ConfigError, FinalizeError, FundingError, PaymentError, SpillError};
