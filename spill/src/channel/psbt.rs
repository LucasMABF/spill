use bitcoin::{Psbt, Transaction, TxIn, TxOut, Witness, absolute, script::ScriptBuf, transaction};

use crate::{Channel, ChannelParams, channel::backend::ChannelBackend};

impl<B: ChannelBackend + Clone> ChannelParams<B> {
    /// Constructs a funding PSBT for the channel.
    ///
    /// The returned PSBT represents the channel's funding transaction, which can
    /// be completed, signed by the payer and later broadcast to fund the channel.
    ///
    /// # Details
    ///
    /// - The PSBT has no inputs; the caller must add inputs and account for fees
    /// - The PSBT contains a single output paying the channel capacity to the
    ///   channel's funding script.
    /// - The transaction has version 2 and a lock time of 0.
    pub fn funding_psbt(&self) -> Psbt {
        let output = TxOut {
            amount: self.capacity,
            script_pubkey: self.script_pubkey.clone(),
        };

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![],
            outputs: vec![output],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("funding_psbt: internal invariant violated (tx must be unsigned)");

        self.backend.populate_funding_psbt(&mut psbt);

        psbt
    }
}

impl<B: ChannelBackend + Clone> Channel<B> {
    /// Constructs a refund PSBT for the channel.
    ///
    /// The returned PSBT can be completed and signed by the payer to
    /// claim the channel's funds after the refund lock time has passed.
    ///
    /// # Details
    ///
    /// - The PSBT contains a single input referencing the channel's funding outpoint.
    /// - The input's witness UTXO is set according to the channel's funding transaction.
    /// - The PSBT has no outputs by default; the caller must add the refund output
    ///   and account for fees.
    /// - The transaction has version 2 and a lock time of 0.
    pub fn refund_psbt(&self) -> Psbt {
        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: self.params.refund_lock_time.to_sequence(),
            witness: Witness::new(),
        };

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![input],
            outputs: vec![],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("refund_psbt: internal invariant violated (tx must be unsigned)");

        self.params
            .backend
            .populate_refund_psbt(&mut psbt, self.funding_utxo.clone());

        psbt
    }
}
