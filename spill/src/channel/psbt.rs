use bitcoin::{Psbt, ScriptBuf, Transaction, TxIn, TxOut, Witness, absolute, transaction};

use crate::{Channel, ChannelParams};

impl ChannelParams {
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
    /// - The witness script is set according to the channel's rules.
    /// - The transaction has version 2 and a locktime of 0.
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

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("funding_psbt: internal invariant violated (tx must be unsigned)");
        psbt.outputs[0].witness_script = Some(self.funding_script.clone());

        psbt
    }
}

impl Channel {
    /// Constructs a refund PSBT for the channel.
    ///
    /// The returned PSBT can be completed and signed by the payer to
    /// claim the channel's funds after the refund locktime has passed.
    ///
    /// # Details
    ///
    /// - The PSBT contains a single input referencing the channel's funding outpoint.
    /// - The input's witness UTXO and witness script are set according to the
    ///   channel's funding transaction.
    /// - The PSBT has no outputs by default; the caller must add the refund output
    ///   and account for fees.
    /// - The transaction has version 2 and a locktime of 0.
    pub fn refund_psbt(&self) -> Psbt {
        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: self.params.refund_locktime,
            witness: Witness::new(),
        };

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("refund_psbt: internal invariant violated (tx must be unsigned)");

        psbt.inputs[0].witness_utxo = Some(self.funding_utxo.clone());
        psbt.inputs[0].witness_script = Some(self.params.funding_script.clone());

        psbt
    }
}
