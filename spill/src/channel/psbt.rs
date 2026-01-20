use bitcoin::{Psbt, ScriptBuf, Transaction, TxIn, TxOut, Witness, absolute, transaction};

use crate::{Channel, ChannelParams};

impl ChannelParams {
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
