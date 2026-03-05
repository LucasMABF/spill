use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, OutPoint, PrivateKey, Psbt,
    PublicKey, Sequence, TxIn, TxOut, Witness,
    ecdsa::Signature,
    psbt::{Input, Output},
    secp256k1::{Message, SecretKey, ecdsa, rand},
    sighash::SighashCache,
};
use corepc_node::{Client, ImportDescriptorsRequest, Node};

use crate::common::conversion_utils::{
    from_rpc_amount, from_rpc_script_pubkey_buf, from_rpc_txid, to_rpc_address, to_rpc_amount,
};

pub struct TestWallet {
    pub client: Client,
    pub address: Address,
    pub privkey: PrivateKey,
    pub pubkey: PublicKey,
    pub witness_utxo: Option<TxOut>,
    pub outpoint: Option<OutPoint>,
}

fn create_wallet(node: &Node, name: &str) -> TestWallet {
    let client = node
        .create_wallet(name)
        .unwrap_or_else(|_| panic!("failed to create wallet {}", name));

    let secret = SecretKey::new(&mut rand::rng());
    let privkey = PrivateKey::from_secp(secret, Network::Regtest);
    let pubkey: CompressedPublicKey = privkey
        .public_key()
        .try_into()
        .expect("public key must be compressed");

    let address = Address::p2wpkh(pubkey, Network::Regtest);

    let descriptor = format!("wpkh({})", privkey);
    let checksum = client
        .get_descriptor_info(&descriptor)
        .expect("failed to get descriptor info")
        .checksum;
    let descriptor = format!("{}#{}", descriptor, checksum);

    client
        .import_descriptors(&[ImportDescriptorsRequest {
            descriptor,
            timestamp: "now".into(),
        }])
        .expect("failed to import descriptor");

    TestWallet {
        client,
        address,
        privkey,
        pubkey: pubkey.into(),
        witness_utxo: None,
        outpoint: None,
    }
}

pub fn get_wallet(node: &Node, name: &str, start_balance: Amount) -> TestWallet {
    let mut wallet = create_wallet(node, name);

    if start_balance == Amount::ZERO {
        return wallet;
    }

    let miner_address = node
        .client
        .new_address()
        .expect("failed to generate miner address");

    node.client
        .generate_to_address(150, &miner_address)
        .expect("failed to mine blocks");

    node.client
        .send_to_address(
            &to_rpc_address(&wallet.address),
            to_rpc_amount(start_balance),
        )
        .expect("failed to send to wallet");

    node.client
        .generate_to_address(1, &miner_address)
        .expect("failed to mine block");

    let unspent = wallet
        .client
        .list_unspent()
        .expect("failed to list unspent utxos")
        .into_model()
        .expect("failed to parse list_unspent output");

    let utxo = unspent
        .0
        .into_iter()
        .find(|u| u.address.clone().assume_checked() == to_rpc_address(&wallet.address))
        .expect("failed to find wallet's utxo");

    let witness_utxo = TxOut {
        amount: from_rpc_amount(utxo.amount.unsigned_abs()),
        script_pubkey: from_rpc_script_pubkey_buf(utxo.script_pubkey),
    };

    let outpoint = OutPoint {
        txid: from_rpc_txid(utxo.txid),
        vout: utxo.vout,
    };

    wallet.witness_utxo = Some(witness_utxo);
    wallet.outpoint = Some(outpoint);

    wallet
}

pub fn fund_psbt(psbt: &mut Psbt, wallet: &TestWallet, fee: Amount) {
    let input = Input {
        witness_utxo: Some(
            wallet
                .witness_utxo
                .clone()
                .expect("failed to get witness_utxo from wallet"),
        ),
        ..Default::default()
    };

    let txin = TxIn {
        previous_output: wallet
            .outpoint
            .expect("failed to get outpoint from wallet's utxo"),
        script_sig: Default::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    psbt.inputs.push(input);
    psbt.unsigned_tx.inputs.push(txin);

    let input_amount = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .expect("failed to get witness_utxo from psbt")
        .amount;
    let outputs_amount = psbt
        .unsigned_tx
        .outputs
        .iter()
        .map(|o| o.amount)
        .fold(Amount::ZERO, |acc, a| {
            (acc + a).expect("Amount calculation must be valid")
        });

    let change = (input_amount - outputs_amount - fee).expect("Amount calculation must be valid");
    if change != Amount::ZERO {
        psbt.outputs.push(Output::default());
        psbt.unsigned_tx.outputs.push(TxOut {
            script_pubkey: wallet.address.script_pubkey(),
            amount: change,
        });
    }
}

pub fn sign_psbt(psbt: &mut Psbt, wallet: &TestWallet) {
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let witness_utxo = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .expect("failed to get witness_utxo from psbt");

    let sighash = if let Some(witness_script) = psbt.inputs[0].witness_script.as_ref() {
        cache
            .p2wsh_signature_hash(
                0,
                witness_script,
                witness_utxo.amount,
                EcdsaSighashType::All,
            )
            .expect("failed to generate sighash cache")
    } else {
        cache
            .p2wpkh_signature_hash(
                0,
                &witness_utxo.script_pubkey,
                witness_utxo.amount,
                EcdsaSighashType::All,
            )
            .expect("failed to generate sighash cache")
    };
    let msg = Message::from_digest(sighash.to_byte_array());

    let sig = ecdsa::sign(msg, wallet.privkey.as_inner());

    let sig = Signature {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    };

    psbt.inputs[0].partial_sigs.insert(wallet.pubkey, sig);
}

pub fn finalize_tx(psbt: &mut Psbt) {
    let input = &mut psbt.inputs[0];
    let (pubkey, sig) = input
        .partial_sigs
        .first_key_value()
        .expect("failed to get signature from psbt");

    let mut sig_bytes = sig.signature.serialize_der().to_vec();
    sig_bytes.push(sig.sighash_type.to_u32() as u8);

    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pubkey.to_bytes());

    input.final_script_witness = Some(witness);
}

pub fn add_output_psbt(psbt: &mut Psbt, wallet: &TestWallet, fee: Amount) {
    let input_amount = psbt
        .inputs
        .first()
        .expect("failed to get input from psbt")
        .witness_utxo
        .clone()
        .expect("failed to get witness_utxo from psbt")
        .amount;

    let amount = (input_amount - fee).expect("Amount calculaion must be valid");
    psbt.outputs.push(Output::default());
    psbt.unsigned_tx.outputs.push(TxOut {
        script_pubkey: wallet.address.script_pubkey(),
        amount,
    });
}

pub fn get_balance(wallet: &TestWallet) -> Amount {
    let balance = wallet
        .client
        .list_unspent()
        .expect("failed to list unspent utxos")
        .into_model()
        .expect("failed to parse list_unspent output")
        .0
        .iter()
        .map(|a| a.amount)
        .fold(corepc_node::client::bitcoin::Amount::ZERO, |acc, a| {
            acc + a.unsigned_abs()
        });

    from_rpc_amount(balance)
}
