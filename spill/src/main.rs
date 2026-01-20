use std::{fs, str::FromStr};

use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, Psbt, PublicKey, ScriptBuf,
    Sequence, TxIn, TxOut, Witness,
    consensus::encode::serialize_hex,
    ecdsa::Signature,
    psbt::{Input, Output},
    secp256k1::{self, Message, SecretKey},
    sighash::SighashCache,
};
use serde_json::Value;
use spill::ChannelParams;

struct Wallet {
    private_key: PrivateKey,
    public_key: PublicKey,
    address: Address,
    utxo_outpoint: Option<OutPoint>,
    utxo_txout: Option<TxOut>,
}

fn main() {
    let (alice, bob) = load_wallets();

    let ch_params = ChannelParams::new(
        alice.public_key,
        bob.public_key,
        Amount::from_int_btc(1),
        Sequence::from_height(6),
    )
    .unwrap();

    let mut psbt = ch_params.funding_psbt();

    complete_funding_tx(&alice, &mut psbt);

    sign_funding_tx(&alice, &mut psbt);

    finalize_funding_tx(&mut psbt);

    let funding_tx = psbt.extract_tx().unwrap();
    let funding_tx_hex = serialize_hex(&funding_tx);
    let funding_tx_id = funding_tx.compute_txid();

    println!("{}", funding_tx_hex);
    println!("{}", funding_tx_id);

    let funding_outpoint = OutPoint {
        txid: funding_tx_id,
        vout: 0,
    };

    let mut ch = ch_params
        .verify_funding_tx(&funding_tx, funding_outpoint)
        .unwrap();

    let mut psbt = ch
        .next_payment(Amount::from_sat(1000), Amount::from_sat(1000))
        .unwrap();

    sign_payment_tx(&alice, &mut psbt);

    // send it to bob
    ch.apply_payment(&psbt).unwrap();

    let mut psbt = ch
        .next_payment(Amount::from_sat(4000), Amount::from_sat(1000))
        .unwrap();

    sign_payment_tx(&alice, &mut psbt);

    // send it to bob
    ch.apply_payment(&psbt).unwrap();

    sign_payment_tx(&bob, &mut psbt);

    ch.finalize_payment_tx(&mut psbt).unwrap();

    let payment_tx = psbt.extract_tx().unwrap();
    let payment_tx_hex = serialize_hex(&payment_tx);
    let payment_tx_id = payment_tx.compute_txid();

    println!("{}", payment_tx_hex);
    println!("{}", payment_tx_id);

    // make refund tx for Alice
    let mut psbt = ch.refund_psbt();

    complete_refund_tx(&alice, &mut psbt);
    sign_refund_tx(&alice, &mut psbt);
    ch.finalize_refund_tx(&mut psbt).unwrap();

    let refund_tx = psbt.extract_tx().unwrap();
    let refund_tx_hex = serialize_hex(&refund_tx);
    let refund_tx_id = refund_tx.compute_txid();

    println!("{}", refund_tx_hex);
    println!("{}", refund_tx_id);
}

fn sign_refund_tx(signer: &Wallet, psbt: &mut Psbt) {
    let witness_script = psbt.inputs[0].witness_script.as_ref().unwrap();
    let witness_utxo = psbt.inputs[0].witness_utxo.as_ref().unwrap();

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(0, witness_script, witness_utxo.value, EcdsaSighashType::All)
        .unwrap();

    let msg = Message::from_digest_slice(&sighash[..]).unwrap();

    let curve = secp256k1::Secp256k1::new();
    let sig = curve.sign_ecdsa(&msg, &signer.private_key.inner);

    let sig = Signature {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    };

    psbt.inputs[0].partial_sigs.insert(signer.public_key, sig);
}

fn complete_refund_tx(payer: &Wallet, psbt: &mut Psbt) {
    let fee = Amount::from_sat(1000);

    let txout = TxOut {
        value: Amount::from_int_btc(1) - fee,
        script_pubkey: payer.address.script_pubkey(),
    };

    psbt.outputs.push(Output::default());
    psbt.unsigned_tx.output.push(txout);
}

fn sign_payment_tx(signer: &Wallet, psbt: &mut Psbt) {
    let witness_script = psbt.inputs[0].witness_script.as_ref().unwrap();
    let witness_utxo = psbt.inputs[0].witness_utxo.as_ref().unwrap();

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(0, witness_script, witness_utxo.value, EcdsaSighashType::All)
        .unwrap();

    let msg = Message::from_digest_slice(&sighash[..]).unwrap();

    let curve = secp256k1::Secp256k1::new();
    let sig = curve.sign_ecdsa(&msg, &signer.private_key.inner);

    let sig = Signature {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    };

    psbt.inputs[0].partial_sigs.insert(signer.public_key, sig);
}

fn finalize_funding_tx(psbt: &mut Psbt) {
    let input = &mut psbt.inputs[0];
    let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();

    let mut sig_bytes = sig.signature.serialize_der().to_vec();
    sig_bytes.push(sig.sighash_type.to_u32() as u8);

    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pubkey.to_bytes());

    input.final_script_witness = Some(witness);
}

fn sign_funding_tx(payer: &Wallet, psbt: &mut Psbt) {
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            0,
            &payer.address.script_pubkey(),
            payer.utxo_txout.clone().unwrap().value,
            EcdsaSighashType::All,
        )
        .unwrap();

    let msg = secp256k1::Message::from_digest_slice(&sighash[..]).unwrap();

    let curve = secp256k1::Secp256k1::new();
    let sig = curve.sign_ecdsa(&msg, &payer.private_key.inner);

    let sig = Signature {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    };

    psbt.inputs[0].partial_sigs.insert(payer.public_key, sig);
}

fn complete_funding_tx(payer: &Wallet, psbt: &mut Psbt) {
    let input = Input {
        witness_utxo: Some(payer.utxo_txout.clone().unwrap()),
        ..Default::default()
    };

    let txin = TxIn {
        previous_output: payer.utxo_outpoint.unwrap(),
        script_sig: Default::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    psbt.inputs.push(input);
    psbt.unsigned_tx.input.push(txin);

    let fee = Amount::from_sat(1000);

    let txout = TxOut {
        value: payer.utxo_txout.clone().unwrap().value - (psbt.unsigned_tx.output[0].value + fee),
        script_pubkey: payer.address.script_pubkey(),
    };

    psbt.outputs.push(Output::default());
    psbt.unsigned_tx.output.push(txout);
}

fn load_wallets() -> (Wallet, Wallet) {
    let data = fs::read_to_string("wallets.json").unwrap();
    let wallets: Value = serde_json::from_str(&data).unwrap();

    let curve = secp256k1::Secp256k1::new();

    let alice_private_key_hex = wallets["alice"]["private_key"].as_str().unwrap();
    let alice_secret_key = SecretKey::from_str(alice_private_key_hex).unwrap();
    let alice_private_key = PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: alice_secret_key,
    };
    let alice_public_key = alice_private_key.public_key(&curve);

    let utxo_outpoint =
        OutPoint::from_str(wallets["alice"]["utxo_outpoint"].as_str().unwrap()).unwrap();
    let utxo_txout = TxOut {
        value: Amount::from_sat(wallets["alice"]["utxo_txout"]["value"].as_u64().unwrap()),
        script_pubkey: ScriptBuf::from_hex(
            wallets["alice"]["utxo_txout"]["script_pubkey_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    };

    let alice_address = Address::p2wpkh(&alice_public_key.try_into().unwrap(), Network::Signet);

    let check = Address::from_str(wallets["alice"]["address"].as_str().unwrap())
        .unwrap()
        .require_network(Network::Signet)
        .unwrap();

    assert!(
        alice_address == check,
        "Address generated don't match the one provided."
    );

    let alice = Wallet {
        private_key: alice_private_key,
        public_key: alice_public_key,
        address: alice_address,
        utxo_outpoint: Some(utxo_outpoint),
        utxo_txout: Some(utxo_txout),
    };

    let bob_private_key_hex = wallets["bob"]["private_key"].as_str().unwrap();
    let bob_secret_key = SecretKey::from_str(bob_private_key_hex).unwrap();
    let bob_private_key = PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: bob_secret_key,
    };
    let bob_public_key = bob_private_key.public_key(&curve);

    let bob_address = Address::p2wpkh(&bob_public_key.try_into().unwrap(), Network::Signet);

    let check = Address::from_str(wallets["bob"]["address"].as_str().unwrap())
        .unwrap()
        .require_network(Network::Signet)
        .unwrap();

    assert!(
        bob_address == check,
        "Address generated don't match the one provided."
    );

    let bob = Wallet {
        private_key: bob_private_key,
        public_key: bob_public_key,
        address: bob_address,
        utxo_outpoint: None,
        utxo_txout: None,
    };

    (alice, bob)
}
