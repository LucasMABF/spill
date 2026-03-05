use std::str::FromStr;

pub fn to_rpc_tx(tx: &bitcoin::Transaction) -> corepc_node::client::bitcoin::Transaction {
    let bytes = bitcoin::consensus::encode::serialize(&tx);
    corepc_node::client::bitcoin::consensus::encode::deserialize(&bytes)
        .expect("failed to deserialize transaction to old version")
}

pub fn to_rpc_address(address: &bitcoin::Address) -> corepc_node::client::bitcoin::Address {
    let bech32 = address.to_string();
    corepc_node::client::bitcoin::Address::from_str(&bech32)
        .expect("failed to parse address to old version")
        .require_network(corepc_node::client::bitcoin::Network::Regtest)
        .expect("Network should be Regtest")
}

pub fn from_rpc_script_pubkey_buf(
    script_pub_key_buf: corepc_node::client::bitcoin::ScriptBuf,
) -> bitcoin::ScriptPubKeyBuf {
    let bytes = script_pub_key_buf.into_bytes();
    bitcoin::ScriptPubKeyBuf::from_bytes(bytes)
}

pub fn from_rpc_amount(amount: corepc_node::client::bitcoin::Amount) -> bitcoin::Amount {
    let bytes = corepc_node::client::bitcoin::consensus::encode::serialize(&amount);
    bitcoin::consensus::encode::deserialize(&bytes)
        .expect("failed to deserialize amount to new version")
}

pub fn to_rpc_amount(amount: bitcoin::Amount) -> corepc_node::client::bitcoin::Amount {
    let bytes = bitcoin::consensus::encode::serialize(&amount);
    corepc_node::client::bitcoin::consensus::encode::deserialize(&bytes)
        .expect("failed to deserialize amount to old version")
}

pub fn from_rpc_txid(txid: corepc_node::client::bitcoin::Txid) -> bitcoin::Txid {
    let txid_str = txid.to_string();
    bitcoin::Txid::from_str(&txid_str).expect("failed to parse txid to new version")
}
