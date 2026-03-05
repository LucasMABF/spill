use bitcoin::{Amount, OutPoint, Transaction, primitives::relative};
use corepc_node::Node;
use spill::{Channel, ChannelParams, SegwitBackend};

use crate::segwit::wallet::{
    TestWallet, add_output_psbt, finalize_tx, fund_psbt, get_wallet, sign_psbt,
};

pub struct TestContext {
    pub node: Node,
    pub payer: TestWallet,
    pub payee: TestWallet,
    pub funding_tx: Transaction,
    pub channel: Channel<SegwitBackend>,
    pub refund_tx: Transaction,
}

pub fn setup_test(
    payer_start_balance: Amount,
    channel_capacity: Amount,
    fee: Amount,
    locktime: relative::LockTime,
) -> TestContext {
    let exe = corepc_node::exe_path().expect("bitcoind executable not found");
    let node = corepc_node::Node::new(exe).expect("failed to start node");

    let payer = get_wallet(&node, "payer", payer_start_balance);
    let payee = get_wallet(&node, "payee", Amount::ZERO);

    let channel_params = ChannelParams::new(
        payer.pubkey,
        payee.pubkey,
        channel_capacity,
        locktime,
        SegwitBackend::new(),
    )
    .expect("failed to create ChannelParams");

    let mut funding_psbt = channel_params.funding_psbt();

    fund_psbt(&mut funding_psbt, &payer, fee);
    sign_psbt(&mut funding_psbt, &payer);
    finalize_tx(&mut funding_psbt);
    let funding_tx = funding_psbt
        .extract_tx()
        .expect("failed to extract transaction from psbt");

    let vout = funding_tx
        .outputs
        .iter()
        .position(|o| o.script_pubkey == *channel_params.script_pubkey())
        .expect("failed to find funding output") as u32;

    let outpoint = OutPoint {
        txid: funding_tx.compute_txid(),
        vout,
    };

    let channel = channel_params
        .verify_funding_tx(&funding_tx, outpoint)
        .expect("failed to generate Channel");

    let mut refund_psbt = channel.refund_psbt();

    add_output_psbt(&mut refund_psbt, &payer, fee);
    sign_psbt(&mut refund_psbt, &payer);

    channel
        .finalize_refund_tx(&mut refund_psbt)
        .expect("failed to finalize refund psbt");

    let refund_tx = refund_psbt
        .extract_tx()
        .expect("failed to extract refund transaction");

    TestContext {
        node,
        payer,
        payee,
        funding_tx,
        channel,
        refund_tx,
    }
}
