use bitcoin::{Amount, primitives::relative};

use crate::{
    common::conversion_utils::to_rpc_tx,
    segwit::{
        setup::{TestContext, setup_test},
        wallet::get_balance,
    },
};

#[test]
fn refund_flow() {
    let start_balance = Amount::from_sat_u32(50_000);
    let fee = Amount::from_sat_u32(1_000);

    let TestContext {
        node,
        funding_tx,
        refund_tx,
        payer,
        ..
    } = setup_test(
        start_balance,
        Amount::from_sat_u32(40_000),
        fee,
        relative::LockTime::from_height(10),
    );

    node.client
        .send_raw_transaction(&to_rpc_tx(&funding_tx))
        .expect("failed to broadcast funding transaction");

    let burn_address = node
        .client
        .new_address()
        .expect("failed to generate burn address");
    node.client
        .generate_to_address(10, &burn_address)
        .expect("failed to mine blocks");

    node.client
        .send_raw_transaction(&to_rpc_tx(&refund_tx))
        .expect("failed to send refund transaction");

    node.client
        .generate_to_address(1, &burn_address)
        .expect("failed to mine blocks");

    // start_balance - funding_fee - refund_fee
    let expected_balance = (start_balance - fee - fee).expect("Amount calculation must be valid");
    let balance = get_balance(&payer);

    assert_eq!(expected_balance, balance)
}
