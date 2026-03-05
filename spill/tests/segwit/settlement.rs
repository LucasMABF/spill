use bitcoin::{Amount, primitives::relative};

use crate::{
    common::conversion_utils::to_rpc_tx,
    segwit::{
        setup::{TestContext, setup_test},
        wallet::{get_balance, sign_psbt},
    },
};

#[test]
fn settlement_flow() {
    let start_balance = Amount::from_sat_u32(50_000);
    let fee = Amount::from_sat_u32(1_000);

    let TestContext {
        node,
        funding_tx,
        payer,
        payee,
        mut channel,
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

    let payment1 = Amount::from_sat_u32(10_000);
    let mut payment_psbt = channel
        .next_payment(payment1, fee)
        .expect("failed to send payment");

    sign_psbt(&mut payment_psbt, &payer);

    let _info = channel
        .verify_payment_psbt(&payment_psbt)
        .expect("failed to verify payment");

    channel
        .apply_payment(&payment_psbt)
        .expect("failed to apply payment to channel");

    let payment2 = Amount::from_sat_u32(3_000);
    let mut payment_psbt = channel
        .next_payment(payment2, fee)
        .expect("failed to send payment");

    sign_psbt(&mut payment_psbt, &payer);

    channel
        .apply_payment(&payment_psbt)
        .expect("failed to apply payment to channel");

    sign_psbt(&mut payment_psbt, &payee);
    channel
        .finalize_payment_tx(&mut payment_psbt)
        .expect("failed to finalize payment transaction");
    let payment_tx = payment_psbt
        .extract_tx()
        .expect("failed to extract transaction from psbt");

    node.client
        .send_raw_transaction(&to_rpc_tx(&payment_tx))
        .expect("failed to send payment transaction");

    let burn_address = node
        .client
        .new_address()
        .expect("failed to generate burn address");

    node.client
        .generate_to_address(1, &burn_address)
        .expect("failed to mine block");

    dbg!(payment_tx);

    // start_balance - funding_fee - payments - payment_fee
    let payer_expected_balance = (start_balance - payment1 - payment2 - fee - fee)
        .expect("Amount calculation must be valid");
    let payer_balance = get_balance(&payer);

    assert_eq!(payer_expected_balance, payer_balance);

    let payee_expected_balance = (payment1 + payment2).expect("Amount calculation must be valid");
    let payee_balance = get_balance(&payee);

    assert_eq!(payee_expected_balance, payee_balance);
}
