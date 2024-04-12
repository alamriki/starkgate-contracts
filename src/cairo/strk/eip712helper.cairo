// Constants are named using uppercase and underscores for readability.
const STARKNET_DOMAIN_TYPE_HASH: Felt252 =
    0x1BFC207425A47A5DFA1A50A4F5241203F50624CA5FDF5E18755765416B8E288;

const LOCK_AND_DELEGATE_TYPE_HASH: Felt252 =
    0x2AB9656E71E13C39F9F290CC5354D2E50A410992032118A1779539BE0E4E75;

const DAPP_NAME: &str = "TOKEN_LOCK_AND_DELEGATION";
const DAPP_VERSION: &str = "1.0.0";
const STARKNET_MESSAGE: &str = "StarkNet Message";

use starknet::{ContractAddress, get_tx_info};
use openzeppelin::account::interface::{AccountABIDispatcher, AccountABIDispatcherTrait};

// Function to validate the signature using StarkNet's Account ABI Dispatcher.
fn validate_signature(account: ContractAddress, hash: Felt252, signature: Array<Felt252>) {
    let dispatcher = AccountABIDispatcher { contract_address: account };
    let is_valid_signature_felt = dispatcher.is_valid_signature(hash, signature);

    // Check for 'VALID' status or boolean 'true' for backwards compatibility.
    let is_valid_signature = matches!(
        is_valid_signature_felt,
        starknet::VALIDATED | 1
    );

    // Use assert! macro to ensure the signature is valid.
    assert!(
        is_valid_signature,
        "Signature validation failed: expected VALID or true, got {}",
        is_valid_signature_felt
    );
}


// Calculates the message hash for signing, following the SNIP equivalent of EIP-712,
// detailed in https://community.starknet.io/t/snip-off-chain-signatures-a-la-eip712/98029
#[inline(always)]
fn lock_and_delegate_message_hash(
    domain: felt252,
    account: ContractAddress,
    delegatee: ContractAddress,
    amount: u256,
    nonce: felt252,
    expiry: u64,
) -> felt252 {
    let mut lock_and_delegate_inputs = array![
        LOCK_AND_DELEGATE_TYPE_HASH,
        delegatee.into(),
        amount.low.into(), // 2**128 is good enough here, as the entire supply < 2**94.
        nonce,
        expiry.into()
    ]
        .span();
    let lock_and_delegate_hash = pedersen_hash_span(elements: lock_and_delegate_inputs);
    let mut message_inputs = array![
        STARKNET_MESSAGE, domain, account.into(), lock_and_delegate_hash
    ]
        .span();
    pedersen_hash_span(elements: message_inputs)
}

fn calc_domain_hash() -> felt252 {
    let mut domain_state_inputs = array![
        STARKNET_DOMAIN_TYPE_HASH, DAPP_NAME, DAPP_VERSION, get_tx_info().unbox().chain_id
    ]
        .span();
    pedersen_hash_span(elements: domain_state_inputs)
}

fn pedersen_hash_span(mut elements: Span<felt252>) -> felt252 {
    let number_of_elements = elements.len();
    assert(number_of_elements > 0, 'Requires at least one element');

    // Pad with 0.
    let mut current: felt252 = 0;
    loop {
        // Pop elements and apply hash.
        match elements.pop_front() {
            Option::Some(next) => { current = pedersen::pedersen(current, *next); },
            Option::None(()) => { break; },
        };
    };
    // Hash with number of elements.
    pedersen::pedersen(current, number_of_elements.into())
}
