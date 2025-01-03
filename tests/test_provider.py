import time

import pytest
from ape import reverts
from ape.exceptions import BlockNotFoundError, TransactionNotFoundError
from eth_utils import to_hex

from ape_titanoboa.config import DEFAULT_TEST_CHAIN_ID


@pytest.fixture(scope="module", autouse=True)
def sepolia_fork(networks):
    with networks.ethereum.local.use_provider("boa") as provider:
        yield provider


def test_is_connected(chain):
    assert chain.provider.is_connected


def test_deploy_contract(contract, owner):
    instance = contract.deploy(123, sender=owner)
    assert instance.address is not None
    assert instance.contract_type is not None


def test_send_transaction(chain, contract_instance, owner):
    expected_block = chain.provider.get_block("pending")
    tx = contract_instance.setNumber(321, sender=owner)
    assert not tx.failed
    assert tx.block_number == expected_block.number

    # Show that state has changed.
    assert contract_instance.myNumber() == 321

    # Show the "new" pending block is expected (+1).
    new_pending_block = chain.provider.get_block("pending")
    assert new_pending_block.number == expected_block.number + 1
    assert new_pending_block.timestamp >= expected_block.timestamp


def test_send_call(contract_instance, owner):
    result = contract_instance.myNumber()
    assert result == 123


def test_get_receipt(contract_instance, owner, chain):
    tx = contract_instance.setNumber(321, sender=owner)
    tx_hash = tx.txn_hash

    actual = chain.provider.get_receipt(tx_hash)
    assert actual.txn_hash == tx.txn_hash

    # Show we get the correct error when the receipt is not found.
    with pytest.raises(TransactionNotFoundError):
        chain.provider.get_receipt("asdfasdfasdf")


def test_AccountAPI_nonce(owner, contract):
    """
    Showing the integration with `AccountAPI.nonce` works
    (testing `TitanoboaProvider.get_nonce()` indirectly).
    """
    start_nonce = owner.nonce
    assert isinstance(start_nonce, int)

    # Deploy (transact)
    contract.deploy(123, sender=owner)

    assert owner.nonce == start_nonce + 1


def test_ReceiptAPI_events(owner, contract_instance):
    """
    Shows the integration with `ReceiptAPI.events / decode_logs` works
    (testing the result of `TitanobaProvider.send_transaction() | .get_receipt()`).
    """
    tx = contract_instance.setNumber(321, sender=owner)
    actual = tx.events
    assert len(actual) == 1
    assert actual[0].prevNum == 123
    assert actual[0].newNum == 321


def test_get_block(chain):
    # Earliest block (genesis).
    zero_block = chain.provider.get_block(0)
    earliest_block = chain.provider.get_block("earliest")
    assert zero_block.number == 0
    assert earliest_block.number == 0
    assert zero_block.hash == earliest_block.hash

    # Latest block (chain height).
    chain.mine()
    latest_block = chain.provider.get_block("latest")
    latest_block_by_number = chain.provider.get_block(latest_block.number)
    assert latest_block_by_number.number == latest_block.number
    assert latest_block.hash != earliest_block.hash

    # Pending block.
    pending_block = chain.provider.get_block("pending")
    assert pending_block.number == latest_block.number + 1
    assert pending_block.hash != latest_block.hash
    assert pending_block.hash != zero_block.hash

    # By number.
    chain.mine(5)
    number = chain.blocks.height - 3
    block_by_number = chain.provider.get_block(number)
    assert block_by_number.number == number
    with pytest.raises(BlockNotFoundError):
        chain.provider.get_block(chain.blocks.height + 100)

    # Show "earliest" still works after mining.
    earliest_again = chain.provider.get_block("earliest")
    assert earliest_again.number == earliest_block.number

    # By hash.
    block_by_hash = chain.provider.get_block(block_by_number.hash)
    assert block_by_hash.number == block_by_number.number
    with pytest.raises(BlockNotFoundError):
        chain.provider.get_block(b"111111")


def test_get_transactions_by_block(contract_instance, owner, chain):
    tx = contract_instance.setNumber(321, sender=owner)
    latest_block = chain.blocks.head

    for block_id in ("latest", latest_block.number, latest_block.hash):
        actual = list(chain.provider.get_transactions_by_block(block_id))

    assert len(actual) == 1
    assert to_hex(actual[-1].txn_hash) == tx.txn_hash


def test_AccountAPI_balance(owner):
    """
    Show the integration with `AccountAPI.balance` works
    (calls `TitanoboaProvider.get_balance()` under-the-hood.
    """
    assert owner.balance > 0


def test_ChainManager_mine(chain):
    """
    Calls `TitanoboaProvider.mine()` under-the-hood.
    """
    height = chain.blocks.height
    chain.mine()
    assert chain.blocks.height == height + 1


def test_auto_mine(chain, owner):
    assert chain.provider.auto_mine
    chain.provider.auto_mine = False
    assert not chain.provider.auto_mine
    chain.provider.auto_mine = True

    # Show auto-mine works.
    height = chain.blocks.height
    owner.transfer(owner, 123)
    height += 1
    assert chain.blocks.height == height

    # Show manual-mine works.
    chain.provider.auto_mine = False
    owner.transfer(owner, 123)
    assert chain.blocks.height == height, "Chain mined when auto_mine=False"
    chain.provider.mine()
    height += 1
    assert chain.blocks.height == height

    chain.provider.auto_mine = True


def test_snapshot(chain):
    actual = chain.provider.snapshot()
    assert actual


def test_get_code(chain, contract_instance):
    actual = chain.provider.get_code(contract_instance.address)
    assert bool(actual)  # Exists.


def test_restore(chain, owner, contract, accounts):
    # Initial state.
    instance = contract.deploy(123, sender=owner)
    state = instance.myNumber()
    height = chain.blocks.height
    nonce = owner.nonce
    balance = owner.balance
    timestamp = chain.blocks.head.timestamp

    # We should come back to the initial state when restoring.
    snapshot = chain.snapshot()

    # Wreck state.
    chain.mine(5)
    tx = owner.transfer(accounts[1], 1)
    txn_hash = tx.txn_hash
    assert chain.provider.get_receipt(txn_hash)  # This works now, but shouldn't after restore.
    instance.setNumber(321, sender=owner)
    deployment = contract.deploy(555, sender=owner)

    # Go back and ensure we are 100% back.
    chain.restore(snapshot)

    failing_tests = []
    passing_tests = []

    def run_test(name, act, expt):
        result = passing_tests if act == expt else failing_tests
        result.append(name)

    run_test("CHAIN HEIGHT", chain.blocks.height, height)
    run_test("ACCOUNT NONCE", owner.nonce, nonce)
    run_test("ACCOUNT BALANCE", owner.balance, balance)
    run_test("DEPLOYMENT CODE", bool(chain.provider.get_code(deployment.address)), False)
    run_test("CONTRACT STATE", instance.myNumber(), state)
    run_test("BLOCK TIMESTAMP", chain.blocks.head.timestamp, timestamp)

    # Ensure the transaction made during "wrecking state" is no longer found.
    with pytest.raises(TransactionNotFoundError):
        _ = chain.provider.get_receipt(txn_hash)

    if failing_tests:
        failing_tests_str = ", ".join(failing_tests)
        fail_msg = f"State not restored: '{failing_tests_str}'."
        pytest.fail(fail_msg)


def test_chain_isolate(chain, owner, contract, accounts):
    """
    Show we integrate with `chain.isolate()` well
    (similar to `test_restore()`).
    """
    instance = contract.deploy(123, sender=owner)
    state = instance.myNumber()
    height = chain.blocks.height
    nonce = owner.nonce
    balance = owner.balance
    timestamp = chain.blocks.head.timestamp

    with chain.isolate():
        # Wreck state.
        chain.mine(5)
        owner.transfer(accounts[1], 1)
        instance.setNumber(321, sender=owner)
        deployment = contract.deploy(555, sender=owner)

    failing_tests = []
    passing_tests = []

    def run_test(name, act, expt):
        result = passing_tests if act == expt else failing_tests
        result.append(name)

    run_test("CHAIN HEIGHT", chain.blocks.height, height)
    run_test("ACCOUNT NONCE", owner.nonce, nonce)
    run_test("ACCOUNT BALANCE", owner.balance, balance)
    run_test("DEPLOYMENT CODE", bool(chain.provider.get_code(deployment.address)), False)
    run_test("CONTRACT STATE", instance.myNumber(), state)
    run_test("BLOCK TIMESTAMP", chain.blocks.head.timestamp, timestamp)

    if failing_tests:
        failing_tests_str = ", ".join(failing_tests)
        fail_msg = f"State not restored: '{failing_tests_str}'."
        pytest.fail(fail_msg)


def test_estimate_gas_cost(chain, owner, contract_instance):
    tx = contract_instance.setNumber.as_transaction(123, sender=owner)
    actual = chain.provider.estimate_gas_cost(tx)
    assert actual > 0


def test_set_balance(chain, owner):
    balance = owner.balance
    new_balance = balance * 2
    chain.provider.set_balance(owner.address, new_balance)
    assert owner.balance == new_balance


def test_reverts(chain, contract_instance, accounts):
    """
    Integration test with `ape.reverts`.
    """
    not_owner = accounts[2]
    with reverts("!authorized"):
        contract_instance.setNumber(55, sender=not_owner)


def test_trace(contract_instance, owner):
    """
    Integration testing various tracing-related features
    you would use in testing, such `.return_value`.
    """
    tx = contract_instance.setNumber(456, sender=owner)
    trace = tx.trace
    assert trace is not None

    # Root method ABI
    assert trace.root_method_abi.name == "setNumber"

    # `ReceiptAPI.return_value` test.
    actual_retval = tx.return_value
    expected_retval = 461  # 456 + 5 (see smart-contract)
    assert actual_retval == expected_retval

    # CallTreeNode
    call_tree_node = tx.trace.get_calltree()
    assert call_tree_node is not None


def test_account_impersonation(contract, contract_instance, owner, accounts, chain):
    """
    Ensuring the boa integration works with an account-impersonation flow.
    """
    impersonated_account = accounts[contract_instance.address]
    impersonated_account.balance = owner.balance
    receipt = contract_instance.setBalance(owner, 0, sender=impersonated_account)
    assert receipt.sender == contract_instance.address

    # Getting a past receipt.
    chain.mine()
    past_receipt = chain.provider.get_receipt(receipt.txn_hash)
    assert past_receipt.txn_hash == receipt.txn_hash

    # Deploy.
    new_contract = contract.deploy(555, sender=impersonated_account)
    tx = new_contract.setNumber(556, sender=impersonated_account)
    assert tx.sender == impersonated_account.address
    assert new_contract.myNumber() == 556
    assert len(tx.logs) > 0

    # Return value (tracing).
    actual_returnvalue = tx.return_value
    expected_returnvalue = 561  # 556 + 5
    assert actual_returnvalue == expected_returnvalue
    assert chain.provider.get_receipt(tx.txn_hash).return_value == expected_returnvalue

    # Revert detection.
    with reverts("!authorized"):
        contract_instance.setNumber(55, sender=impersonated_account)


def test_set_timestamp(chain):
    time_at_start = int(time.time())
    start_ts = chain.blocks.head.timestamp
    new_timestamp = start_ts + 2500
    chain.provider.set_timestamp(new_timestamp)

    def wait_for_time_to_increase(start_time):
        now = int(time.time())
        while now <= start_time:
            now = int(time.time())

    # Show that time is froze after setting the timestamp.
    wait_for_time_to_increase(time_at_start)
    assert chain.pending_timestamp == new_timestamp

    # After mining, the timestamp is no longer frozen but it
    # MUST stay in the future passed the point when it was frozen.
    chain.provider.mine()
    wait_for_time_to_increase(int(time.time()))
    ts = chain.pending_timestamp
    assert ts > new_timestamp  # Is passed (not behind!) the time when it was frozen.
    wait_for_time_to_increase(int(time.time()))
    assert chain.pending_timestamp > ts  # No longer frozen!


def test_mine(chain):
    start_number = chain.blocks.height
    chain.provider.mine()
    actual = chain.blocks.height
    expected = start_number + 1
    assert actual == expected

    # Show can mine more than 1 block.
    start_number = chain.blocks.height
    to_mine = 3
    chain.provider.mine(to_mine)
    actual = chain.blocks.height
    expected = start_number + to_mine
    assert actual == expected


def test_pending_timestamp(chain):
    """
    Show we integrate well with `chain.pending_timestamp`.
    """
    pending_ts = chain.pending_timestamp
    new_ts = pending_ts + 5
    chain.provider.set_timestamp(new_ts)
    assert chain.pending_timestamp == new_ts


def test_onchain_timestamp(chain, contract_instance, owner):
    """
    Testing that Ape's timestamp is the same as a contract's
    usage of `block.timestamp`.
    """

    def run_test():
        ape_ts = chain.blocks.head.timestamp
        chain_ts = contract_instance.getBlockTimestamp()
        assert ape_ts == chain_ts

    run_test()

    # Show still works after mining.
    chain.mine()
    run_test()

    # Show still works after changing the timestamp manually.
    new_ts = chain.blocks.head.timestamp + 7
    chain.provider.set_timestamp(new_ts)
    run_test()

    # Show still works after transacting.
    expected = chain.pending_timestamp
    expected_block = chain.provider.get_block("pending")
    tx = contract_instance.setNumber(777, sender=owner)
    run_test()

    latest_block = chain.provider.get_block("latest")
    assert tx.block_number == latest_block.number, "Transaction not in latest block."
    assert tx.block_number == expected_block.number, "Transaction mined on un-expected block."

    actual = tx.timestamp
    if actual < expected:
        pytest.fail("Somehow went back in time after mining a new block.")


def test_chain_id(chain):
    actual = chain.provider.chain_id
    expected = DEFAULT_TEST_CHAIN_ID
    assert actual == expected
