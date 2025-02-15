import time

import pytest
from ape import Contract, reverts
from ape.exceptions import BlockNotFoundError, ContractLogicError, TransactionNotFoundError
from ape.types.events import LogFilter
from eth.exceptions import Revert
from eth_utils import to_hex
from hexbytes import HexBytes

from ape_titanoboa.config import DEFAULT_TEST_CHAIN_ID
from ape_titanoboa.trace import BoaTrace


def test_is_connected(chain, networks, run_fork_tests):
    assert chain.provider.is_connected

    if run_fork_tests:
        with networks.ethereum.sepolia_fork.use_provider("boa"):
            assert chain.provider.is_connected


def test_deploy_contract(contract, owner, networks):
    instance = contract.deploy(123, sender=owner)
    assert instance.address is not None
    assert instance.contract_type is not None

    # TODO: Deploying contracts in fork mode currently does not work.
    #   (Charles is aware)
    # with networks.ethereum.sepolia_fork.use_provider("boa"):
    #     with pytest.raises(ContractNotFoundError):
    #         assert instance.myNumber()
    #
    #     fork_instance = contract.deploy(123, sender=owner)
    #     assert fork_instance.address is not None
    #     assert fork_instance.contract_type is not None

    # Contract is found again after leaving the forked context.
    assert instance.myNumber() == 123


def test_deploy_contract_with_default_payable_method(chain, project, owner):
    """
    Tests against a bug where if you tried to deploy a contract with a default
    payable method, Ape's proxy detection system would trigger an error
    about mutating static-call state.
    """
    contract = project.ContractWithDefaultPayable.deploy(sender=owner)
    assert contract.contract_type.name == "ContractWithDefaultPayable"


def test_send_transaction(chain, contract_instance, contract, owner, networks, not_owner):
    expected_block = chain.provider.get_block("pending")
    tx = contract_instance.setNumber(321, sender=owner)
    assert tx.signature is None
    assert not tx.failed
    assert tx.block_number == expected_block.number

    # Show that state has changed.
    assert contract_instance.myNumber() == 321

    # Show the "new" pending block is expected (+1).
    new_pending_block = chain.provider.get_block("pending")
    assert new_pending_block.number == expected_block.number + 1
    assert new_pending_block.timestamp >= expected_block.timestamp

    # TODO: Deploying contracts in fork mode currently does not work.
    #   (Charles is aware)
    # Show we can transact on forked networks too.
    # block_id_from_config = 7341111
    # with networks.ethereum.sepolia_fork.use_provider("boa"):
    #     fork_contract_instance = contract.deploy(123, sender=owner)
    #     tx = fork_contract_instance.setNumber(321, sender=owner)
    #     assert tx.block_number >= block_id_from_config

    # Show it goes back to the local block number.
    # tx = contract_instance.setNumber(321123, sender=owner)
    # assert tx.block_number < block_id_from_config

    # Show we can send failing transactions.
    tx = contract_instance.setNumber(3213, sender=not_owner, raise_on_revert=False)
    assert tx.failed


def test_send_transaction_payable(contract_instance, owner):
    contract_instance.gimmeMoney(value=1, sender=owner)
    with reverts():
        contract_instance.gimmeMoney(sender=owner)


def test_send_transaction_sign(contract_instance, owner):
    tx = contract_instance.gimmeMoney(value=1, sender=owner, sign=True)
    assert tx.signature is not None
    assert not tx.failed


def test_send_call(contract_instance, owner, contract, networks, run_fork_tests):
    result = contract_instance.myNumber()
    assert result == 123

    if run_fork_tests:
        with networks.ethereum.sepolia_fork.use_provider("boa"):
            # fork_contract_instance = contract.deploy(111, sender=owner)
            # result = fork_contract_instance.myNumber()
            # assert result == 111

            # Interact with apip Sepolia contract.
            polyhedra = Contract("0x465C15e9e2F3837472B0B204e955c5205270CA9E")
            assert polyhedra.name() == "tZKJ"

        # Show it works the same back on local.
        result = contract_instance.myNumber()
        assert result == 123


def test_send_call_method_not_exists(chain, contract_instance):
    tx = chain.provider.network.ecosystem.create_transaction(
        data="0x12345678000", receiver=contract_instance.address
    )
    with pytest.raises(ContractLogicError):
        _ = chain.provider.send_call(tx)


def test_get_receipt(contract_instance, owner, chain, networks, run_fork_tests):
    local_tx = contract_instance.setNumber(321, sender=owner)
    actual = chain.provider.get_receipt(local_tx.txn_hash)
    assert actual.txn_hash == local_tx.txn_hash

    # Show we get the correct error when the receipt is not found.
    with pytest.raises(TransactionNotFoundError):
        chain.provider.get_receipt("asdfasdfasdf")

    if run_fork_tests:
        # Get a sepolia receipt.
        with networks.ethereum.sepolia_fork.use_provider("boa"):
            txn_hash = "0x68605140856c13038d325048c411aed98cc1eecc189f628a38edb597f6b9679e"
            receipt = chain.provider.get_receipt(txn_hash)
            assert receipt.txn_hash == txn_hash

            # Ensure the local transaction we made isn't available.
            with pytest.raises(TransactionNotFoundError):
                _ = chain.provider.get_receipt(local_tx.txn_hash)

            sepolia_tx = owner.transfer(owner, 0)
            assert chain.provider.get_receipt(sepolia_tx.txn_hash).txn_hash == sepolia_tx.txn_hash

        # Ensure the sepolia-fork transaction we made isn't available.
        with pytest.raises(TransactionNotFoundError):
            _ = chain.provider.get_receipt(sepolia_tx.txn_hash)

        # Get a holesky receipt.
        with networks.ethereum.holesky_fork.use_provider("boa"):
            txn_hash = "0x611745e08130a55df98a3758ac6029fb68a60651dad15d6ee6435e457ac8ed34"
            receipt = chain.provider.get_receipt(txn_hash)
            assert receipt.txn_hash == txn_hash

            # Ensure the local transaction we made isn't available.
            with pytest.raises(TransactionNotFoundError):
                _ = chain.provider.get_receipt(local_tx.txn_hash)

            # Ensure the sepolia-fork transaction we made isn't available.
            with pytest.raises(TransactionNotFoundError):
                _ = chain.provider.get_receipt(sepolia_tx.txn_hash)

            holesky_tx = owner.transfer(owner, 0)
            assert chain.provider.get_receipt(holesky_tx.txn_hash).txn_hash == holesky_tx.txn_hash

        # Ensure the holesky-fork transaction we made isn't available.
        with pytest.raises(TransactionNotFoundError):
            _ = chain.provider.get_receipt(holesky_tx.txn_hash)


def test_AccountAPI_nonce(owner, contract, chain, networks, run_fork_tests):
    """
    Showing the integration with `AccountAPI.nonce` works
    (testing `TitanoboaProvider.get_nonce()` indirectly).
    """
    start_nonce = owner.nonce
    assert isinstance(start_nonce, int)

    # Deploy (transact)
    contract.deploy(123, sender=owner)
    local_nonce = owner.nonce
    nonce_before_fork = start_nonce + 1
    assert local_nonce == nonce_before_fork

    # Local boa doesn't know Vitalik.
    vitalik = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    assert chain.provider.get_nonce(vitalik) == 0

    if run_fork_tests:
        with networks.ethereum.holesky_fork.use_provider("boa"):
            # Transact so the nonce changes on the fork.
            start_nonce = owner.nonce
            owner.transfer(owner, 9)
            assert owner.nonce == start_nonce + 1

        with networks.ethereum.mainnet_fork.use_provider("boa"):
            # Mainnet fork boa knows Vitalik's nonce.
            assert chain.provider.get_nonce(vitalik) > 0

        # Show the nonce is as it was.
        assert owner.nonce == nonce_before_fork


def test_ReceiptAPI_logs(owner, contract_instance):
    tx = contract_instance.setNumber(321, sender=owner)
    actual = tx.logs
    for log in actual:
        for topic in log["topics"]:
            # Every topic *MUST* be 32 bytes or else it may fail
            # to decode to an event.
            assert len(topic) == 32


def test_ReceiptAPI_events(owner, contract_instance):
    """
    Shows the integration with `ReceiptAPI.events / decode_logs` works
    (testing the result of `TitanoboaProvider.send_transaction() | .get_receipt()`).
    """
    tx = contract_instance.setNumber(321, sender=owner)
    actual = tx.events
    assert len(actual) == 1
    assert actual[0].prevNum == 123
    assert actual[0].newNum == 321


def test_get_block(chain, networks, run_fork_tests):
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

    # Get blocks from sepolia.
    if run_fork_tests:
        with networks.ethereum.sepolia_fork.use_provider("boa"):
            block = chain.provider.get_block("latest")
            assert block.number >= 7341111  # From configuration.

            # Mine.
            chain.provider.mine(5)
            block = chain.provider.get_block("latest")
            assert block.number >= 7341116
            block = chain.provider.get_block(7341116)
            assert block.number == 7341116

            # Historical block.
            block = chain.provider.get_block(3)
            assert block.timestamp == 1634951317


def test_get_transactions_by_block(contract_instance, owner, chain):
    tx = contract_instance.setNumber(321, sender=owner)
    latest_block = chain.blocks.head

    for block_id in ("latest", latest_block.number, latest_block.hash):
        actual = list(chain.provider.get_transactions_by_block(block_id))

    assert len(actual) == 1
    assert to_hex(actual[-1].txn_hash) == tx.txn_hash


def test_AccountAPI_balance(owner, networks, run_fork_tests):
    """
    Show the integration with `AccountAPI.balance` works
    (calls `TitanoboaProvider.get_balance()` under-the-hood.
    """
    balance = owner.balance
    assert balance > 0

    if run_fork_tests:
        with networks.ethereum.mainnet_fork.use_provider("boa"):
            assert owner.balance != balance

    # Show it goes back after fork.
    assert owner.balance == balance


def test_ChainManager_mine(chain):
    """
    Calls `TitanoboaProvider.mine()` under-the-hood.
    """
    height = chain.blocks.height
    chain.mine()
    assert chain.blocks.height == height + 1


def test_auto_mine(chain, owner, project):
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

    # Show can set auto-mine in config.
    with project.temp_config(titanoboa={"auto_mine": True}):
        assert chain.provider.auto_mine
    with project.temp_config(titanoboa={"auto_mine": False}):
        assert not chain.provider.auto_mine


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


def test_estimate_gas_cost(chain, owner, contract_instance, accounts):
    tx = contract_instance.setNumber.as_transaction(123, sender=owner)
    actual = chain.provider.estimate_gas_cost(tx)
    assert actual > 0


def test_set_balance(chain, owner):
    balance = owner.balance
    new_balance = balance * 2
    chain.provider.set_balance(owner.address, new_balance)
    assert owner.balance == new_balance


def test_reverts(contract_instance, project, owner, not_owner):
    """
    Integration test with `ape.reverts`.
    """
    with reverts("!authorized") as revert:
        contract_instance.setNumber(55, sender=not_owner)

    # Show we can get the exception and the transaction.
    assert isinstance(revert.value, ContractLogicError)
    failing_tx = revert.value.txn
    assert failing_tx is not None

    # Show it works with Solidity custom exceptions as well.
    sol_contract = project.SolidityContract.deploy(700, sender=owner)
    with reverts(sol_contract.Unauthorized):
        sol_contract.withdraw(sender=not_owner)


def test_trace(contract_instance, owner, not_owner):
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

    # Get a failed receipt's trace.
    failed_tx = contract_instance.setNumber(5, sender=not_owner, raise_on_revert=False)
    assert failed_tx.failed
    failed_trace = failed_tx.trace.revert_message
    assert failed_trace == "!authorized"


def test_impersonate_account(contract, contract_instance, owner, accounts, chain):
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

    # Ensure still works when have made >9 transactions.
    # This is important because it ensures that our made-up hash
    # still works when it is an odd length (handles padding).
    base = 557
    for idx in range(10):
        number = base + idx
        tx = new_contract.setNumber(number, sender=impersonated_account)
        expected = number + 5
        assert tx.return_value == expected

    # Check the return value for a failing receipt.
    failed_tx = contract_instance.setNumber(5, sender=impersonated_account, raise_on_revert=False)
    assert failed_tx.return_value is not None  # Mostly checking it does not fail.

    # Show when we impersonate an account with a leading zero that it still works.
    # (NOTE: There was a bug where the oddness of digits caused hashes to be missing when checking
    #   `.return_value`, so this test is VERY important.
    impersonated_account_2 = accounts["0x0d0707963952f2fba59dd06f2b425ace40b492fe"]
    new_contract = contract.deploy(1, sender=impersonated_account_2)
    tx = new_contract.setNumber(910, sender=impersonated_account_2)
    assert tx.return_value == 915


def test_set_timestamp(chain):
    time_at_start = int(time.time())
    start_ts = chain.blocks.head.timestamp
    new_timestamp = start_ts + 2500
    chain.provider.set_timestamp(new_timestamp)

    def wait_for_time_to_increase(start_time):
        now = int(time.time())
        while now <= start_time:
            now = int(time.time())

    # Show that time is frozen after setting the timestamp.
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


def test_chain_id(chain, networks, run_fork_tests):
    actual = chain.provider.chain_id
    expected = DEFAULT_TEST_CHAIN_ID
    assert actual == expected

    if run_fork_tests:
        with networks.ethereum.holesky_fork.use_provider("boa") as holesky_fork:
            actual = holesky_fork.chain_id
            expected = 17000  # Holesky
            assert actual == expected

        # Show it goes back.
        actual = chain.provider.chain_id
        expected = DEFAULT_TEST_CHAIN_ID
        assert actual == expected


def test_block_identifier(chain, project, networks, run_fork_tests):
    if not run_fork_tests:
        pytest.skip("Fork tests skipped")

    with networks.ethereum.sepolia_fork.use_provider("boa"):
        actual = chain.provider.block_identifier
        expected = 7341111  # From configuration.
        assert actual == expected

        # Test the default.
        with project.temp_config(titanoboa={}):
            assert chain.provider.block_identifier == "safe"


def test_fork(networks, owner, run_fork_tests):
    """
    Show we can integrate nicely with Ape's `networks.fork()` method.
    """
    if not run_fork_tests:
        pytest.skip("Fork tests skipped")

    with networks.ethereum.sepolia.use_provider("alchemy"):
        # When connected to a live network, it is typical to fork it for
        # running simulations.
        with networks.fork():
            polyhedra = Contract("0x465C15e9e2F3837472B0B204e955c5205270CA9E")
            with pytest.raises(ContractLogicError):
                polyhedra.mint(owner.address, 1_000, sender=owner)


def test_get_virtual_machine_error(chain):
    you_messed_up = (
        "0x08c379a000000000000000000000000000000000000000000000000000000000000000"
        "20000000000000000000000000000000000000000000000000000000000000000d796f75"
        "206d657373656420757000000000000000000000000000000000000000"
    )
    revert = Revert(HexBytes(you_messed_up))
    actual = chain.provider.get_virtual_machine_error(revert)
    assert actual.revert_message == "you messed up"


@pytest.mark.parametrize("tx_hash", ("0x123", HexBytes("0x123")))
def test_boa_trace_transaction_hash(tx_hash):
    trace = BoaTrace(transaction_hash=tx_hash)
    assert trace.transaction_hash == "0x0123"


def test_get_contract_logs(chain, contract_instance, owner):
    start_block = chain.blocks.height
    contract_instance.setNumber(321, sender=owner)
    contract_instance.setNumber(321, sender=owner)
    contract_instance.setNumber(321, sender=owner)
    stop_block = chain.blocks.height
    log_filter = LogFilter(
        start_block=start_block,
        stop_block=stop_block,
        addresses=[contract_instance.address],
        events=[contract_instance.NumberChange.abi],
    )
    actual = [log for log in chain.provider.get_contract_logs(log_filter)]
    assert len(actual) == 3

    for log in actual:
        assert log.event_name == "NumberChange"
