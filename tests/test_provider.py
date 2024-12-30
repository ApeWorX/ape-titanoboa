import pytest
from ape import reverts
from ape_ethereum.ecosystem import Block
from eth_utils import to_hex


@pytest.fixture(scope="module", autouse=True)
def sepolia_fork(networks):
    with networks.ethereum.local.use_provider("boa") as fork_provider:
        yield fork_provider


def test_is_connected(chain):
    assert chain.provider.is_connected


def test_deploy_contract(contract, owner):
    instance = contract.deploy(123, sender=owner)
    assert instance.address is not None
    assert instance.contract_type is not None


def test_send_transaction(contract_instance, owner):
    tx = contract_instance.setNumber(321, sender=owner)
    assert not tx.failed

    # Show that state has changed.
    assert contract_instance.myNumber() == 321


def test_send_call(contract_instance, owner):
    result = contract_instance.myNumber()
    assert result == 123


def test_get_receipt(contract_instance, owner, chain):
    tx = contract_instance.setNumber(321, sender=owner)
    tx_hash = tx.txn_hash

    actual = chain.provider.get_receipt(tx_hash)
    assert actual.txn_hash == tx.txn_hash


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


@pytest.mark.parametrize("block_id", ("latest", "earliest", "pending", 0))
def test_get_block(chain, block_id):
    actual = chain.provider.get_block(block_id)
    repr(actual)
    assert isinstance(actual, Block)


def test_get_transactions_by_block(contract_instance, owner, chain):
    tx = contract_instance.setNumber(321, sender=owner)
    actual = list(chain.provider.get_transactions_by_block(chain.blocks.height))
    assert len(actual) >= 1
    # NOTE: Fails on `ape-foundry` because of https://github.com/ApeWorX/ape/issues/2438
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
    assert chain.blocks.height == height  # Didn't ++.
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

    # We should come back to the initial state when restoring.
    snapshot = chain.snapshot()

    # Wreck state.
    chain.mine(5)
    owner.transfer(accounts[1], 1)
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


def test_reverts(contract_instance, accounts):
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
    # `ReceiptAPI.return_value` test.
    tx = contract_instance.setNumber(456, sender=owner)
    actual_retval = tx.return_value
    expected_retval = 461  # 456 + 5 (see smart-contract)
    assert actual_retval == expected_retval
