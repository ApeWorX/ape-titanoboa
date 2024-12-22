import pytest
from ape_ethereum.ecosystem import Block


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
    assert len(actual) == 1
    assert actual[0] == tx.transaction


def test_auto_mine(chain, owner):
    assert chain.provider.auto_mine
    chain.provider.auto_mine = False
    assert not chain.provider.auto_mine
    chain.provider.auto_mine = True

    # Show auto-mine works.
    start_num = chain.blocks.height
    owner.transfer(123, owner)
    assert chain.blocks.height == start_num + 1

    # Show manual-mine also works.
    start_num = chain.blocks.height
    owner.transfer(123, owner)
    assert chain.blocks.height == start_num
    chain.mine()
    assert chain.blocks.height == start_num + 1
