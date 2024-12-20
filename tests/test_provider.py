import pytest
from ape_ethereum.ecosystem import Block


def test_is_connected(chain):
    assert chain.provider.is_connected


def test_deploy_contract(contract, owner):
    instance = contract.deploy(123, sender=owner)
    assert instance.address is not None
    assert instance.contract_type is not None


def test_send_transaction(contract, owner):
    instance = contract.deploy(123, sender=owner)
    tx = instance.setNumber(321, sender=owner)
    assert not tx.failed

    # Show that state has changed.
    assert instance.myNumber() == 321


def test_send_call(contract, owner):
    instance = contract.deploy(123, sender=owner)
    result = instance.myNumber()
    assert result == 123


def test_get_receipt(contract, owner, chain):
    instance = contract.deploy(123, sender=owner)
    tx = instance.setNumber(321, sender=owner)
    tx_hash = tx.txn_hash

    actual = chain.provider.get_receipt(tx_hash)
    assert actual.txn_hash == tx.txn_hash


def test_get_nonce(owner, contract):
    start_nonce = owner.nonce
    assert isinstance(start_nonce, int)

    # Deploy (transact)
    contract.deploy(123, sender=owner)

    assert owner.nonce == start_nonce + 1


def test_tx_events(owner, contract):
    instance = contract.deploy(123, sender=owner)
    tx = instance.setNumber(321, sender=owner)
    actual = tx.events
    assert len(actual) == 1
    assert actual[0].prevNum == 123
    assert actual[0].newNum == 321


@pytest.mark.parametrize("block_id", ("latest", "earliest", "pending", 0))
def test_get_block(chain, block_id):
    actual = chain.provider.get_block(block_id)
    repr(actual)
    assert isinstance(actual, Block)
