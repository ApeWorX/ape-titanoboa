def test_is_connected(boa_provider):
    assert boa_provider.is_connected


def test_deploy_contract(contract, owner):
    instance = contract.deploy(123, sender=owner)
    assert instance.address is not None
    assert instance.contract_type is not None


def test_transaction(contract, owner):
    instance = contract.deploy(123, sender=owner)
    tx = instance.setNumber(321, sender=owner)
    assert not tx.failed


def test_call(contract, owner):
    instance = contract.deploy(123, sender=owner)
    result = instance.myNumber()
    assert result == 123


def test_get_receipt(contract, owner, boa_provider):
    instance = contract.deploy(123, sender=owner)
    tx = instance.setNumber(321, sender=owner)
    tx_hash = tx.txn_hash

    actual = boa_provider.get_receipt(tx_hash)
    assert actual.txn_hash == tx.txn_hash


def test_get_nonce(owner, contract):
    start_nonce = owner.nonce
    assert isinstance(start_nonce, int)

    # Deploy (transact)
    contract.deploy(123, sender=owner)

    assert owner.nonce == start_nonce + 1
