def test_is_connected(boa_provider):
    assert boa_provider.is_connected


def test_deploy_contract(contract, owner):
    instance = contract.deploy(sender=owner)
    assert instance.address is not None
    assert instance.contract_type is not None


def test_transaction(contract, owner):
    instance = contract.deploy(sender=owner)
    tx = instance.test_external_method(sender=owner)
    assert not tx.failed


# TODO
# def test_call(contract, owner):
#     instance = contract.deploy(sender=owner)
#     result = instance.test_view_method()
#     assert result


def test_get_receipt(contract, owner, boa_provider):
    instance = contract.deploy(sender=owner)
    tx = instance.test_external_method(sender=owner)
    tx_hash = tx.txn_hash

    actual = boa_provider.get_receipt(tx_hash)
    assert actual == tx


def test_get_nonce(owner, contract):
    start_nonce = owner.nonce
    assert isinstance(start_nonce, int)

    # Deploy (transact)
    contract.deploy(sender=owner)

    assert owner.nonce == start_nonce + 1
