import pytest


@pytest.fixture(scope="module", autouse=True)
def sepolia_fork(networks):
    with networks.ethereum.sepolia_fork.use_provider("boa") as fork_provider:
        yield fork_provider


def test_chain_height(chain):
    """
    Since we are using the fork provider, our chain HEAD should be
    heightened.
    """
    expected = 7341111  # From configuration.
    actual = chain.blocks.height
    assert actual == expected

    # NOTE: It is very important the timestamp is accurate
    #   for any on-chain state that requires it.
    assert chain.blocks.head.timestamp == 1734992352


def test_get_block(chain):
    block = chain.provider.get_block("latest")
    assert block.number == 7341111  # From configuration.

    # Mine.
    chain.provider.mine(5)
    block = chain.provider.get_block("latest")
    assert block.number == 7341116
    block = chain.provider.get_block(7341116)
    assert block.number == 7341116

    # Historical block.
    block = chain.provider.get_block(3)
    assert block.timestamp == 1634951317


def test_block_identifier(chain, project):
    actual = chain.provider.block_identifier
    expected = 7341111  # From configuration.
    assert actual == expected

    # Test the default.
    with project.temp_config(titanoboa={}):
        assert chain.provider.block_identifier == "safe"


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

    # Get a historical receipt.
    txn_hash = "0x68605140856c13038d325048c411aed98cc1eecc189f628a38edb597f6b9679e"
    receipt = chain.provider.get_receipt(txn_hash)
    assert receipt.txn_hash == txn_hash
