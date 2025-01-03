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

    block = chain.provider.get_block(3)
    assert block.timestamp == 1634951317


def test_block_identifier(chain):
    actual = chain.provider.block_identifier
    expected = 7341111  # From configuration.
    assert actual == expected
