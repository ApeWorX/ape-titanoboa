import pytest


@pytest.fixture(scope="module", autouse=True)
def sepolia_fork(networks):
    with networks.ethereum.sepolia_fork.use_provider("boa") as fork_provider:
        yield fork_provider


def test_get_latest_block(chain):
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
