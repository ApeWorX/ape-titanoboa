import pytest


@pytest.fixture(scope="session", autouse=True)
def boa_provider(networks):
    with networks.ethereum.local.use_provider("titanoboa") as boa_provider:
        yield boa_provider
