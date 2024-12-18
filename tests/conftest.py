import pytest


@pytest.fixture(scope="session")
def contract(project):
    return project.VyperContract


@pytest.fixture(scope="session")
def owner(accounts):
    return accounts[0]
