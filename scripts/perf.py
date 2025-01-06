from time import perf_counter

from ape import accounts, chain, project
from ape.cli import ConnectedProviderCommand
from click import command, echo, option


@command(cls=ConnectedProviderCommand)
@option("--transaction-iterations", help="The number of transactions to make", default=500)
def cli(transaction_iterations):
    """
    Performance check, useful for comparisons.
    """
    echo(f"Performance check: {chain.provider.name}")
    start = perf_counter()
    owner = accounts.test_accounts[0]
    contract = project.VyperContract.deploy(123, sender=owner)

    for idx in range(transaction_iterations):
        number = contract.myNumber()
        contract.setNumber(number + 1, sender=owner)

    finish = perf_counter()
    elapsed = finish - start
    seconds = int(elapsed)
    milliseconds = int((elapsed - seconds) * 1000)
    echo(f"Time: {seconds} seconds {milliseconds} milliseconds")
