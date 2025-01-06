#!/usr/bin/env python
import cProfile
import io
import pstats
import sys
from time import perf_counter

from ape import accounts, chain, project
from ape.cli import ConnectedProviderCommand
from click import command, echo, option


@command(cls=ConnectedProviderCommand)
@option("--transaction-iterations", help="The number of transactions to make", default=500)
@option(
    "--profile", is_flag=True, callback=lambda ctx, param, val: cProfile.Profile() if val else None
)
def cli(transaction_iterations, profile):
    """
    Performance check, useful for comparisons.
    """
    echo(f"Performance check: {chain.provider.name}")

    if profile:
        profile.enable()

    start = perf_counter()
    owner = accounts.test_accounts[0]
    contract = project.VyperContract.deploy(123, sender=owner)

    for idx in range(transaction_iterations):
        number = contract.myNumber()
        contract.setNumber(number + 1, sender=owner)

    if profile:
        profile.disable()
        s = io.StringIO()
        ps = pstats.Stats(profile, stream=s).sort_stats("time")
        ps.print_stats()
        echo(s.getvalue().rstrip())

    finish = perf_counter()
    elapsed = finish - start
    seconds = int(elapsed)
    milliseconds = int((elapsed - seconds) * 1000)
    echo(f"Time: {seconds} seconds {milliseconds} milliseconds")


if __name__ == "__main__":
    cli(sys.argv[1:])
