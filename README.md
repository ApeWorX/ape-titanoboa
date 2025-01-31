# Quick Start

Use Titanoboa as a provider in Ape.

## Dependencies

* [python3](https://www.python.org/downloads) version 3.9 or greater, python3-dev

## Installation

### via `pip`

You can install the latest release via [`pip`](https://pypi.org/project/pip/):

```bash
pip install ape-titanoboa
```

### via `setuptools`

You can clone the repository and use [`setuptools`](https://github.com/pypa/setuptools) for the most up-to-date version:

```bash
git clone https://github.com/ApeWorX/ape-titanoboa.git
cd ape-titanoboa
python3 setup.py install
```

## Quick Usage

Use titanoboa as your development or simulation provider (testing).
For example, run your project's tests using the `--network` flag and `boa` as the name of the provider:

```shell
ape test --network ethereum:local:boa
```

Boa works the same as other Ape testing providers such as `ape-foundry` or the Ethereum tester that comes with `ape-test` by default.

### Fast Mode

To enable Titanoboa's fast mode automatically, configure the plugin with `fast_mode: True`:

```yaml
titanoboa:
  fast_mode: True
```

### Fork Mode

You can for networks using `ape-titanoba` to simulate actions.
For example, let's say you are in a console session with mainnet:

```shell
ape console --network ethereum:mainnet:alchemy
```

Fork mainnet into `boa` to run simulations:

```python
from ape import Contract, accounts, networks

with networks.fork():
    # Reference a contract from Ethereum mainnet in your fork.
    contract = Contract("0x388C818CA8B9251b393131C08a736A67ccB19297")
    # Impersonate any relevant accounts needed for the simulation.
    owner = accounts["0xdb65702a9b26f8a643a31a4c84b9392589e03d7c"]
    # Attempt to call methods on the contract using the impersonated accounts.
    contract.recoverERC20("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", 10, sender=owner)
```

You can also connect to a forked-network directly using the `--network` flag:

```shell
ape console --network ethereum:mainnet-fork:boa
```

Or in Python:

```python
from ape import chain, networks

with networks.ethereum.mainnet_fork.use_provider("boa"):
    print(chain.provider.chain_id)
```

## Development

This project is in development and should be considered a beta.
Things might not be in their final state and breaking changes may occur.
Comments, questions, criticisms and pull requests are welcomed.
