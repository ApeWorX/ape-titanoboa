from typing import TYPE_CHECKING

import pytest
from ape.utils import ManagerAccessMixin, cached_property
from eth_utils import keccak, to_checksum_address

if TYPE_CHECKING:
    from ape.contracts import ContractInstance
    from ape.types import AddressType
    from ethpm_types import ContractType


def pytest_collect_file(parent, file_path):
    # NOTE: Do not use greedy `.suffix`, use full extension
    if file_path.name.startswith("test") and file_path.name.endswith(".t.vy"):
        return VyperTest.from_parent(parent, path=file_path)


class VyperTest(pytest.File, ManagerAccessMixin):
    @cached_property
    def TEST_CASE_ADDRESS(self) -> "AddressType":
        # NOTE: Compute a unique address per test case module to inject into Boa env
        return to_checksum_address(keccak(text=self.path.name)[:20])

    @cached_property
    def contract_type(self) -> "ContractType":
        vyper = self.compiler_manager.registered_compilers[".vy"]
        # TODO: Inject `ape.project` under `project` module?
        # TODO: Inject other Ape features as pre-compiles under `ape` module?
        #       `c: project.MyContract = ape.deploy("project.MyContract", ...)`
        return next(vyper.compile([self.path]))

    def collect(self):
        # NOTE: Only `mutable` methods can be valid test cases
        all_method_names = map(lambda abi: abi.name, self.contract_type.mutable_methods)

        for name in sorted(all_method_names):
            if name.startswith("test"):
                yield TestCase.from_parent(parent=self, name=name)


class BaseTestCase(ManagerAccessMixin):
    # NOTE: Needed to work with ape's fixture detection
    fixturenames = set("_function_isolation")

    @cached_property
    def contract(self) -> "ContractInstance":
        assert isinstance(self.parent, VyperTest)  # make mypy happy
        # NOTE: Injecting code is much faster than deploying it
        self.provider.env.set_code(
            self.parent.TEST_CASE_ADDRESS,
            bytes.fromhex(self.parent.contract_type.runtime_bytecode.bytecode[2:]),
        )
        return self.chain_manager.contracts.instance_at(
            self.parent.TEST_CASE_ADDRESS,
            contract_type=self.parent.contract_type,
        )


class TestCase(pytest.Item, BaseTestCase):
    def runtest(self):
        method = getattr(self.contract, self.name)
        # TODO: `.call` w/ injected contract "fixtures"?
        #       e.g. `def foo(c: project.MyContract, ...)` will inject instance of
        #       `project.MyContract` and call `method` w/ it (check `ABIType.internalType`)

        # TODO: `.call` w/ fuzzed args if args present
        # TODO: Add strategy adaption w/ custom NatSpec
        #       (`@custom:strategy <arg-name> <package>[.<mod>]:<strategy-name>`)
        with self.chain_manager.isolate():
            method.call()


# TODO: StatefulTestCase (setup stateful test w/ invariants and rules)
