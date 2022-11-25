import boa  # type: ignore
import pytest
from ape.utils import cached_property


def pytest_collect_file(file_path, parent):
    if file_path.name.endswith(".t.vy") and file_path.name.startswith("test_"):
        return BoaFile.from_parent(path=file_path, parent=parent)


class BoaFile(pytest.File):
    def collect(self):
        self.contract_deployer = boa.load_partial(self.path)
        for name in sorted(self.contract_deployer.compiler_data.function_signatures.keys()):
            if name.startswith("test"):
                yield BoaItem.from_parent(name=name, parent=self)


class BoaItem(pytest.Item):
    @cached_property
    def contract(self):
        return self.parent.contract_deployer.deploy()

    def runtest(self):
        getattr(self.contract, self.name)()

    def repr_failure(self, excinfo):
        """Called when self.runtest() raises an exception."""
        if isinstance(excinfo.value, boa.BoaError):
            return str(excinfo.value.stack_trace)

        raise excinfo.value

    def reportinfo(self):
        return self.path, 0, f"{self.parent.name}::{self.name}"
