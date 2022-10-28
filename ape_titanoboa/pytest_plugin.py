import boa  # type: ignore
import pytest


def pytest_collect_file(file_path, parent):
    if file_path.name.endswith(".t.vy") and file_path.name.startswith("test_"):
        return BoaFile.from_parent(path=file_path, parent=parent)


class BoaFile(pytest.File):
    def collect(self):
        self.contract = boa.load(self.path)
        for name in sorted(self.contract._sigs["self"].keys()):
            if name.startswith("test"):
                yield BoaItem.from_parent(name=name, parent=self)


class BoaItem(pytest.Item):
    def runtest(self):
        getattr(self.parent.contract, self.name)()

    def repr_failure(self, excinfo):
        """Called when self.runtest() raises an exception."""
        if isinstance(excinfo.value, boa.BoaError):
            return str(excinfo.value.stack_trace)

        raise excinfo.value

    def reportinfo(self):
        return self.path, 0, f"{self.parent.name}::{self.name}"
