from functools import cached_property
from typing import Any, Iterator, Optional

from ape_ethereum.trace import TransactionTrace
from evm_trace import CallTreeNode
from hexbytes import HexBytes


class BoaTrace(TransactionTrace):
    """
    An execution trace from titanoboa.
    """

    @property
    def computation(self) -> Any:
        return self.transaction["computation"]

    @property
    def transaction(self) -> dict:
        return self.provider._canonical_transactions[self.transaction_hash]

    @cached_property
    def return_value(self) -> Any:
        abi = self.root_method_abi
        output = HexBytes(self.computation.output)
        return self.provider.network.ecosystem.decode_returndata(abi, output)

    @cached_property
    def revert_message(self) -> Optional[str]:
        if revert := self.transaction.get("revert"):
            vm_err = self.provider.get_virtual_machine_error(revert)
            return vm_err.revert_message

        return None

    def get_raw_frames(self) -> Iterator[dict]:
        yield from []

    def get_raw_calltree(self) -> dict:
        return self.computation["call_trace"]

    def get_calltree(self) -> CallTreeNode:
        data = self.computation.call_trace.to_dict()
        data["call_type"] = "CALL"
        return CallTreeNode.model_validate(data)
