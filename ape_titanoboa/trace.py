from functools import cached_property
from typing import Any, Iterator, Optional

from ape_ethereum.trace import TransactionTrace
from hexbytes import HexBytes


class BoaTrace(TransactionTrace):
    """
    An execution trace from titanoboa.
    """

    @property
    def computation(self) -> Any:
        return self.provider._canonical_transactions[self.transaction_hash]["computation"]

    @cached_property
    def return_value(self) -> Any:
        abi = self.root_method_abi
        output = HexBytes(self.computation.output)
        return self.provider.network.ecosystem.decode_returndata(abi, output)

    @cached_property
    def revert_message(self) -> Optional[str]:
        return None

    def get_raw_frames(self) -> Iterator[dict]:
        yield from []

    def get_raw_calltree(self) -> dict:
        return {}
