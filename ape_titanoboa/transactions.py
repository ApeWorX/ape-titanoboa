from typing import TYPE_CHECKING, Any, Optional

from ape_ethereum.transactions import DynamicFeeTransaction, Receipt
from eth.exceptions import Revert

if TYPE_CHECKING:
    from eth_pydantic_types import HexBytes


class BoaReceipt(Receipt):
    """
    A receipt that includes the computation.
    """

    computation: Any
    revert: Optional[Revert] = None


class BoaTransaction(DynamicFeeTransaction):
    """
    A receipt that includes the computation.
    """

    def __init__(self, **kwargs):
        txn_hash = kwargs.pop("txn_hash")
        super().__init__(**kwargs)
        self._txn_hash = txn_hash

    @property
    def txn_hash(self) -> "HexBytes":
        # NOTE: we know this is bytes. type-ignore for performance.
        return self._txn_hash  # type: ignore
