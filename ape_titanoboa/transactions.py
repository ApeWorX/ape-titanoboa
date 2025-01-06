from typing import TYPE_CHECKING

from ape_ethereum.transactions import DynamicFeeTransaction, Receipt

if TYPE_CHECKING:
    from eth_pydantic_types import HexBytes


class BoaReceipt(Receipt):
    """
    A receipt that includes the computation.
    """

    def __init__(self, **kwargs):
        computation = kwargs.pop("computation")
        revert = kwargs.pop("revert")
        super().__init__(**kwargs)
        self._computation = computation
        self._revert = revert

    @property
    def computation(self):
        return self._computation

    @property
    def revert(self):
        return self._revert


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
