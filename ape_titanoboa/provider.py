from functools import cached_property
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Optional

from ape.api.providers import BlockAPI, ProviderAPI
from ape.api.transactions import ReceiptAPI, TransactionAPI
from ape.exceptions import BlockNotFoundError, TransactionNotFoundError
from eth_pydantic_types import HexBytes

if TYPE_CHECKING:
    from ape.types import AddressType, BlockID, ContractCode, ContractLog, LogFilter

    from ape_titanoboa.config import TitanoboaConfig


class TitanoboaProvider(ProviderAPI):
    """
    A provider for Ape using titanoboa as its backend.
    """

    # TODO: Support block ID
    _balances: dict["AddressType", int] = {}
    _contracts: dict["AddressType", "HexBytes"] = {}
    _nonces: dict["AddressType", int] = {}
    _blocks: list[BlockAPI] = []
    _block_hashes: dict[str, int] = {}
    _transactions: dict[str, ReceiptAPI]

    @cached_property
    def boa(self):
        import boa

        return boa

    @property
    def is_connected(self) -> bool:
        return True

    @property
    def config(self) -> "TitanoboaConfig":  # type: ignore
        return super().config  # type: ignore

    @property
    def chain_id(self) -> int:
        return self.config.chain_id

    def connect(self):
        pass

    def disconnect(self):
        pass

    def update_settings(self, new_settings: dict):
        self.provider_settings = new_settings

    def get_balance(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        return self._balances.get(address, 0)

    def get_code(
        self, address: "AddressType", block_id: Optional["BlockID"] = None
    ) -> "ContractCode":
        return self._contracts.get(address, HexBytes(""))

    def make_request(self, rpc: str, parameters: Optional[Iterable] = None) -> Any:
        raise NotImplementedError("TODO")

    def get_nonce(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        return self._nonces.get(address, HexBytes(""))

    def estimate_gas_cost(self, txn: TransactionAPI, block_id: Optional["BlockID"] = None) -> int:
        # TODO
        return 0

    @property
    def gas_price(self) -> int:
        # TODO
        return 0

    @property
    def max_gas(self) -> int:
        # TODO
        return 0

    def get_block(self, block_id: "BlockID") -> BlockAPI:
        if isinstance(block_id, int):
            # By block number.
            try:
                return self._blocks[block_id]
            except KeyError:
                raise BlockNotFoundError(block_id)

        # By hash.
        try:
            block_num = self._block_hashes[block_id]
            return self._blocks[block_num]
        except KeyError:
            raise BlockNotFoundError(block_id)

    def send_call(
        self,
        txn: TransactionAPI,
        block_id: Optional["BlockID"] = None,
        state: Optional[dict] = None,
        **kwargs,
    ) -> "HexBytes":
        pass

    def get_receipt(self, txn_hash: str, **kwargs) -> ReceiptAPI:
        try:
            return self._transactions[txn_hash]
        except KeyError:
            raise TransactionNotFoundError(txn_hash)

    def get_transactions_by_block(self, block_id: "BlockID") -> Iterator[TransactionAPI]:
        # TODO
        yield from []

    def send_transaction(self, txn: TransactionAPI) -> ReceiptAPI:
        pass

    def get_contract_logs(self, log_filter: "LogFilter") -> Iterator["ContractLog"]:
        # TODO
        yield from []
