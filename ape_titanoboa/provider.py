import time
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Optional

from ape.api.providers import BlockAPI, TestProviderAPI
from ape.api.transactions import ReceiptAPI, TransactionAPI
from ape.exceptions import (
    BlockNotFoundError,
    ContractLogicError,
    ProviderError,
    TransactionNotFoundError,
    VirtualMachineError,
)
from ape_ethereum.transactions import TransactionStatusEnum
from boa import env  # type: ignore
from eth.exceptions import Revert
from hexbytes import HexBytes

if TYPE_CHECKING:
    from ape.types import AddressType, BlockID, ContractCode, ContractLog, LogFilter, SnapshotID
    from ape_test.config import ApeTestConfig

    from ape_titanoboa.config import TitanoboaConfig


class TitanoboaProvider(TestProviderAPI):
    """
    A provider for Ape using titanoboa as its backend.
    """

    _nonces: dict["AddressType", int] = {}
    _blocks: list[BlockAPI] = []
    _block_hashes: dict[str, int] = {}
    _transactions: dict[str, ReceiptAPI] = {}
    _timestamp: Optional[int] = None
    _auto_mine: bool = False

    @property
    def current_timestamp(self) -> int:
        if self._timestamp is not None:
            return self._timestamp

        return int(time.time())

    @property
    def is_connected(self) -> bool:
        # true when there is a genesis block.
        return len(self._blocks) > 0

    @property
    def config(self) -> "TitanoboaConfig":  # type: ignore
        return super().config  # type: ignore

    @property
    def apetest_config(self) -> "ApeTestConfig":
        return self.config_manager.get_config("test")

    @property
    def chain_id(self) -> int:
        return self.config.chain_id

    @property
    def auto_mine(self) -> bool:
        return self._auto_mine

    @auto_mine.setter
    def auto_mine(self, value):
        self._auto_mine = value

    def connect(self):
        self._generate_chain()

    def disconnect(self):
        self._blocks = []

    def _generate_chain(self):
        self._generate_block_zero()
        self._generate_accounts()

    def _generate_block_zero(self):
        data = {"timestamp": self.current_timestamp, "gasLimit": 0, "gasUsed": 0, "number": 0}
        block = self.network.ecosystem.decode_block(data)
        self._blocks = [block]

    def _generate_accounts(self):
        balance = self.apetest_config.balance
        map(lambda a: env.set_balance(a, balance), self.account_manager.test_accounts)

    def update_settings(self, new_settings: dict):
        self.provider_settings = new_settings

    def get_balance(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        return env.get_balance(address)

    def get_code(
        self, address: "AddressType", block_id: Optional["BlockID"] = None
    ) -> "ContractCode":
        return env.get_code(address)

    def make_request(self, rpc: str, parameters: Optional[Iterable] = None) -> Any:
        raise NotImplementedError()

    def get_nonce(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        return self._nonces.get(address, 0)

    def estimate_gas_cost(self, txn: TransactionAPI, block_id: Optional["BlockID"] = None) -> int:
        # TODO
        env.execute_code()
        return 0

    @property
    def gas_price(self) -> int:
        return env.get_gas_price()

    @property
    def max_gas(self) -> int:
        return env.evm.get_gas_limit()

    def get_block(self, block_id: "BlockID") -> BlockAPI:
        if block_id == "latest":
            return self._blocks[-1]

        elif block_id == "earliest":
            return self._blocks[-1]

        elif block_id == "pending":
            raise NotImplementedError("TODO!")

        elif isinstance(block_id, int):
            # By block number.
            try:
                return self._blocks[block_id]
            except IndexError:
                raise BlockNotFoundError(block_id)

        # By hash.
        try:
            block_num = self._block_hashes[block_id]
            return self._blocks[block_num]
        except IndexError:
            raise BlockNotFoundError(block_id)

    def send_call(
        self,
        txn: TransactionAPI,
        block_id: Optional["BlockID"] = None,
        state: Optional[dict] = None,
        **kwargs,
    ) -> "HexBytes":
        if not txn.receiver:
            raise ProviderError("Missing receiver.")

        computation = env.execute_code(
            data=txn.data,
            gas=txn.gas_limit,
            is_modifying=False,
            to_address=txn.receiver,
        )

        try:
            computation.raise_if_error()
        except Revert as err:
            raise self.get_virtual_machine_error(err) from err

        return HexBytes(computation.output)

    def get_receipt(self, txn_hash: str, **kwargs) -> ReceiptAPI:
        try:
            return self._transactions[txn_hash]
        except KeyError:
            raise TransactionNotFoundError(txn_hash)

    def get_transactions_by_block(self, block_id: "BlockID") -> Iterator[TransactionAPI]:
        # TODO
        yield from []

    def prepare_transaction(self, txn: TransactionAPI) -> TransactionAPI:
        txn.max_fee = 0
        txn.max_priority_fee = 0
        txn.gas_limit = env.evm.get_gas_limit()
        if sender := txn.sender:
            txn.nonce = self._nonces.get(sender, 0)

        return txn

    def send_transaction(self, txn: TransactionAPI) -> ReceiptAPI:
        sender_nonce = self._nonces.get(txn.sender, 0)
        tx_nonce = txn.nonce
        if tx_nonce is None or tx_nonce < sender_nonce:
            raise ProviderError(f"Invalid nonce '{tx_nonce}'.")

        else:
            # TODO: Improve this...
            while sender_nonce > tx_nonce:
                time.sleep(1)
                sender_nonce = self._nonces.get(txn.sender, 0)

        # Process tx data.
        if txn.receiver:
            # Method call.
            computation = env.execute_code(
                data=txn.data,
                gas=txn.gas_limit,
                sender=txn.sender,
                to_address=txn.receiver,
                value=txn.value,
            )

        else:
            # Deploy.
            contract_address, computation = env.deploy(
                bytecode=txn.data,
                gas=txn.gas_limit,
                sender=txn.sender,
                value=txn.value,
            )

        try:
            computation.raise_if_error()
        except Revert as err:
            raise self.get_virtual_machine_error(err) from err

        new_block_number = (self._blocks[-1].number or 0) + 1
        data = {
            "block_number": new_block_number,
            "contract_address": next(iter(computation.contracts_created), None),
            "status": TransactionStatusEnum.NO_ERROR,
            "txn_hash": txn.txn_hash,
        }
        receipt = self.network.ecosystem.decode_receipt(data)

        # Advance block.
        if self._auto_mine:
            block_data = {
                "gasUsed": computation.get_gas_used(),
                "gasLimit": txn.gas_limit,
                "number": new_block_number,
                "timestamp": self.current_timestamp,
            }
            new_block = self.network.ecosystem.decode_block(block_data)
            self._blocks.append(new_block)

        # TODO: Queue up block tx data so when mine is called, it gets included.

        # Cache so can lookup later.
        self._transactions[receipt.txn_hash] = receipt

        # Bump sender's nonce.
        self._nonces[txn.sender] = self._nonces.get(txn.sender, 0) + 1

        return receipt

    def get_contract_logs(self, log_filter: "LogFilter") -> Iterator["ContractLog"]:
        yield from []

    def snapshot(self) -> "SnapshotID":
        return len(self._blocks) - 1  # Latest block number.

    def restore(self, snapshot_id: "SnapshotID"):
        block_number = int(snapshot_id)
        if block_number > len(self._blocks) - 1:
            raise ProviderError("snapshot_id (block_number) cannot exceed block HEAD.")

        self._blocks = self._blocks[:2]
        self._transactions = {
            tx_hash: tx
            for tx_hash, tx in self._transactions.items()
            if tx.block_number <= block_number
        }
        # TODO: Undo state in ENV.

    def set_timestamp(self, new_timestamp: int):
        self._timestamp = new_timestamp

    def mine(self, num_blocks: int = 1):
        block_num = len(self._blocks)
        for _ in range(num_blocks):
            data = {
                "timestamp": self.current_timestamp,
                "gasLimit": 0,
                "gasUsed": 0,
                "number": block_num,
            }
            block = self.network.ecosystem.decode_block(data)
            self._blocks.append(block)
            block_num += 1

    def get_virtual_machine_error(self, exception: Exception, **kwargs) -> VirtualMachineError:
        if isinstance(exception, Revert):
            raise ContractLogicError(revert_message=exception.args[0])

        return VirtualMachineError()
