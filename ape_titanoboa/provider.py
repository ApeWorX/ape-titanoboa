import time
from functools import cached_property
from typing import TYPE_CHECKING, Any, ClassVar, Iterable, Iterator, Optional

from ape.api.providers import BlockAPI, TestProviderAPI
from ape.api.transactions import ReceiptAPI, TransactionAPI
from ape.exceptions import (
    ContractLogicError,
    ProviderError,
    TransactionNotFoundError,
    VirtualMachineError,
)
from ape_ethereum.transactions import TransactionStatusEnum
from eth.exceptions import Revert
from eth_pydantic_types import HexBytes

from ape_titanoboa.utils import convert_boa_log

if TYPE_CHECKING:
    from ape.types import AddressType, BlockID, ContractCode, ContractLog, LogFilter, SnapshotID
    from ape_test.config import ApeTestConfig
    from boa.environment import Env  # type: ignore

    from ape_titanoboa.config import TitanoboaConfig


class TitanoboaProvider(TestProviderAPI):
    """
    A provider for Ape using titanoboa as its backend.
    """

    NAME: ClassVar[str] = "boa"

    _auto_mine: bool = True
    _nonces: dict["AddressType", int] = {}
    _pending_block: dict = {}
    _transactions: dict[str, ReceiptAPI] = {}

    @cached_property
    def env(self) -> "Env":
        from boa import env  # type: ignore

        env.evm.patch.chain_id = self.config.chain_id
        return env

    @property
    def is_connected(self) -> bool:
        return "env" in self.__dict__

    @property
    def config(self) -> "TitanoboaConfig":  # type: ignore
        return self.config_manager.get_config("titanoboa")

    @property
    def apetest_config(self) -> "ApeTestConfig":
        return self.config_manager.get_config("test")

    @property
    def chain_id(self) -> int:
        return self.env.evm.patch.chain_id

    @property
    def auto_mine(self) -> bool:
        return self._auto_mine

    @auto_mine.setter
    def auto_mine(self, value):
        self._auto_mine = value

    def connect(self):
        _ = self.env
        self._generate_chain()

    def disconnect(self):
        self.__dict__.pop("env", None)

    def _generate_chain(self):
        self._generate_accounts()

    def _generate_accounts(self):
        balance = self.apetest_config.balance
        map(lambda a: self.env.set_balance(a, balance), self.account_manager.test_accounts)

    def update_settings(self, new_settings: dict):
        self.provider_settings = new_settings

    def get_balance(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        return self.env.get_balance(address)

    def get_code(
        self, address: "AddressType", block_id: Optional["BlockID"] = None
    ) -> "ContractCode":
        return self.env.get_code(address)

    def make_request(self, rpc: str, parameters: Optional[Iterable] = None) -> Any:
        raise NotImplementedError()

    def get_nonce(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        return self._nonces.get(address, 0)

    def estimate_gas_cost(self, txn: TransactionAPI, block_id: Optional["BlockID"] = None) -> int:
        # TODO
        return self.env.evm.chain.estimate_gas(txn)

    @property
    def gas_price(self) -> int:
        return self.env.get_gas_price()

    @property
    def max_gas(self) -> int:
        return self.env.evm.get_gas_limit()

    def get_block(self, block_id: "BlockID") -> BlockAPI:
        if block_id == "latest":
            header = self.env.evm.chain.get_canonical_head()
        elif block_id == "earliest":
            header = self.env.evm.chain.get_canonical_block_by_number(0).header
        elif block_id == "pending":
            header = self.env.evm.chain.get_block().header
        elif isinstance(block_id, int):
            header = self.env.evm.chain.get_canonical_block_by_number(block_id).header
        else:
            header = self.env.evm.chain.get_block_by_hash(block_id).header

        return self.network.ecosystem.decode_block(
            {
                "gasLimit": header.gas_limit,
                "gasUsed": header.gas_used,
                "hash": header.hash,
                "number": header.block_number,
                "parentHash": header.parent_hash,
                "timestamp": header.timestamp,
            }
        )

    def send_call(
        self,
        txn: TransactionAPI,
        block_id: Optional["BlockID"] = None,
        state: Optional[dict] = None,
        **kwargs,
    ) -> "HexBytes":
        if not txn.receiver:
            raise ProviderError("Missing receiver.")

        computation = self.env.execute_code(
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
        txn.gas_limit = self.env.evm.get_gas_limit()
        txn.chain_id = self.chain_id
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
            computation = self.env.execute_code(
                data=txn.data,
                gas=txn.gas_limit,
                sender=txn.sender,
                to_address=txn.receiver,
                value=txn.value,
            )

        else:
            # Deploy.
            contract_address, computation = self.env.deploy(
                bytecode=txn.data,
                gas=txn.gas_limit,
                sender=txn.sender,
                value=txn.value,
            )

        try:
            computation.raise_if_error()
        except Revert as err:
            raise self.get_virtual_machine_error(err) from err

        new_block_number = self.env.evm.chain.get_block().header.block_number
        gas_used = computation.get_gas_used()

        # Advance block.
        block_data: dict = {
            "block_number": new_block_number,
            "timestamp": self.env.evm.patch.timestamp,
        }
        if self._auto_mine:
            block_data["gas_used"] = gas_used
            block_data["gas_limit"] = txn.gas_limit
            header = self.env.evm.vm.get_header()
            new_block = self.env.evm.vm.get_block_class()(header)
            self.env.evm.chain.persist_block(new_block)
        else:
            self._pending_block = block_data

        logs: list[dict] = [
            convert_boa_log(
                log,
                blockNumber=new_block_number,
                transactionHash=txn.txn_hash,
                transactionIndex=tx_idx,
            )
            for tx_idx, log in enumerate(computation._log_entries)
        ]
        data = {
            "block_number": new_block_number,
            "contract_address": next(iter(computation.contracts_created), None),
            "logs": logs,
            "status": TransactionStatusEnum.NO_ERROR,
            "txn_hash": txn.txn_hash,
        }
        receipt = self.network.ecosystem.decode_receipt(data)
        self._transactions[receipt.txn_hash] = receipt

        # Bump sender's nonce.
        self._nonces[txn.sender] = self._nonces.get(txn.sender, 0) + 1

        return receipt

    def get_contract_logs(self, log_filter: "LogFilter") -> Iterator["ContractLog"]:
        yield from []

    def snapshot(self) -> "SnapshotID":
        return self.env.evm.chain.get_canonical_head().hash

    def restore(self, snapshot_id: "SnapshotID"):
        raise NotImplementedError("TODO")

    def set_timestamp(self, new_timestamp: int):
        seconds = new_timestamp - self.env.evm.chain.get_canonical_head().timestamp
        self.env.time_travel(seconds=seconds, blocks=0)

    def mine(self, num_blocks: int = 1):
        self.env.evm.chain.mine_block()

    def get_virtual_machine_error(self, exception: Exception, **kwargs) -> VirtualMachineError:
        if isinstance(exception, Revert):
            raise ContractLogicError(revert_message=exception.args[0])

        return VirtualMachineError()
