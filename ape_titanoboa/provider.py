import re
import time
from copy import copy
from functools import cached_property
from types import ModuleType
from typing import TYPE_CHECKING, Any, ClassVar, Iterable, Iterator, Optional, Union

from ape.api.providers import BlockAPI, TestProviderAPI
from ape.exceptions import ContractLogicError, ProviderError, VirtualMachineError
from ape_ethereum.transactions import TransactionStatusEnum
from eth.constants import ZERO_ADDRESS
from eth.exceptions import Revert
from eth.vm.spoof import SpoofTransaction
from eth_abi import decode
from eth_pydantic_types import HexBytes
from eth_utils import ValidationError, to_hex

from ape_titanoboa.config import BoaForkConfig
from ape_titanoboa.trace import BoaTrace
from ape_titanoboa.transactions import BoaReceipt, BoaTransaction
from ape_titanoboa.utils import convert_boa_log

if TYPE_CHECKING:
    from ape.api import ForkedNetworkAPI, ReceiptAPI, TestAccountAPI, TraceAPI, TransactionAPI
    from ape.api.networks import ProviderContextManager
    from ape.types import AddressType, BlockID, ContractCode, ContractLog, LogFilter, SnapshotID
    from ape_test.accounts import TestAccount
    from ape_test.config import ApeTestConfig
    from boa.environment import Env  # type: ignore
    from boa.util.open_ctx import Open  # type: ignore
    from eth.abc import BlockAPI as VMBlockAPI

    from ape_titanoboa.config import BoaConfig


class BaseTitanoboaProvider(TestProviderAPI):
    """
    A provider for Ape using titanoboa as its backend.
    """

    NAME: ClassVar[str] = "boa"

    # Flags.
    _auto_mine: bool = True
    _connected: bool = False

    # Account state.
    _accounts: dict[int, "TestAccount"] = {}
    _nonces: dict["AddressType", int] = {}

    # Transaction state.
    _canonical_transactions: dict[str, dict] = {}
    _pending_transactions: dict[str, dict] = {}

    # Snapshot state.
    _snapshot_state: dict["SnapshotID", dict] = {}

    @cached_property
    def boa(self) -> ModuleType:
        # perf: cached property is slightly more performant
        #   than using Python module caching system alone.
        import boa  # type: ignore

        return boa

    @property
    def env(self) -> "Env":
        raise NotImplementedError("Must be implemented by a subclass.")

    @property
    def client_version(self) -> str:
        return "titanoboa"

    @cached_property
    def block_class(self) -> type["VMBlockAPI"]:
        return self.env.evm.vm.get_block_class()

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def config(self) -> "BoaConfig":  # type: ignore
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

    @cached_property
    def mnemonic_seed(self) -> bytes:
        # perf: lazy imports so module loads faster.
        from eth_account.hdaccount.mnemonic import Mnemonic

        return Mnemonic.to_seed(self.apetest_config.mnemonic)

    @cached_property
    def hdpath_format(self) -> str:
        hd_path = self.apetest_config.hd_path
        return hd_path if "{}" in hd_path or "{0}" in hd_path else f"{hd_path.rstrip('/')}/{{}}"

    def connect(self):
        _ = self.env
        self._connected = True

    def disconnect(self):
        self.__dict__.pop("env", None)
        self._connected = False
        self.boa.reset_env()  # type: ignore

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

    def estimate_gas_cost(self, txn: "TransactionAPI", block_id: Optional["BlockID"] = None) -> int:
        receiver_bytes = HexBytes(txn.receiver) if txn.receiver else ZERO_ADDRESS
        evm_tx_data = {
            "data": txn.data,
            "gas": txn.gas,
            "gas_price": 0,
            "nonce": txn.nonce or 0,
            "to": receiver_bytes,
            "value": txn.value,
        }
        evm_tx = self.env.evm.chain.create_unsigned_transaction(**evm_tx_data)
        sender_bytes = HexBytes(txn.sender) if txn.sender else ZERO_ADDRESS
        spoof_tx = SpoofTransaction(evm_tx, from_=sender_bytes)
        try:
            return self.env.evm.chain.estimate_gas(spoof_tx)
        except ValidationError as err:
            # TODO: Figure out why this happens...
            if match := re.match(
                r"Invalid transaction nonce: Expected (\d*), but got \d*", f"{err}"
            ):
                expected = int(match.groups()[0])
                evm_tx_data["nonce"] = expected
                evm_tx = self.env.evm.chain.create_unsigned_transaction(**evm_tx_data)
                spoof_tx = SpoofTransaction(evm_tx, from_=sender_bytes)
                return self.env.evm.chain.estimate_gas(spoof_tx)

            raise  # Raise the error as-is.

    @property
    def gas_price(self) -> int:
        return self.env.get_gas_price()

    @property
    def max_gas(self) -> int:
        return self.env.evm.get_gas_limit()

    def get_block(self, block_id: "BlockID") -> BlockAPI:
        header = (
            self.env.evm.chain.get_block().header
            if block_id == "pending"
            else self.env.evm.chain.get_canonical_head()
        )
        offset = self.boa.env.evm.vm.state.block_number
        return self.network.ecosystem.decode_block(
            {
                "gasLimit": header.gas_limit,
                "gasUsed": header.gas_used,
                "hash": header.hash,
                "number": header.block_number + offset,
                "parentHash": header.parent_hash,
                "timestamp": self.env.evm.patch.timestamp,
            }
        )

    def send_call(
        self,
        txn: "TransactionAPI",
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

    def get_receipt(self, txn_hash: str, **kwargs) -> "ReceiptAPI":
        data = self._canonical_transactions[txn_hash]
        return BoaReceipt(**data)

    def get_transactions_by_block(self, block_id: "BlockID") -> Iterator["TransactionAPI"]:
        if isinstance(block_id, int):
            yield from self._get_transactions_by_block_number(block_id)

        else:
            header = self.env.evm.chain.get_block_by_hash(block_id).header
            yield from self._get_transactions_by_block_number(header.block_number)

    def _get_transactions_by_block_number(self, number: int) -> Iterator["TransactionAPI"]:
        for data in self._canonical_transactions.values():
            if data["block_number"] > number:
                # perf: exit early if we have exceeded the give number.
                return

            # For some reason, transaction API expects bytes.
            data["txn_hash"] = HexBytes(data["txn_hash"])

            yield BoaTransaction(**data)

    def prepare_transaction(self, txn: "TransactionAPI") -> "TransactionAPI":
        txn.max_fee = 0
        txn.max_priority_fee = 0
        txn.gas_limit = self.env.evm.get_gas_limit()
        txn.chain_id = self.chain_id

        if txn.nonce is None and txn.sender:
            txn.nonce = self._nonces.get(txn.sender, 0)

        return txn

    def send_transaction(self, txn: "TransactionAPI") -> "ReceiptAPI":
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

        if txn.signature:
            txn_hash = to_hex(txn.txn_hash)
        else:
            # Impersonated transaction. Make one up using the sender.
            txn_hash = to_hex(int(txn.sender, 16) + txn.nonce)

        new_block_number = self.env.evm.chain.get_block().header.block_number
        logs: list[dict] = [
            convert_boa_log(
                log,
                blockNumber=new_block_number,
                logIndex=log_idx,
                transactionHash=txn_hash,
                transactionIndex=0,
            )
            for log_idx, log in enumerate(computation.get_log_entries())
        ]
        txn_data = txn.model_dump()
        data = {
            "block_number": new_block_number,
            "computation": computation,
            "contract_address": next(iter(computation.contracts_created), None),
            "data": to_hex(txn.data),
            "gas_limit": txn.gas_limit,
            "gas_price": 0,
            "gas_used": computation.get_gas_used(),
            "logs": logs,
            "nonce": txn.nonce,
            "signature": txn.signature,
            "status": TransactionStatusEnum.NO_ERROR,
            "to": txn.receiver,
            "transaction": txn_data,
            "txn_hash": txn_hash,
        }
        receipt = BoaReceipt(**data)

        # Prepare new block/transaction.
        if self._auto_mine:
            self.env.evm.patch.block_number += 1
            self._canonical_transactions[txn_hash] = data
        else:
            # Will become canon once `self.mine()` is called.
            self._pending_transactions[txn_hash] = data

        # Bump sender's nonce.
        self._nonces[txn.sender] = self._nonces.get(txn.sender, 0) + 1

        return receipt

    def get_contract_logs(self, log_filter: "LogFilter") -> Iterator["ContractLog"]:
        yield from []

    def snapshot(self) -> "SnapshotID":
        snapshot = self.env.evm.snapshot()

        self._snapshot_state[snapshot] = {
            "block_number": self.env.evm.patch.block_number,
            "nonces": copy(self._nonces),  # TODO: Use less memory.
        }

        return snapshot

    def restore(self, snapshot_id: "SnapshotID"):
        # Undoes any chain-state (e.g. deployments, storage, balances).
        self.env.evm.revert(snapshot_id)
        state = self._snapshot_state.pop(snapshot_id)
        self.env.evm.patch.block_number = state["block_number"]
        self._nonces = state["nonces"]

    def set_timestamp(self, new_timestamp: int):
        seconds = new_timestamp - self.env.evm.chain.get_canonical_head().timestamp
        self.env.time_travel(seconds=seconds, blocks=None)

    def mine(self, num_blocks: int = 1):
        if self._pending_transactions:
            for tx_hash, tx in self._pending_transactions.items():
                self._canonical_transactions[tx_hash] = tx

        self.env.evm.patch.block_number += num_blocks

    def get_virtual_machine_error(self, exception: Exception, **kwargs) -> VirtualMachineError:
        if isinstance(exception, Revert):
            raw_data = exception.args[0]
            revert_data = raw_data[4:]

            try:
                message = decode(("string",), revert_data)[0]
            except Exception:
                message = ""

            raise ContractLogicError(revert_message=message)

        return VirtualMachineError()

    def set_balance(self, address: "AddressType", amount: int):
        self.env.set_balance(address, amount)

    def get_transaction_trace(  # type: ignore[empty-body]
        self, txn_hash: Union["HexBytes", str]
    ) -> "TraceAPI":
        transaction_hash = to_hex(txn_hash) if isinstance(txn_hash, bytes) else f"{txn_hash}"
        return BoaTrace(transaction_hash=transaction_hash)  # type: ignore

    def get_test_account(self, index: int) -> "TestAccountAPI":
        if index in self._accounts:
            return self._accounts[index]

        # Generate account for the first time.
        keys = self._generate_keys(index)
        account = self.account_manager.init_test_account(
            index,
            keys[0],
            str(keys[1]),
        )
        self._accounts[index] = account

        # Initialize balance.
        self.env.set_balance(account.address, self.apetest_config.balance)

        return account

    def _generate_keys(self, index: int) -> tuple[str, str]:
        # perf: lazy imports so module loads faster.
        from eth_account.account import Account
        from eth_account.hdaccount import HDPath

        pkey = to_hex(HDPath(self.hdpath_format.format(index)).derive(self.mnemonic_seed))
        account = Account.from_key(pkey)
        return account.address, pkey

    def unlock_account(self, address: "AddressType") -> bool:
        # NOTE: All accounts are basically unlocked in boa.
        return True


class TitanoboaProvider(BaseTitanoboaProvider):
    """
    The Boa-based provider used for `local` networks.
    """

    @cached_property
    def env(self) -> "Env":
        self.boa.env.evm.patch.chain_id = self.config.chain_id
        return self.boa.env


class ForkTitanoboaProvider(BaseTitanoboaProvider):
    """
    The Boa-provider used for forked-networks.
    """

    @cached_property
    def env(self) -> "Env":
        return self.boa.env

    @cached_property
    def fork(self) -> "Open":
        from boa import fork  # type: ignore

        block_id = self.block_identifier or "safe"
        return fork(self.fork_url, block_identifier=block_id, allow_dirty=True)

    @cached_property
    def fork_config(self) -> "BoaForkConfig":
        return (
            self.config.fork.get(self.network.ecosystem.name, {}).get(
                self.forked_network.upstream_network.name
            )
            or BoaForkConfig()
        )

    @property
    def forked_network(self) -> "ForkedNetworkAPI":
        return self.network  # type: ignore

    @property
    def _forked_connection(self) -> "ProviderContextManager":
        if provider := self.fork_config.upstream_provider:
            return self.forked_network.upstream_network.use_provider(provider)
        else:
            return self.forked_network.upstream_network.use_default_provider()

    @cached_property
    def fork_url(self) -> str:
        with self._forked_connection as upstream_provider:
            return upstream_provider.http_uri

    @property
    def block_identifier(self) -> Optional["BlockID"]:
        return self.fork_config.get("block_identifier")

    @cached_property
    def forked_block_start(self) -> "BlockAPI":
        with self._forked_connection as upstream_provider:
            return upstream_provider.get_block(self.block_identifier or "latest")

    def connect(self):
        self.fork.__enter__()

    def disconnect(self):
        self.fork.__exit__()
        super().disconnect()

        for cached_prop in ("fork", "fork_url", "fork_config"):
            self.__dict__.pop(cached_prop, None)

    def get_block(self, block_id: "BlockID") -> BlockAPI:
        start_number = self.forked_block_start.number or 0
        try:
            result = super().get_block(block_id)
        except Exception:
            # Try upstream.
            with self._forked_connection as upstream_provider:
                return upstream_provider.get_block(block_id)

        if result.number is not None and result.number <= start_number:
            # Correct data such as timestamp, which may be necessary for some tests.
            with self._forked_connection as upstream_provider:
                return upstream_provider.get_block(result.number)

        return result

    def make_request(self, rpc: str, parameters: Optional[Iterable] = None) -> Any:
        with self._forked_connection as provider:
            return provider.make_request(rpc, parameters=parameters)
