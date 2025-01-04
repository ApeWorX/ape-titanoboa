import re
import time
from abc import ABC
from collections import defaultdict
from copy import copy
from functools import cached_property
from types import ModuleType
from typing import TYPE_CHECKING, Any, ClassVar, Iterable, Iterator, Optional, Union

from ape.api.providers import BlockAPI, TestProviderAPI
from ape.exceptions import (
    BlockNotFoundError,
    ContractLogicError,
    ProviderError,
    TransactionNotFoundError,
    VirtualMachineError,
)
from ape_ethereum.transactions import TransactionStatusEnum
from eth.constants import ZERO_ADDRESS
from eth.exceptions import Revert
from eth.vm.spoof import SpoofTransaction
from eth_abi import decode
from eth_pydantic_types import HexBytes
from eth_utils import ValidationError, to_hex

from ape_titanoboa.config import BoaForkConfig, ForkBlockIdentifier
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

    from ape_titanoboa.config import BoaConfig


class BaseTitanoboaProvider(TestProviderAPI, ABC):
    """
    A provider for Ape using titanoboa as its backend.
    """

    NAME: ClassVar[str] = "boa"

    # Flags.
    _auto_mine: bool = True
    _connected: bool = False

    # Account state.
    _accounts: dict[int, "TestAccount"] = {}
    _nonces: defaultdict["AddressType", int] = defaultdict(int)

    # Transaction state.
    _canonical_transactions: dict[str, dict] = {}
    _pending_transactions: dict[str, dict] = {}

    # Snapshot state.
    _snapshot_state: dict["SnapshotID", dict] = {}

    # Block state.
    _blocks: list[dict] = []

    # Time.
    # Used when `set_timestamp()` is called.
    _pending_timestamp: Optional[int] = None
    # Used when timestamp was set but then mined to keep us in the future.
    _timestamp_offset: int = 0
    _execution_timestamp: Optional[int] = None  # Used when auto mine is off.

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

    @property
    def earliest_block(self) -> "BlockAPI":
        return self.get_block_by_number(0)

    @property
    def latest_block(self) -> "BlockAPI":
        latest_block_number = self.env.evm.patch.block_number
        return self.get_block_by_number(latest_block_number)

    @property
    def pending_block(self) -> "BlockAPI":
        header = self.env.evm.chain.get_block().header
        block_number = self.env.evm.patch.block_number + 1
        timestamp = self.pending_timestamp
        return self._init_blockapi(header, block_number, timestamp)

    @property
    def pending_timestamp(self) -> int:
        if self._execution_timestamp is not None:
            # Use the same time from last execution (so it retains in the block).
            return self._execution_timestamp

        elif self._pending_timestamp is not None:
            # Time is frozen (via `set_timestamp()`).
            return self._pending_timestamp

        # NOTE: self._timestamp_offset is > 0 when set_timestamp has
        #   been called and we have since mined the block using the
        #   frozen time. This keeps us passed that point.
        return int(time.time()) + self._timestamp_offset

    @property
    def gas_price(self) -> int:
        return self.env.get_gas_price()

    @property
    def max_gas(self) -> int:
        return self.env.evm.get_gas_limit()

    @cached_property
    def _reusable_header(self):
        # NOTE: We use this header only as a base,
        #   this chain is all very made-up. It being
        #   the canonical-head is irrelevant here.
        return self.env.evm.chain.get_canonical_head()

    def connect(self):
        _ = self.env
        self._connected = True
        # Add genesis block.
        self._blocks.append({"ts": self.env.evm.patch.timestamp})
        self.env.evm.patch.block_number = 0

        if self._accounts:
            # Accounts have already been accessed, maybe through pytest
            # fixtures; and we have changed networks. We must ensure
            # they are configured with a balance. Clearing them on
            # disconnect does not work because they might be cached in pytest.
            for acct in self._accounts.values():
                self.env.set_balance(acct.address, self.apetest_config.balance)

    def disconnect(self):
        self.boa.reset_env()  # type: ignore
        self._blocks = []
        self._pending_timestamp = None
        self._timestamp_offset = 0
        self._canonical_transactions = {}
        self._pending_transactions = {}
        self._nonces = {}
        self._snapshot_state = {}
        self._execution_timestamp = None

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
        sender_bytes = HexBytes(txn.sender) if txn.sender else ZERO_ADDRESS
        try:
            return self._estimate_spoof_transaction(evm_tx_data, sender_bytes)
        except ValidationError as err:
            # TODO: Figure out why this happens...
            if match := re.match(
                r"Invalid transaction nonce: Expected (\d*), but got \d*", f"{err}"
            ):
                expected = int(match.groups()[0])
                evm_tx_data["nonce"] = expected
                return self._estimate_spoof_transaction(evm_tx_data, sender_bytes)

            raise  # Raise the error as-is.

    def _estimate_spoof_transaction(self, transaction_dict: dict, sender: bytes) -> int:
        evm_tx = self.env.evm.chain.create_unsigned_transaction(**transaction_dict)
        spoof_tx = SpoofTransaction(evm_tx, from_=sender)
        return self.env.evm.chain.estimate_gas(spoof_tx)

    def get_block(self, block_id: "BlockID") -> BlockAPI:
        if isinstance(block_id, int):
            return self.get_block_by_number(block_id)
        elif block_id == "earliest":
            return self.earliest_block
        elif block_id == "latest":
            return self.latest_block
        elif block_id == "pending":
            return self.pending_block

        return self.get_block_by_hash(block_id)

    def get_block_by_number(self, number: int) -> "BlockAPI":
        raise NotImplementedError("Must be implemented in sub-class,")

    def get_block_by_hash(self, block_hash: bytes) -> "BlockAPI":
        raise NotImplementedError("Must be implemented in sub-class,")

    def _get_block_index_from_hash(self, block_hash: bytes) -> int:
        # NOTE: This is the block **index** because in the case of forked chains,
        #   the block number is much higher than the index.
        header = self._reusable_header

        # NOTE: Hashes are made up from the reusable hash plus the block number
        return int(to_hex(block_hash), 16) - int(to_hex(header.hash), 16)

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
        try:
            data = self._canonical_transactions[txn_hash]
        except KeyError as err:
            raise TransactionNotFoundError(txn_hash) from err

        return BoaReceipt(**data)

    def get_transactions_by_block(self, block_id: "BlockID") -> Iterator["TransactionAPI"]:
        block = self.get_block(block_id)
        if block.number is not None:
            for txn_hash in self._blocks[block.number].get("txns", []):
                data = self._canonical_transactions[txn_hash]
                data["txn_hash"] = HexBytes(data["txn_hash"])
                yield BoaTransaction(**data)

    def prepare_transaction(self, txn: "TransactionAPI") -> "TransactionAPI":
        txn.max_fee = 0
        txn.max_priority_fee = 0
        txn.gas_limit = self.env.evm.get_gas_limit()
        txn.chain_id = self.chain_id

        if txn.nonce is None and txn.sender:
            txn.nonce = self._nonces[txn.sender]

        return txn

    def send_transaction(self, txn: "TransactionAPI") -> "ReceiptAPI":
        sender_nonce = self._nonces[txn.sender]
        tx_nonce = txn.nonce
        if tx_nonce is None or tx_nonce < sender_nonce:
            raise ProviderError(f"Invalid nonce '{tx_nonce}'.")

        else:
            # TODO: Improve this...
            while sender_nonce > tx_nonce:
                time.sleep(1)
                sender_nonce = self._nonces[txn.sender]

        # Set block.timestamp/number for execution. This must be the
        # same during execution as it will be in the block.
        execution_timestamp = self.pending_timestamp
        self._pending_timestamp = None
        new_block_number = self.env.evm.patch.block_number + 1
        self.env.evm.patch.timestamp = execution_timestamp
        self.env.evm.patch.block_number = new_block_number

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

        revert = None
        try:
            computation.raise_if_error()
        except Revert as err:
            # The transaction failed. Continue mining the block
            # before handling.
            revert = err

        # Figure out the transaction's hash.
        if txn.signature:
            txn_hash = to_hex(txn.txn_hash)
        else:
            # Impersonated transaction. Make one up using the sender.
            txn_hash = to_hex(int(txn.sender, 16) + txn.nonce)

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
            # Advance the chain.
            self._blocks.append({"ts": execution_timestamp, "txns": [txn_hash]})
            self._canonical_transactions[txn_hash] = data
        else:
            # Will become canon once `self.mine()` is called.
            self._pending_transactions[txn_hash] = data
            # Undo chain-changes until manually mined.
            self.env.evm.patch.timestamp = self._blocks[-1]["ts"]
            self.env.evm.patch.block_number = self.env.evm.patch.block_number - 1

        # Bump sender's nonce.
        self._nonces[txn.sender] = self._nonces[txn.sender] + 1

        if revert is not None and txn.raise_on_revert:
            raise self.get_virtual_machine_error(revert) from revert

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
        try:
            state = self._snapshot_state.pop(snapshot_id)
        except KeyError:
            return

        block_number = state["block_number"]
        current_block_number = self.env.evm.patch.block_number
        self.env.evm.patch.block_number = block_number

        if block_number <= self.env.evm.patch.block_number:
            try:
                old_block = self._blocks[block_number]
            except IndexError:
                pass
            else:
                self.env.evm.patch.timestamp = old_block["ts"]

            new_height = block_number + 1

            # Clear transactions.
            for block_to_remove in range(new_height, current_block_number + 1):
                try:
                    block = self._blocks[block_to_remove]
                except IndexError:
                    continue

                for transaction_hash in block.get("txns", []):
                    self._canonical_transactions.pop(transaction_hash, None)

            # Clear blocks.
            self._blocks = self._blocks[:new_height]

        self._nonces = state["nonces"]

    def set_timestamp(self, new_timestamp: int):
        self._pending_timestamp = new_timestamp

    def mine(self, num_blocks: int = 1):
        if self._pending_transactions:
            for tx_hash, tx in self._pending_transactions.items():
                self._canonical_transactions[tx_hash] = tx

            # Reset so the next execution-set uses the real pending timestamp.
            self._execution_timestamp = None

        self._advance_chain(
            blocks=num_blocks, transaction_hashes=list(self._pending_transactions.keys())
        )
        self._pending_transactions = {}

    def _advance_chain(self, blocks: int = 1, transaction_hashes: Optional[list] = None):
        for _ in range(blocks):
            # NOTE: auto-mine is off, the pending timestamp refers to the timestamp
            #   set before executing any EVM code (transactions), so it is the same
            #   in the block as it was when executed.
            timestamp = self.pending_timestamp

            if self._pending_timestamp is not None:
                # Unfreeze time.
                self._timestamp_offset = timestamp - int(time.time())
                self._pending_timestamp = None

            new_block: dict = {"ts": timestamp}
            self._blocks.append(new_block)
            self.env.evm.patch.block_number += 1
            self.env.evm.patch.timestamp = timestamp

        # Hashes only appear in last block added.
        if transaction_hashes:
            self._blocks[-1]["txns"] = transaction_hashes

    def get_virtual_machine_error(self, exception: Exception, **kwargs) -> VirtualMachineError:
        if isinstance(exception, Revert):
            raw_data = exception.args[0]
            revert_data = raw_data[4:]

            try:
                message = decode(("string",), revert_data)[0]
            except Exception:
                message = ""

            raise ContractLogicError(revert_message=message, **kwargs)

        return VirtualMachineError(**kwargs)

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

    def _init_blockapi(self, header, block_number: int, timestamp: int) -> "BlockAPI":
        # NOTE: If we don't do this, all the hashes are the same, and that
        #   creates problems in Ape.
        fake_hash = HexBytes(int(to_hex(header.hash), 16) + block_number)
        return self.network.ecosystem.decode_block(
            {
                "gasLimit": header.gas_limit,
                "gasUsed": header.gas_used,
                "hash": fake_hash,
                "number": block_number,
                "parentHash": header.parent_hash,
                "timestamp": timestamp,
            }
        )


class TitanoboaProvider(BaseTitanoboaProvider):
    """
    The Boa-based provider used for `local` networks.
    """

    @cached_property
    def env(self) -> "Env":
        self.boa.env.evm.patch.chain_id = self.settings.chain_id
        return self.boa.env

    def get_nonce(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        return self._nonces[address]

    def get_block_by_number(self, number: int) -> "BlockAPI":
        try:
            timestamp = self._blocks[number]["ts"]
        except IndexError:
            raise BlockNotFoundError(number)

        return self._init_blockapi(self._reusable_header, number, timestamp)

    def get_block_by_hash(self, block_hash: bytes) -> "BlockAPI":
        block_index = self._get_block_index_from_hash(block_hash)
        try:
            timestamp = self._blocks[block_index]["ts"]
        except IndexError:
            raise BlockNotFoundError(HexBytes(block_hash))

        # Block index is the same as block number for local networks.
        return self._init_blockapi(self._reusable_header, block_index, timestamp)


class ForkTitanoboaProvider(BaseTitanoboaProvider):
    """
    The Boa-provider used for forked-networks.
    """

    _upstream_blocks: dict["BlockID", "BlockAPI"] = {}

    @cached_property
    def env(self) -> "Env":
        return self.boa.env

    @cached_property
    def fork(self) -> "Open":
        from boa import fork  # type: ignore

        block_id = self.block_identifier or "safe"
        return fork(self.fork_url, block_identifier=block_id, allow_dirty=True)

    @property
    def fork_config(self) -> "BoaForkConfig":
        return (
            self.settings.fork.get(self.network.ecosystem.name, {}).get(
                self.forked_network.upstream_network.name
            )
            or BoaForkConfig()
        )

    @property
    def forked_network(self) -> "ForkedNetworkAPI":
        return self.network  # type: ignore

    @property
    def earliest_block(self) -> "BlockAPI":
        return self._get_block_from_upstream("earliest")

    @property
    def _upstream_connection(self) -> "ProviderContextManager":
        if provider := self.fork_config.upstream_provider:
            return self.forked_network.upstream_network.use_provider(provider)
        else:
            return self.forked_network.upstream_network.use_default_provider()

    @cached_property
    def fork_url(self) -> str:
        with self._upstream_connection as upstream_provider:
            return upstream_provider.http_uri

    @property
    def block_identifier(self) -> ForkBlockIdentifier:
        return self.fork_config.block_identifier

    @cached_property
    def forked_block_start(self) -> "BlockAPI":
        with self._upstream_connection as upstream_provider:
            return upstream_provider.get_block(self.block_identifier)

    @cached_property
    def _upstream_chain_id(self) -> int:
        with self._upstream_connection as upstream_provider:
            return upstream_provider.chain_id

    @property
    def chain_id(self) -> int:
        # TODO: Support having a different chain ID than the upstream
        #   (with the default being the upstream).
        return self._upstream_chain_id

    def connect(self):
        self._connected = True
        self.fork.__enter__()
        block = self.forked_block_start
        self.env.evm.patch.block_number = block.number
        self.env.evm.patch.timestamp = block.timestamp
        self._blocks = [{"ts": block.timestamp}]
        self.env.evm.patch.chain_id = self._upstream_chain_id

    def disconnect(self):
        self.fork.__exit__()
        super().disconnect()

    def get_nonce(self, address: "AddressType", block_id: Optional["BlockID"] = None) -> int:
        if address in self._nonces:
            return self._nonces[address]

        # Get the data from upstream.
        with self._upstream_connection as upstream_provider:
            nonce = upstream_provider.get_nonce(address)
            self._nonces[address] = nonce

        return nonce

    def get_block_by_number(self, number: int) -> "BlockAPI":
        start_number = self.forked_block_start.number or 0
        if number == start_number:
            return self.forked_block_start

        elif number < start_number:
            # Is before fork.
            return self._get_block_from_upstream(number)

        # Is since fork.
        return self._get_block_since_fork_by_number(number)

    def _get_block_since_fork_by_number(self, number: int) -> "BlockAPI":
        start_number = self.forked_block_start.number or 0
        index = number - start_number
        try:
            timestamp = self._blocks[index]["ts"]
        except IndexError:
            # NOTE: Ensure we raise error with the *given* number.
            raise BlockNotFoundError(number)

        return self._init_blockapi(self._reusable_header, number, timestamp)

    def get_block_by_hash(self, block_hash: bytes) -> "BlockAPI":
        index = self._get_block_index_from_hash(block_hash)

        if index >= 0 or index < len(self._blocks):
            block_number = (self.forked_block_start.number or 0) + index
            return self._init_blockapi(
                self._reusable_header, block_number, self._blocks[index]["ts"]
            )

        return self._get_block_from_upstream(block_hash)

    def _get_block_from_upstream(self, block_id: "BlockID") -> "BlockAPI":
        if block := self._upstream_blocks.get(block_id):
            return block

        with self._upstream_connection as upstream_provider:
            upstream_block = upstream_provider.get_block(block_id)
            # Cache for next time.
            self._upstream_blocks[block_id] = upstream_block
            return upstream_block

    def make_request(self, rpc: str, parameters: Optional[Iterable] = None) -> Any:
        with self._upstream_connection as provider:
            return provider.make_request(rpc, parameters=parameters)

    def get_receipt(self, txn_hash: str, **kwargs) -> "ReceiptAPI":
        if data := self._canonical_transactions.get(txn_hash):
            if isinstance(data, dict):
                # Transaction made with this plugin (boa).
                return BoaReceipt(**data)

            # Is a cached transaction from upstream.
            return data

        # Historical transaction.
        with self._upstream_connection as upstream_provider:
            receipt = upstream_provider.get_receipt(txn_hash)
            self._canonical_transactions[txn_hash] = receipt
            return receipt
