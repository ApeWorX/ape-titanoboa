from typing import TYPE_CHECKING

from ape_test.accounts import TestAccount

if TYPE_CHECKING:
    from ape.api.transactions import ReceiptAPI, TransactionAPI


class BoaAccount(TestAccount):
    def call(
        self,
        txn: "TransactionAPI",
        send_everything: bool = False,
        private: bool = False,
        sign: bool = False,
        **signer_options,
    ) -> "ReceiptAPI":
        """
        Override switched the default value of ``sign`` from ``True`` to ``False``,
        as there is no reason to sign when using Boa.
        """
        return super().call(txn, send_everything, private=private, sign=sign, **signer_options)
