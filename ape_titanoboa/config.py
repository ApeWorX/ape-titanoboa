from typing import Literal, Optional, Union

from ape.api.config import PluginConfig
from ape.types import BlockID

# TODO: https://github.com/ApeWorX/ape/issues/2454 is resolved,
#   can use `ape.utils.testing.DEFAULT_TEST_CHAIN_ID`, but for
#   now we want this to be the same as ape-foundry's default.
DEFAULT_TEST_CHAIN_ID = 31337
ForkBlockIdentifier = Union[BlockID, Literal["safe"]]


class BoaForkConfig(PluginConfig):
    """
    Configure forked networks.
    """

    upstream_provider: Optional[str] = None
    """
    The value to use, such as plugin name or URL, for the
    upstream network. Defaults to the default provider
    for that network.
    """

    block_identifier: ForkBlockIdentifier = "safe"
    """
    The block ID, such as block number of hash, to fork from (recommended).
    Defaults to the literal "safe" (same as boa).
    """


class BoaConfig(PluginConfig):
    """
    Configure the titanoboa plugin.
    """

    chain_id: int = DEFAULT_TEST_CHAIN_ID
    """
    Change the chain ID for your development "chain".
    """

    fork: dict[str, dict[str, BoaForkConfig]] = {}
    """
    Maps ecosystem name -> network name -> fork configuration (e.g. block number).
    """
