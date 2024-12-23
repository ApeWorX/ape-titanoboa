from typing import Optional

from ape.api.config import PluginConfig
from ape.types import BlockID
from ape.utils.testing import DEFAULT_TEST_CHAIN_ID


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

    block_identifier: Optional[BlockID] = None
    """
    The block ID, such as block number of hash, to fork from (recommended).
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
