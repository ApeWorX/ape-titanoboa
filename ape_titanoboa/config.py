from ape.api.config import PluginConfig
from ape.utils.testing import DEFAULT_TEST_CHAIN_ID


class TitanoboaConfig(PluginConfig):
    """
    Configure the titanoboa plugin.
    """

    chain_id: int = DEFAULT_TEST_CHAIN_ID
