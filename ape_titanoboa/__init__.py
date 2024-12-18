from ape import plugins


@plugins.register(plugins.Config)
def config_class():
    from ape_titanoboa.config import TitanoboaConfig

    return TitanoboaConfig


@plugins.register(plugins.ProviderPlugin)
def providers():
    from ape_titanoboa.provider import TitanoboaProvider

    yield "ethereum", "local", TitanoboaProvider
