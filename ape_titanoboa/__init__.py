from ape import plugins


@plugins.register(plugins.Config)
def config_class():
    from ape_titanoboa.config import BoaConfig

    return BoaConfig


@plugins.register(plugins.ProviderPlugin)
def providers():
    from evmchains import PUBLIC_CHAIN_META

    from ape_titanoboa.provider import ForkTitanoboaProvider, TitanoboaProvider

    for ecosystem, networks in PUBLIC_CHAIN_META.items():
        yield ecosystem, "local", TitanoboaProvider
        for network in networks:
            yield ecosystem, f"{network}-fork", ForkTitanoboaProvider
