from ape import plugins


@plugins.register(plugins.Config)
def config_class():
    from ape_titanoboa.config import TitanoboaConfig

    return TitanoboaConfig


@plugins.register(plugins.ProviderPlugin)
def providers():
    from ape_titanoboa.provider import ForkTitanoboaProvider, TitanoboaProvider
    from evmchains import PUBLIC_CHAIN_META

    for ecosystem, networks in PUBLIC_CHAIN_META.items():
        yield ecosystem, "local", TitanoboaProvider
        for network in networks:
            yield ecosystem, f"{network}-fork", ForkTitanoboaProvider
