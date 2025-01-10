from cchecksum import to_checksum_address
from eth_pydantic_types import HashBytes32


def convert_boa_log(log: tuple, **kwargs) -> dict:
    address = to_checksum_address(f"0x{log[0].hex()}")
    return {
        "address": address,
        "data": log[2],
        "topics": [HashBytes32.__eth_pydantic_validate__(t) for t in log[1]],
        "type": "mined",
        **kwargs,
    }
