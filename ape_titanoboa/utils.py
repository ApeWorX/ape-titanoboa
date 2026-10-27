from cchecksum import to_checksum_address
from eth_pydantic_types import HexBytes32
from hexbytes import HexBytes


def convert_boa_log(log: tuple, **kwargs) -> dict:
    address = to_checksum_address(f"0x{log[0].hex()}")
    return {
        "address": address,
        "data": log[2],
        # HexBytes32 pads on the right, but topics are 32-byte words, so pad on the left.
        "topics": [
            HexBytes32.__eth_pydantic_validate__(HexBytes(t).rjust(32, b"\x00")) for t in log[1]
        ],
        "type": "mined",
        **kwargs,
    }
