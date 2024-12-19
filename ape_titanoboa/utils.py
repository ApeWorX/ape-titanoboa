from cchecksum import to_checksum_address
from hexbytes import HexBytes


def convert_boa_log(log: tuple, **kwargs) -> dict:
    log_index = log[0]  # TODO: Is this actually the log index? IDK
    address = to_checksum_address(f"0x{log[1].hex()}")
    return {
        "address": address,
        "data": log[3],
        "logIndex": log_index,
        "topics": [HexBytes(t) for t in log[2]],
        "type": "mined",
        **kwargs,
    }
