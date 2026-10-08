import pytest
from hexbytes import HexBytes

from ape_titanoboa.utils import convert_boa_log

ADDRESS = bytes.fromhex("5fbdb2315678afecb367f032d93f642f64180aa3")
TOPIC = HexBytes(31 * b"\x00" + b"\x05")


@pytest.mark.parametrize("topic", [5, b"\x05", "0x05", bytes(TOPIC)])
def test_convert_boa_log_pads_topics_on_the_left(topic):
    log = convert_boa_log((ADDRESS, [topic], b""))
    assert log["address"] == "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    assert log["topics"] == [TOPIC]
