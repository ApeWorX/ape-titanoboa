# pragma version ^0.4.0

# Event for tracking donations
event Donation:
    sender: address
    amount: uint256

@external
@payable
def __default__():
    log Donation(msg.sender, msg.value)
