@external
def test_external_method() -> uint256:
    return 0


@view
def test_view_method() -> uint256:
    return 123


@external
def test_failing_method():
    raise
