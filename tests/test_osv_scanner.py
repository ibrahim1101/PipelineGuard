from scanners.osv_scanner import query_osv


def test_empty_inventory_does_not_call_network() -> None:
    assert query_osv([]) == []
