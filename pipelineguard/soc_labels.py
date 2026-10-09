"""Small presentation helpers for the desktop SOC workspace."""


def readable_count(value):
    """Format a non-negative count without inventing data."""
    if value is None:
        return "—"
    try:
        count = int(value)
    except (ValueError, TypeError, OverflowError):
        return "—"
    return str(count) if count >= 0 else "—"
