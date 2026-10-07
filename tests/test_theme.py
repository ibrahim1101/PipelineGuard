from pipelineguard.theme import OLIVE, OLIVE_DARK


def test_olive_theme_is_defined() -> None:
    assert OLIVE.startswith("#")
    assert OLIVE_DARK.startswith("#")
