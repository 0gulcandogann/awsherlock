"""Terminal identity fits narrow terminals and legacy encodings."""

import pytest

from awsherlock.branding import ASCII_WORDMARK, BANNER, terminal_banner


def test_wide_utf8_console_preserves_original_banner():
    assert terminal_banner(width=160, encoding="utf-8") == BANNER


def test_wide_wordmark_rows_share_a_left_edge():
    rows = BANNER.splitlines()[8:14]
    # A's cap starts one cell inside its two vertical strokes.
    assert rows[0].index("█") == 55
    assert [row.index("█") for row in rows[1:5]] == [54] * 4
    assert rows[5].index("╚") == 54


@pytest.mark.parametrize("width", [20, 60, 80, 100])
@pytest.mark.parametrize("encoding", ["utf-8", "ascii", "cp1254"])
def test_banner_fits_width_and_stream_encoding(width, encoding):
    banner = terminal_banner(width=width, encoding=encoding)
    banner.encode(encoding)
    assert all(len(line) <= width for line in banner.splitlines())
    assert "AWSherlock" in banner
    if width >= 60:
        assert ASCII_WORDMARK in banner


def test_narrow_utf8_stacks_portrait_above_wordmark():
    banner = terminal_banner(width=80, encoding="utf-8")
    assert BANNER.splitlines()[0].rstrip(" \u2800") in banner
    assert banner.index(ASCII_WORDMARK) > 0
