import re

import pytest

from guard_core.sync.handlers._suspatterns_file_upload import (
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _file_upload_double_extension_scan_matches,
    _file_upload_scan_window,
)
from guard_core.sync.handlers._suspatterns_matchers import _pickle_global_chain_start
from guard_core.sync.handlers._suspatterns_xml_xxe import _xml_xxe_scheme_completion_end


@pytest.mark.parametrize(
    ("content", "expected"),
    (
        ('field="value"', 'field="value"'),
        ("field='value' trailing", "field='value'"),
        ("field=value", ""),
        ("", ""),
    ),
)
def test_file_upload_scan_window_ends_at_last_quote(
    content: str, expected: str
) -> None:
    assert _file_upload_scan_window(content) == expected


def test_file_upload_double_extension_scan_matches_bounded_filename() -> None:
    compiled = re.compile(_FILE_UPLOAD_DOUBLE_EXTENSION_RE, re.IGNORECASE)
    matches = _file_upload_double_extension_scan_matches(
        'filename="report.py.pdf" filename="invoice.pdf"', compiled
    )
    assert [match.group() for match in matches] == ['filename="report.py.pdf"']


def test_pickle_global_chain_start_can_exhaust_segment_limit() -> None:
    text = "cmod" + ".cmod" * 22 + "\n"
    newline = text.index("\n")

    result = _pickle_global_chain_start(text, newline, 0)

    assert result == 10
    assert text[result:].startswith("cmod")


def test_xml_xxe_scheme_completion_rejects_non_scheme_match() -> None:
    assert _xml_xxe_scheme_completion_end('"not-a-scheme', 1, [], []) is None
