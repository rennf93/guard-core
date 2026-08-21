import re
import string

DATA_CHARS = frozenset(string.ascii_letters + string.digits + "+/_-")
SEPARATOR_CHARS = "".join(
    chr(byte) for byte in range(0x80) if chr(byte) not in DATA_CHARS
) + "".join(chr(codepoint) for codepoint in range(0xDC80, 0xDD00))
WIDENED_SEPARATOR_CHARS = (
    "".join(char for char in SEPARATOR_CHARS if char not in "\r\n=") + "_-"
)

URLSAFE_TRANSLATION = str.maketrans("-_", "+/")
WIDENED_CANDIDATE_MARKER_RE = re.compile(rf"[{re.escape(WIDENED_SEPARATOR_CHARS)}]")
