import re

_REGEX_ASSIGN_CLASS_RE = re.compile(r"\[[^\]]*[=:][^\]]*\]|\(\?:[=:](?:\|[=:])*\)")
_REGEX_GAP_TOKEN_RE = re.compile(r"(?:\\s|\\ |\.|\[[^\]=:]*\])(?:[*+?]|\{[\d,]*\})?")
_REGEX_GROUP_RE = re.compile(r"\(\?:|[()]")
_REGEX_ASSIGN_QUANTIFIER_RE = re.compile(r"([=:])(?:[*+?]|\{[\d,]*\})")


def regex_source_as_pair_text(source: str) -> str:
    text = _REGEX_ASSIGN_CLASS_RE.sub("=", source)
    text = _REGEX_GAP_TOKEN_RE.sub(" ", text)
    text = _REGEX_GROUP_RE.sub("", text)
    return _REGEX_ASSIGN_QUANTIFIER_RE.sub(r"\1", text)
