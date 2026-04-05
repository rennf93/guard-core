"""
Semantic analysis layer for prompt injection detection.

Catches attacks that evade regex patterns through:
- Synonym expansion (\"set aside guidelines\" → matches \"ignore instructions\")
- Unicode homoglyph normalization (Cyrillic а→a, о→o)
- Leetspeak normalization (1gn0r3 → ignore)
- Semantic phrase detection (concept-level matching)
- Fuzzy matching (typo tolerance)
"""

import re
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher

# Unicode homoglyph map: visually similar characters → ASCII equivalent
HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0415": "E",  # Cyrillic Е
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041d": "H",  # Cyrillic Н
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0421": "C",  # Cyrillic С
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    "\u0427": "4",  # Cyrillic Ч (sometimes)
    "\u0491": "r",  # Cyrillic ґ
    "\u2010": "-",  # Hyphen
    "\u2011": "-",  # Non-breaking hyphen
    "\u2012": "-",  # Figure dash
    "\u2013": "-",  # En dash
    "\u2014": "-",  # Em dash
    "\u2018": "'",  # Left single quote
    "\u2019": "'",  # Right single quote
    "\u201c": '"',  # Left double quote
    "\u201d": '"',  # Right double quote
    "\u2026": "...",  # Ellipsis
    "\uff01": "!",  # Fullwidth !
    "\uff1a": ":",  # Fullwidth :
    "\uff1b": ";",  # Fullwidth ;
}

LEETSPEAK_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
}

# Semantic groups: words that are interchangeable in attack context
# NOTE: Keep these tight — broad synonyms cause false positives
SEMANTIC_GROUPS: dict[str, set[str]] = {
    "ignore": {
        "ignore",
        "disregard",
        "skip",
        "bypass",
        "omit",
        "overlook",
        "dismiss",
        "forget",
        "cancel",
        "abort",
        "void",
        "nullify",
        "erase",
        "delete",
        "drop",
        "set aside",
        "put aside",
        "leave out",
    },
    "previous": {
        "previous",
        "prior",
        "above",
        "earlier",
        "preceding",
        "former",
        "before",
        "old",
        "original",
        "initial",
        "existing",
    },
    "instructions": {
        "instructions",
        "rules",
        "commands",
        "directives",
        "prompts",
        "orders",
        "constraints",
        "guardrails",
        "assignments",
        "tasks",
    },
    "override": {
        "override",
        "replace",
        "supersede",
        "overrule",
        "rewrite",
        "overwrite",
        "supplant",
    },
    "show": {
        "show",
        "reveal",
        "display",
        "expose",
        "disclose",
        "divulge",
    },
    "without": {
        "without",
        "free from",
        "devoid of",
    },
}

# Semantic attack phrases: concept-level patterns
# Each is (phrase_words, category_label, confidence)
# Keep to 3-concept phrases where possible to reduce FP
SEMANTIC_PHRASES: list[tuple[list[str], str, float]] = [
    # Instruction override (3-concept for precision)
    (["ignore", "previous", "instructions"], "instruction_override", 0.95),
    (["ignore", "instructions"], "instruction_override", 0.85),
    (["override", "previous", "instructions"], "instruction_override", 0.95),
    (["override", "instructions"], "instruction_override", 0.85),
    (["forget", "instructions"], "instruction_override", 0.9),
    (["ignore", "previous"], "instruction_override", 0.8),
    (["override", "previous"], "instruction_override", 0.8),
    # Jailbreak / restriction removal
    (["without", "guardrails"], "jailbreak", 0.85),
    (["without", "instructions"], "jailbreak", 0.75),
]


@dataclass
class SemanticResult:
    """Result of semantic analysis."""

    is_suspicious: bool
    confidence: float
    method: str
    matched_phrases: list[str] = field(default_factory=list)
    normalized_text: str = ""


class SemanticAnalyzer:
    """
    Semantic analysis for prompt injection detection.

    Normalizes text (homoglyphs, leetspeak, spacing) then checks
    for semantic phrase matches using synonym expansion and
    fuzzy matching.
    """

    def __init__(
        self,
        fuzzy_threshold: float = 0.85,
        proximity_window: int = 5,
    ) -> None:
        self.fuzzy_threshold = fuzzy_threshold
        self.proximity_window = proximity_window

    def normalize(self, text: str) -> str:
        """
        Normalize text by resolving obfuscation.

        Handles: homoglyphs, leetspeak, fullwidth chars,
        spacing obfuscation, unicode normalization.
        """
        # Unicode NFKC normalization (fullwidth → ASCII, etc.)
        text = unicodedata.normalize("NFKC", text)

        # Homoglyph replacement
        for glyph, replacement in HOMOGLYPH_MAP.items():
            text = text.replace(glyph, replacement)

        # Leetspeak (only in word-like contexts, not URLs/numbers)
        words = text.split()
        normalized_words = []
        for word in words:
            if re.match(r"^[a-zA-Z0-9@$!]+$", word) and not word.isdigit():
                normalized = word
                for leet, normal in LEETSPEAK_MAP.items():
                    normalized = normalized.replace(leet, normal)
                normalized_words.append(normalized)
            else:
                normalized_words.append(word)
        text = " ".join(normalized_words)

        # Spacing obfuscation: "i g n o r e" → "ignore"
        text = re.sub(r"\b(\w)\s+(?=\w\s\w|\w\b)", r"\1", text)

        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()

        return text.lower()

    def _get_synonyms(self, word: str) -> set[str]:
        """Get all synonyms for a word."""
        word_lower = word.lower()
        for synonyms in SEMANTIC_GROUPS.values():
            if word_lower in synonyms:
                return synonyms
        return {word_lower}

    def _word_matches_concept(self, text_word: str, concept: str) -> bool:
        """Check if a text word matches a concept via synonyms or fuzzy."""
        synonyms = self._get_synonyms(concept)

        # Exact synonym match (single-word synonyms)
        if text_word in synonyms:
            return True

        # Fuzzy match against single-word synonyms
        for synonym in synonyms:
            if " " in synonym:
                continue  # Skip multi-word for single-word check
            ratio = SequenceMatcher(None, text_word, synonym).ratio()
            if ratio >= self.fuzzy_threshold:
                return True

        return False

    def _bigram_matches_concept(self, word1: str, word2: str, concept: str) -> bool:
        """Check if a two-word bigram matches a multi-word synonym."""
        synonyms = self._get_synonyms(concept)
        bigram = f"{word1} {word2}"

        for synonym in synonyms:
            if " " not in synonym:
                continue
            if bigram == synonym:
                return True
            ratio = SequenceMatcher(None, bigram, synonym).ratio()
            if ratio >= self.fuzzy_threshold:
                return True

        return False

    def _find_concept_positions(self, words: list[str], concept: str) -> list[int]:
        """Find all word positions that match a concept."""
        found: list[int] = []
        for i, word in enumerate(words):
            if self._word_matches_concept(word, concept):
                found.append(i)
            elif i + 1 < len(words) and self._bigram_matches_concept(
                word, words[i + 1], concept
            ):
                found.append(i)
        return found

    def _check_phrase(self, words: list[str], phrase_concepts: list[str]) -> bool:
        """
        Check if text words contain all phrase concepts
        within proximity window.
        """
        positions: dict[str, list[int]] = {}
        for concept in phrase_concepts:
            found = self._find_concept_positions(words, concept)
            if found:
                positions[concept] = found

        if len(positions) < len(phrase_concepts):
            return False

        all_pos = [p for plist in positions.values() for p in plist]
        return (max(all_pos) - min(all_pos)) <= self.proximity_window

    def analyze(self, text: str) -> SemanticResult:
        """
        Analyze text for semantic prompt injection patterns.

        Normalizes text, then checks against semantic phrases
        using synonym expansion and fuzzy matching.
        """
        if not text or len(text) < 5:
            return SemanticResult(
                is_suspicious=False,
                confidence=0.0,
                method="none",
                normalized_text="",
            )

        normalized = self.normalize(text)
        words = normalized.split()

        matched_phrases: list[str] = []
        max_confidence = 0.0

        for phrase_concepts, category, confidence in SEMANTIC_PHRASES:
            if self._check_phrase(words, phrase_concepts):
                label = f"{category}: {' + '.join(phrase_concepts)}"
                matched_phrases.append(label)
                max_confidence = max(max_confidence, confidence)

        if matched_phrases:
            return SemanticResult(
                is_suspicious=True,
                confidence=max_confidence,
                method="semantic",
                matched_phrases=matched_phrases,
                normalized_text=normalized,
            )

        return SemanticResult(
            is_suspicious=False,
            confidence=0.0,
            method="none",
            matched_phrases=[],
            normalized_text=normalized,
        )
