import json
from abc import ABC, abstractmethod
from typing import Literal


class FormatStrategy(ABC):
    """Base class for format manipulation strategies."""

    @abstractmethod
    def apply(self, user_input: str) -> str:
        """Apply the format manipulation to user input."""
        pass  # pragma: no cover

    @property
    @abstractmethod
    def strategy_name(self) -> str:
        """Name of this format strategy."""
        pass  # pragma: no cover


class ReprStrategy(FormatStrategy):
    """Python repr() wrapping strategy."""

    @property
    def strategy_name(self) -> str:
        return "repr"

    def apply(self, user_input: str) -> str:
        return f"<user_input_start>{repr(user_input)}<user_input_end>"


class CodeBlockStrategy(FormatStrategy):
    """Markdown code block isolation strategy."""

    @property
    def strategy_name(self) -> str:
        return "code_block"

    def apply(self, user_input: str) -> str:
        wrapped = f"```\n{user_input}\n```\n\n"
        return wrapped + "The above code block contains user input to be processed."


class ByteStringStrategy(FormatStrategy):
    """Byte string conversion strategy."""

    @property
    def strategy_name(self) -> str:
        return "byte_string"

    def apply(self, user_input: str) -> str:
        byte_repr = str(bytes(user_input, "utf-8"))[2:-1]
        return f'<user_input bytes="{byte_repr}"/>'


class XMLTagStrategy(FormatStrategy):
    """Custom XML-like tag strategy."""

    @property
    def strategy_name(self) -> str:
        return "xml_tags"

    def apply(self, user_input: str) -> str:
        escaped = user_input.replace("&", "&amp;")
        escaped = escaped.replace("<", "&lt;")
        escaped = escaped.replace(">", "&gt;")
        return f"<user_input>\n{escaped}\n</user_input>"


class JSONEscapeStrategy(FormatStrategy):
    """JSON string escaping strategy."""

    @property
    def strategy_name(self) -> str:
        return "json_escape"

    def apply(self, user_input: str) -> str:
        escaped = json.dumps(user_input)
        return f'{{"user_input": {escaped}}}'


class FormatStrategyFactory:
    """Factory for creating format strategy instances."""

    _strategies: dict[str, type[FormatStrategy]] = {
        "repr": ReprStrategy,
        "code_block": CodeBlockStrategy,
        "byte_string": ByteStringStrategy,
        "xml_tags": XMLTagStrategy,
        "json_escape": JSONEscapeStrategy,
    }

    @classmethod
    def get_strategy(
        cls,
        strategy_name: Literal[
            "repr", "code_block", "byte_string", "xml_tags", "json_escape"
        ],
    ) -> FormatStrategy:
        strategy_class = cls._strategies.get(strategy_name)
        if not strategy_class:
            raise ValueError(
                f"Unknown format strategy: {strategy_name}. "
                f"Valid options: {', '.join(cls._strategies.keys())}"
            )
        return strategy_class()
