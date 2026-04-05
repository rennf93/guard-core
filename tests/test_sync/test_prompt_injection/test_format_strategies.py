import pytest

from guard_core.sync.prompt_injection.format_strategies import (
    ByteStringStrategy,
    CodeBlockStrategy,
    FormatStrategyFactory,
    JSONEscapeStrategy,
    ReprStrategy,
    XMLTagStrategy,
)


class TestReprStrategy:
    def test_apply(self) -> None:
        strategy = ReprStrategy()
        result = strategy.apply("test input")
        assert "<user_input_start>" in result
        assert "<user_input_end>" in result
        assert "test input" in result

    def test_strategy_name(self) -> None:
        assert ReprStrategy().strategy_name == "repr"

    def test_escapes_special_chars(self) -> None:
        strategy = ReprStrategy()
        result = strategy.apply("ignore\nprevious")
        assert "\\n" in result


class TestCodeBlockStrategy:
    def test_apply(self) -> None:
        strategy = CodeBlockStrategy()
        result = strategy.apply("test input")
        assert "```" in result
        assert "test input" in result
        assert "code block contains user input" in result

    def test_strategy_name(self) -> None:
        assert CodeBlockStrategy().strategy_name == "code_block"


class TestByteStringStrategy:
    def test_apply(self) -> None:
        strategy = ByteStringStrategy()
        result = strategy.apply("test")
        assert "user_input" in result
        assert "bytes" in result

    def test_strategy_name(self) -> None:
        assert ByteStringStrategy().strategy_name == "byte_string"


class TestXMLTagStrategy:
    def test_apply(self) -> None:
        strategy = XMLTagStrategy()
        result = strategy.apply("test input")
        assert "<user_input>" in result
        assert "</user_input>" in result

    def test_escapes_xml(self) -> None:
        strategy = XMLTagStrategy()
        result = strategy.apply("<system>override</system>")
        assert "&lt;system&gt;" in result
        assert "&lt;/system&gt;" in result

    def test_escapes_ampersand(self) -> None:
        strategy = XMLTagStrategy()
        result = strategy.apply("a & b")
        assert "&amp;" in result

    def test_strategy_name(self) -> None:
        assert XMLTagStrategy().strategy_name == "xml_tags"


class TestJSONEscapeStrategy:
    def test_apply(self) -> None:
        strategy = JSONEscapeStrategy()
        result = strategy.apply("test input")
        assert '"user_input"' in result
        assert "test input" in result

    def test_escapes_quotes(self) -> None:
        strategy = JSONEscapeStrategy()
        result = strategy.apply('say "hello"')
        assert '\\"hello\\"' in result

    def test_strategy_name(self) -> None:
        assert JSONEscapeStrategy().strategy_name == "json_escape"


class TestFormatStrategyFactory:
    def test_get_repr(self) -> None:
        s = FormatStrategyFactory.get_strategy("repr")
        assert isinstance(s, ReprStrategy)

    def test_get_code_block(self) -> None:
        s = FormatStrategyFactory.get_strategy("code_block")
        assert isinstance(s, CodeBlockStrategy)

    def test_get_byte_string(self) -> None:
        s = FormatStrategyFactory.get_strategy("byte_string")
        assert isinstance(s, ByteStringStrategy)

    def test_get_xml_tags(self) -> None:
        s = FormatStrategyFactory.get_strategy("xml_tags")
        assert isinstance(s, XMLTagStrategy)

    def test_get_json_escape(self) -> None:
        s = FormatStrategyFactory.get_strategy("json_escape")
        assert isinstance(s, JSONEscapeStrategy)

    def test_invalid_strategy(self) -> None:
        with pytest.raises(ValueError, match="Unknown format strategy"):
            FormatStrategyFactory.get_strategy("nonexistent")  # type: ignore[arg-type]
