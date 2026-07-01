#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "guard_core"
SYNC_DIR = ROOT / "guard_core" / "sync"
TEST_DIR = ROOT / "tests"
TEST_SYNC_DIR = ROOT / "tests" / "test_sync"

SKIP_SRC = {"models.py", "exceptions.py"}

SKIP_DIRS = {"__pycache__", "sync"}

TEMPLATE_FILES = {
    SYNC_DIR / "__init__.py",
    SYNC_DIR / "protocols" / "__init__.py",
    SYNC_DIR / "protocols" / "response_protocol.py",
    SYNC_DIR / "protocols" / "middleware_protocol.py",
    SYNC_DIR / "protocols" / "request_protocol.py",
    SYNC_DIR / "protocols" / "agent_protocol.py",
    SYNC_DIR / "protocols" / "geo_ip_protocol.py",
    SYNC_DIR / "protocols" / "redis_protocol.py",
    SYNC_DIR / "py.typed",
}

HAND_MAINTAINED = {
    SYNC_DIR / "handlers" / "ratelimit_handler.py",
    TEST_SYNC_DIR / "test_agent" / "test_ratelimit_agent_integration.py",
    TEST_SYNC_DIR / "test_dynamic_rule_atomicity.py",
}

SUBS: list[tuple[str, str]] = [
    (
        r"from guard_core\.protocols\.request_protocol import GuardRequest",
        "from guard_core.sync.protocols.request_protocol import SyncGuardRequest",
    ),
    (
        r"from guard_core\.protocols\.middleware_protocol import GuardMiddlewareProtocol",  # noqa: E501
        "from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol",  # noqa: E501
    ),  # noqa: E501
    (
        r"from guard_core\.protocols\.agent_protocol import AgentHandlerProtocol",
        "from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol",
    ),
    (
        r"from guard_core\.protocols\.redis_protocol import RedisHandlerProtocol",
        "from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol",
    ),
    (
        r"from guard_core\.protocols\.geo_ip_protocol import GeoIPHandler",
        "from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler",
    ),
    (
        r"from guard_core\.protocols\.cloud_ip_store_protocol "
        r"import CloudIpStoreProtocol",
        "from guard_core.sync.protocols.cloud_ip_store_protocol "
        "import SyncCloudIpStoreProtocol",
    ),
    (
        r"from guard_core\.protocols\.cloud_ip_store_protocol "
        r"import CloudIpStoreFactory",
        "from guard_core.sync.protocols.cloud_ip_store_protocol "
        "import SyncCloudIpStoreFactory",
    ),
    (r"from guard_core\.handlers", "from guard_core.sync.handlers"),
    (r"from guard_core\.utils", "from guard_core.sync.utils"),
    (r"from guard_core\.core\.", "from guard_core.sync.core."),
    (r"from guard_core\.detection_engine\b", "from guard_core.sync.detection_engine"),
    (r"from guard_core\.detection_result\b", "from guard_core.sync.detection_result"),
    (r"from guard_core\.decorators\b", "from guard_core.sync.decorators"),
    (r"(?<!Sync)(?<!\w)GuardMiddlewareProtocol\b", "SyncGuardMiddlewareProtocol"),
    (r"(?<!Sync)(?<!\w)AgentHandlerProtocol\b", "SyncAgentHandlerProtocol"),
    (r"(?<!Sync)(?<!\w)RedisHandlerProtocol\b", "SyncRedisHandlerProtocol"),
    (r"(?<!Sync)(?<!\w)GuardRequest\b", "SyncGuardRequest"),
    (r"(?<!Sync)(?<!\w)GeoIPHandler\b", "SyncGeoIPHandler"),
    (r"(?<!Sync)(?<!\w)CloudIpStoreProtocol\b", "SyncCloudIpStoreProtocol"),
    (r"(?<!Sync)(?<!\w)CloudIpStoreFactory\b", "SyncCloudIpStoreFactory"),
    (r"from redis\.asyncio import Redis", "from redis import Redis"),
    (r"redis\.asyncio", "redis"),
    (r"import aiohttp", "import requests"),
    (r"aiohttp\.ClientSession\(\)", "requests.Session()"),
    (r"aiohttp\.ClientSession", "requests.Session"),
    (r"aiohttp\.ClientTimeout\(total=(\d+)\)", r"\1"),
    (r"await response\.read\(\)", "response.content"),
    (r"await response\.text\(\)", "response.text"),
    (r"await response\.json\(content_type=None\)", "response.json()"),
    (r"await response\.json\(\)", "response.json()"),
    (r"response\.status(?!_code)", "response.status_code"),
    (r"async def ", "def "),
    (r"async with ", "with "),
    (r"async for ", "for "),
    (r"await ", ""),
    (r"AsyncIterator", "Iterator"),
    (r"AsyncGenerator", "Generator"),
    (r"from collections\.abc import Awaitable, ", "from collections.abc import "),
    (r"from collections\.abc import Awaitable\n", ""),
    (r"Awaitable\[([^\]]+)\]", r"\1"),
    (r",\s*Awaitable\b", ""),
    (r"asynccontextmanager", "contextmanager"),
    (r"AsyncContextManager", "ContextManager"),
    (r"^import asyncio$", "import threading\nimport time"),
    (r"(\s+)import asyncio$", r"\1pass"),
    (r"asyncio\.Lock\b", "threading.Lock"),
    (r"asyncio\.Event\(\)", "threading.Event()"),
    (r"asyncio\.sleep", "time.sleep"),
    (
        r"asyncio\.create_task\(self\.(\w+)\(",
        r"threading.Thread(target=self.\1, args=(",
    ),  # noqa: E501
    (
        r"(\s+)([\w.]+) = asyncio\.create_task\((\w+)\.(\w+)\(\)\)",
        r"\1\2 = threading.Thread(target=\3.\4, daemon=True)\n\1\2.start()",
    ),
    (
        r"(\s+)([\w.]+) = asyncio\.create_task\((\w+)\(\)\)",
        r"\1\2 = threading.Thread(target=\3, daemon=True)\n\1\2.start()",
    ),
    (r"asyncio\.create_task\((\w+)\)", r"\1"),
    (r"asyncio\.Task\[[^\]]+\]", "threading.Thread"),
    (r"asyncio\.Task", "threading.Thread"),
    (r"asyncio\.CancelledError", "Exception"),
    (r"asyncio\.gather\(\*(\w+)\)", r"[t() for t in \1]"),
    (r"asyncio\.gather\(", "list(("),
    (
        r"await asyncio\.wait_for\(([^,]+),\s*timeout=([^\)]+)\)",
        r"\1.join(timeout=\2)",
    ),
    (
        r"asyncio\.wait_for\(([^,]+),\s*timeout=([^\)]+)\)",
        r"\1.join(timeout=\2)",
    ),
    (r"__aenter__", "__enter__"),
    (r"__aexit__", "__exit__"),
    (r"__aiter__", "__iter__"),
    (r"\.aclose\b", ".close"),
    (r'"guard_core\.handlers\.', '"guard_core.sync.handlers.'),
    (r'"guard_core\.core\.', '"guard_core.sync.core.'),
    (r'"guard_core\.utils', '"guard_core.sync.utils'),
    (r'"guard_core\.detection_engine', '"guard_core.sync.detection_engine'),
    (r'"guard_core\.decorators"', '"guard_core.sync.decorators"'),
]

TEST_SUBS: list[tuple[str, str]] = [
    (
        r"from tests\.conftest import \(([^)]+)\)",
        r"from tests.test_sync.conftest import (\1)",
    ),
    (
        r"from tests\.conftest import MockGuardRequest",
        "from tests.test_sync.conftest import SyncMockGuardRequest",
    ),
    (
        r"from tests\.conftest import MockGuardResponse",
        "from tests.test_sync.conftest import MockGuardResponse",
    ),
    (
        r"from tests\.conftest import MockGuardResponseFactory",
        "from tests.test_sync.conftest import MockGuardResponseFactory",
    ),
    (
        r"from tests\.conftest import (\w+(?:,\s*\w+)*)",
        r"from tests.test_sync.conftest import \1",
    ),
    (r"\bMockGuardRequest\b", "SyncMockGuardRequest"),
    (r"AsyncMock, MagicMock", "MagicMock"),
    (r"MagicMock, AsyncMock", "MagicMock"),
    (r"AsyncMock", "MagicMock"),
    (r", new_callable=MagicMock", ""),
    (r"(mock_\w+)\.text = MagicMock\(return_value=(.+)\)", r"\1.text = \2"),
    (r"(mock_\w+)\.read = MagicMock\(return_value=(.+)\)", r"\1.content = \2"),
    (r"new_callable=MagicMock,\s*", ""),
    (r"@pytest\.mark\.asyncio\n", ""),
    (r"\.assert_awaited_once_with\(", ".assert_called_once_with("),
    (r"\.assert_awaited_once\(\)", ".assert_called_once()"),
    (r"\.assert_awaited\(\)", ".assert_called()"),
    (r"\.assert_not_awaited\(\)", ".assert_not_called()"),
    (r"\.assert_awaited_with\(", ".assert_called_with("),
    (r"\.await_count\b", ".call_count"),
    (r"\.await_args\b", ".call_args"),
    (r"AsyncGenerator", "Generator"),
    (r"\.cancel\(\)", ".join(timeout=1)"),
    (r"\s+try:\n\s+loop_task\n\s+except Exception:\n\s+pass", ""),
    (r"\s+try:\n\s+manager\.update_task\n\s+except Exception:\n\s+pass", ""),
    (r"^\s+loop_task\s*$", ""),
]

TEST_SKIP_DIRS = {"__pycache__", "test_sync", "attack_simulation"}


def apply_subs(content: str, subs: list[tuple[str, str]]) -> str:
    for pattern, replacement in subs:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    return content


POST_FIXUPS: list[tuple[str, str]] = [
    (
        r"            except Exception:\n                self\.logger\.info\(\"Dynamic rule update loop cancelled\"\)\n                break\n            except Exception as e:",  # noqa: E501
        r"            except Exception as e:",
    ),
    (
        r"                pass\n\n                coro = self\._send_geo_event\(\n"
        r"                    event_type=\"geo_lookup_failed\",\n"
        r"                    ip_address=ip,\n"
        r"                    action_taken=\"lookup_failed\",\n"
        r"                    reason=f\"Geographic lookup failed: \{str\(e\)\}\",\n"
        r"                \)\n                pass",
        "                self._send_geo_event(\n"
        '                    event_type="geo_lookup_failed",\n'
        "                    ip_address=ip,\n"
        '                    action_taken="lookup_failed",\n'
        '                    reason=f"Geographic lookup failed: {str(e)}",\n'
        "                )",
    ),
    (r"list\(\(([^,]+\(\),\s*[^,]+\(\)),\s*return_exceptions=True\)", r"[\1]"),
    (
        r"            try:\n                self\.update_task\n            except Exception:\n                pass",  # noqa: E501
        "            pass",
    ),
]

DOTALL_FIXUPS: list[tuple[str, str]] = [
    (
        r"pass\n\n(\s+)coro = (self\._send_geo_event\(.+?\))\n\s+try:\n\s+coro\n\s+except Exception:\n\s+coro\.close\(\)",  # noqa: E501
        r"\2",
    ),
    (
        r"self\.update_task = threading\.Thread\(target=self\._rule_update_loop, args=\(\)\)\n\s+self\.logger\.info",  # noqa: E501
        "self.update_task = threading.Thread(\n"
        "                target=self._rule_update_loop, daemon=True\n"
        "            )\n"
        "            self.update_task.start()\n"
        "            self.logger.info",
    ),
    (
        r"self\._lazy_init_task = threading\.Thread\("
        r"target=self\._run_lazy_init, args=\(\)\)",
        "self._lazy_init_task = threading.Thread(\n"
        "                target=self._run_lazy_init, daemon=True\n"
        "            )\n"
        "            self._lazy_init_task.start()",
    ),
    (
        r"def handle_passthrough\(\n\s+self,\n\s+request: SyncGuardRequest,\n\s+call_next: Callable\[\[SyncGuardRequest\], GuardResponse\],\n\s+\) -> GuardResponse \| None:\n\s+if not request\.client_host:\n\s+response = call_next\(request\)\n\s+return self\.context\.response_factory\.apply_modifier\(response\)\n\n\s+if self\.context\.validator\.is_path_excluded\(request\):\n\s+response = call_next\(request\)\n\s+return self\.context\.response_factory\.apply_modifier\(response\)\n\n\s+return None",  # noqa: E501
        "def handle_passthrough(\n"
        "        self,\n"
        "        request: SyncGuardRequest,\n"
        "        call_next: Callable[[SyncGuardRequest], GuardResponse] | None = None,\n"  # noqa: E501
        "    ) -> GuardResponse | None:\n"
        "        if not request.client_host:\n"
        "            if call_next:\n"
        "                response = call_next(request)\n"
        "                return self.context.response_factory.apply_modifier(response)\n"  # noqa: E501
        "            return None\n"
        "\n"
        "        if self.context.validator.is_path_excluded(request):\n"
        "            if call_next:\n"
        "                response = call_next(request)\n"
        "                return self.context.response_factory.apply_modifier(response)\n"  # noqa: E501
        "            return None\n"
        "\n"
        "        return None",
    ),
    (
        r"def handle_security_bypass\(\n\s+self,\n\s+request: SyncGuardRequest,\n\s+call_next: Callable\[\[SyncGuardRequest\], GuardResponse\],\n\s+route_config: RouteConfig \| None,",  # noqa: E501
        "def handle_security_bypass(\n"
        "        self,\n"
        "        request: SyncGuardRequest,\n"
        "        call_next: Callable[[SyncGuardRequest], GuardResponse] | None = None,\n"  # noqa: E501
        "        route_config: RouteConfig | None = None,",
    ),
    (
        r"if not self\.context\.config\.passive_mode:\n\s+response = call_next\(request\)\n\s+return self\.context\.response_factory\.apply_modifier\(response\)\n\n\s+return None",  # noqa: E501
        "if not self.context.config.passive_mode:\n"
        "            if call_next:\n"
        "                response = call_next(request)\n"
        "                return self.context.response_factory.apply_modifier(response)\n"  # noqa: E501
        "            return None\n"
        "\n"
        "        return None",
    ),
    (
        r"def stop\(self\) -> None:\n\s+if self\.update_task:\n"
        r"\s+self\.update_task\.cancel\(\)\n"
        r"\s+pass\n"
        r"\s+self\.update_task = None\n"
        r"\s+self\.logger\.info\(\"Stopped dynamic rule update loop\"\)",
        "def stop(self) -> None:\n"
        "        if self.update_task and self.update_task.is_alive():\n"
        "            self.update_task.join(timeout=5)\n"
        "            self.update_task = None\n"
        '            self.logger.info("Stopped dynamic rule update loop")',
    ),
]


def transform_source(content: str) -> str:
    content = apply_subs(content, SUBS)
    for pattern, replacement in POST_FIXUPS:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    for pattern, replacement in DOTALL_FIXUPS:
        content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    return content


def _skip_async_only_tests(content: str) -> str:
    lines = content.split("\n")
    result: list[str] = []
    pending_decorators: list[str] = []
    skipping = False

    for line in lines:
        stripped = line.lstrip()

        if not skipping and stripped.startswith("@"):
            pending_decorators.append(line)
            continue

        if "# async-only" in line:
            match = re.match(r"^(\s*)(?:async )?def (test_\w+)\(", line)
            if match:
                skipping = True
                pending_decorators = []
                continue

        if skipping:
            is_next_def = re.match(
                r"^(?:async )?def test_|^@pytest\.mark|^class ", line
            )
            if is_next_def:
                skipping = False
                result.append(line)
            continue

        if pending_decorators:
            result.extend(pending_decorators)
            pending_decorators = []
        result.append(line)

    return "\n".join(result)


def transform_test(content: str) -> str:
    content = _skip_async_only_tests(content)
    content = apply_subs(content, SUBS)
    content = apply_subs(content, TEST_SUBS)
    for pattern, replacement in POST_FIXUPS:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    return content


def collect_source_files() -> list[tuple[Path, Path]]:
    pairs = []
    for root, dirs, files in os.walk(SRC_DIR):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        rel = root_path.relative_to(SRC_DIR)

        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            if rel == Path(".") and f in SKIP_SRC:
                continue
            if rel == Path(".") and f == "__init__.py":
                continue

            src = root_path / f
            dst = SYNC_DIR / rel / f

            if dst.resolve() in TEMPLATE_FILES:
                continue
            if dst.resolve() in HAND_MAINTAINED:
                continue

            pairs.append((src, dst))
    return pairs


def collect_test_files() -> list[tuple[Path, Path]]:
    pairs = []
    for root, dirs, files in os.walk(TEST_DIR):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in TEST_SKIP_DIRS]

        rel = root_path.relative_to(TEST_DIR)

        for f in sorted(files):
            if not f.endswith(".py"):
                continue

            src = root_path / f
            dst = TEST_SYNC_DIR / rel / f
            if dst.resolve() in HAND_MAINTAINED:
                continue
            pairs.append((src, dst))
    return pairs


def generate(check: bool = False) -> bool:
    all_match = True

    for src, dst in collect_source_files():
        content = src.read_text()
        transformed = transform_source(content)

        if check:
            if dst.exists():
                existing = dst.read_text()
                if existing != transformed:
                    print(f"MISMATCH: {dst}")
                    all_match = False
            else:
                print(f"MISSING: {dst}")
                all_match = False
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(transformed)

    for src, dst in collect_test_files():
        content = src.read_text()
        transformed = transform_test(content)

        if check:
            if dst.exists():
                existing = dst.read_text()
                if existing != transformed:
                    print(f"MISMATCH: {dst}")
                    all_match = False
            else:
                print(f"MISSING: {dst}")
                all_match = False
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(transformed)

    return all_match


def format_generated() -> None:
    import subprocess

    subprocess.run(
        [
            "uv",
            "run",
            "ruff",
            "check",
            "--fix",
            "--quiet",
            str(SYNC_DIR),
            str(TEST_SYNC_DIR),
        ],
        cwd=ROOT,
        capture_output=True,
    )
    subprocess.run(
        ["uv", "run", "ruff", "format", "--quiet", str(SYNC_DIR), str(TEST_SYNC_DIR)],
        cwd=ROOT,
        capture_output=True,
    )


def main() -> None:
    check = "--check" in sys.argv

    if check:
        import tempfile  # noqa: I001
        import shutil

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_sync = Path(tmpdir) / "sync"
            tmp_test = Path(tmpdir) / "test_sync"

            if SYNC_DIR.exists():
                shutil.copytree(SYNC_DIR, tmp_sync)
            if TEST_SYNC_DIR.exists():
                shutil.copytree(TEST_SYNC_DIR, tmp_test)

            generate(check=False)
            format_generated()

            ok = True
            for _, dst in collect_source_files():
                tmp_file = tmp_sync / dst.relative_to(SYNC_DIR)
                if not tmp_file.exists():
                    continue
                if dst.read_text() != tmp_file.read_text():
                    print(f"CHANGED: {dst}")
                    ok = False

            for _, dst in collect_test_files():
                tmp_file = tmp_test / dst.relative_to(TEST_SYNC_DIR)
                if not tmp_file.exists():
                    continue
                if dst.read_text() != tmp_file.read_text():
                    print(f"CHANGED: {dst}")
                    ok = False

            if SYNC_DIR.exists():
                shutil.rmtree(SYNC_DIR)
            if TEST_SYNC_DIR.exists():
                shutil.rmtree(TEST_SYNC_DIR)
            shutil.copytree(tmp_sync, SYNC_DIR)
            shutil.copytree(tmp_test, TEST_SYNC_DIR)

        if ok:
            print("OK: sync code is up to date")
            sys.exit(0)
        else:
            print("FAIL: sync code is outdated")
            print("Run 'make sync' to regenerate")
            sys.exit(1)
    else:
        generate(check=False)
        format_generated()
        print("Generated sync code in guard_core/sync/ and tests/test_sync/")


if __name__ == "__main__":
    main()
