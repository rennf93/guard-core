import json
import subprocess
import sys
from typing import cast

FORBIDDEN_MODULES = frozenset({"aiohttp", "maxminddb", "redis"})


def _imported_forbidden_modules() -> list[str]:
    script = (
        "import json\n"
        "import sys\n"
        "import guard_core\n"
        f"forbidden = {FORBIDDEN_MODULES!r}\n"
        "print(json.dumps(sorted(m for m in sys.modules "
        "if m.split('.')[0] in forbidden)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    return cast(list[str], json.loads(result.stdout))


def test_importing_guard_core_does_not_load_aiohttp_maxminddb_or_redis() -> None:
    assert _imported_forbidden_modules() == []
