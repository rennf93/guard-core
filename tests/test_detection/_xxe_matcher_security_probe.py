import json
import statistics
import time

from guard_core.handlers._suspatterns_xml_xxe import (
    _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE,
    _xml_internal_entity_finditer,
    _xml_system_finditer,
    _xml_xxe_public_external_dtd_finditer,
)


def measure() -> dict[str, list[float]]:
    result: dict[str, list[float]] = {}
    compiled = _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE
    for size in (16384, 32768, 65536, 131072):
        shapes = {
            "public_in_url": '<!DOCTYPE x PUBLIC "id" "http://evil/'
            + "PUBLIC " * (size // 7)
            + '">',
            "public_in_trailer": '<!DOCTYPE x PUBLIC "id" "http://evil/x" '
            + "PUBLIC " * (size // 7)
            + ">",
            "empty_scheme_decoys": '<!DOCTYPE x PUBLIC "id" '
            + '"http://" ' * (size // 10)
            + '"http://evil/x">',
        }
        for shape, text in shapes.items():
            samples = []
            for _ in range(5):
                start = time.process_time()
                matches = list(_xml_xxe_public_external_dtd_finditer(text, compiled))
                samples.append(time.process_time() - start)
                assert matches, shape
            result.setdefault(shape, []).append(statistics.median(samples))
        for label, finder, tail in [
            ("system_openers", _xml_system_finditer, ">"),
            ("internal_openers", _xml_internal_entity_finditer, "<!ENTITY"),
        ]:
            text = "<!DOCTYPE" * (size // 9) + tail
            samples = []
            for _ in range(5):
                start = time.process_time()
                matches = list(finder(text))
                samples.append(time.process_time() - start)
                assert not matches, label
            result.setdefault(label, []).append(statistics.median(samples))
    return result


if __name__ == "__main__":
    print(json.dumps(measure()))
