from pathlib import Path

from tests.attack_simulation.loaders import (
    BenignSample,
    Seed,
    load_benign,
    load_seeds,
)

CORPUS = Path(__file__).parent / "corpus"


def test_load_seeds_parses_payloads_and_provenance():
    seeds = load_seeds(CORPUS / "seeds")
    assert all(isinstance(seed, Seed) for seed in seeds)
    xss = [seed for seed in seeds if seed.attack_class == "xss"]
    assert len(xss) == 2
    assert xss[0].seed_id == "xss-0"
    assert xss[0].payload == "<script>alert(1)</script>"
    assert "project" in xss[0].license
    assert all(not seed.payload.startswith("#") for seed in seeds)


def test_load_benign_tags_category():
    benign = load_benign(CORPUS / "benign")
    assert all(isinstance(sample, BenignSample) for sample in benign)
    categories = {sample.category for sample in benign}
    assert "prose_sql_keywords" in categories
    assert "encoded_legit" in categories
    sql_prose = [s for s in benign if s.category == "prose_sql_keywords"]
    assert any("SELECT a coffee" in s.text for s in sql_prose)
