# Attack-simulation campaign — human gate

The AI-coordinated campaign (`.claude/workflows/attack-campaign.workflow.js`, untracked)
is a discovery tool. It never edits the committed corpus. It writes proposals to
`tests/attack_simulation/out/` (git-ignored):

- `campaign-report.md` — human-readable confirmed bypasses, clustered by class+technique.
- `campaign-proposals.json` — machine-readable, each with a `disposition` (`seed` or `transform`).

The campaign's own verification is only as strong as the model it ran on. Treat every
proposal as a candidate, not a fact. Re-verify each against the real detector before
promoting it:

```python
import asyncio
from tests.attack_simulation.score_payloads import score_payloads
print(asyncio.run(score_payloads(["<candidate payload>"])))
```

A `detected: false` result confirms the detector genuinely misses it; then judge whether
it is a genuine attack worth keeping.

## Promoting a proposal (manual)

1. Read `out/campaign-report.md`. Decide which confirmed bypasses are worth keeping.
2. Re-verify each chosen payload with `score_payloads` (above) — keep only real misses.
3. For a `seed`: add the payload to `corpus/seeds/<attack_class>.txt` under a
   `# source: campaign-derived, verified` header line.
4. For a `transform`: add the function to `mutations.py` and a unit test in
   `test_mutations.py`, then register it in `TRANSFORMS`.
5. Regenerate the baseline:
   `uv run python -c "import asyncio,json; from pathlib import Path; from tests.attack_simulation.harness import run_benchmark; b=Path('tests/attack_simulation'); r=asyncio.run(run_benchmark(b/'corpus')); (b/'baseline.json').write_text(json.dumps({'detection_rate':r['detection_rate'],'fp_rate':r['fp_rate']},indent=2,sort_keys=True)+chr(10))"`
6. Run `uv run pytest tests/attack_simulation/ --no-cov` and commit the corpus +
   baseline changes. The ratchet now protects the new coverage.

Nothing from the campaign is committed except what a human promotes here.
