# Prompt Injection Benchmarks

Reproducible evaluation harness for `guard_core.prompt_injection` against several public datasets. **The measured numbers here, not the headline claims in upstream model cards, are what you should expect in your own traffic.**

## Opt-in by design

`guard_core.prompt_injection` is off by default. Enabling it is a two-step choice:

1. `SecurityConfig(enable_prompt_injection_defense=True)` — activates the check
2. `pip install 'guard-core[prompt_injection]'` — only needed for ML layers (embedding / transformer)

Without the extra, pattern + statistical layers work with zero additional dependencies. ML layers fail with a clear `ImportError` pointing at the extra — they never sneak in silently.

## Layers measured

| Layer | Config | Extra required | Notes |
|---|---|---|---|
| `pattern_only` | `PatternDetector(sensitivity=0.0)` | no | Zero-dep baseline, ~1–5 ms / classification |
| `pattern_plus_statistical` | `InjectionScorer` with `SemanticAnalyzer` boost | no | Identical to `pattern_only` in practice on natural-language inputs; statistical signal only moves on obfuscated payloads |
| `embedding` | `EmbeddingDetector(all-MiniLM-L6-v2, threshold=0.5)` | `[prompt_injection]` | Contributes to an ensemble; **not effective as a standalone classifier** (R < 0.10 at any FP-safe threshold) |
| `transformer` | `TransformerDetector(protectai/deberta-v3-base-prompt-injection)` | `[prompt_injection]` | Binary classifier, ~50–200 ms / classification |
| `full_stack` | `PromptGuard(...)` — pattern → statistical → embedding → transformer cascade | `[prompt_injection]` | Recommended when latency permits |

## Datasets

### eval_v1 (primary)

Combines five public datasets into a 47k-sample corpus with a 70/15/15 stratified-by-(language,label) split. Sources (see `dataset_loaders.py` for provenance):

- `jayavibhav/prompt-injection` — ~261k English prompts, stratified-sampled to 20k.
- `deepset/prompt-injections` (train split) — 546 samples, EN + DE.
- `Lakera/gandalf_ignore_instructions` — 777 adversarial Gandalf attempts (all positive).
- `reshabhs/SPML_Chatbot_Prompt_Injection` — 16k chatbot user-prompts against system-prompt contexts.
- `xTRam1/safe-guard-prompt-injection` — 10k EN text+label samples.

The split manifest (`manifests/eval_v1.json`) freezes sample IDs per split so runs are reproducible without shipping the raw data.

```bash
# First run downloads datasets and builds the split (cached afterwards)
uv run python benchmarks/prompt_injection/benchmark_eval_v1.py --split test
uv run python benchmarks/prompt_injection/benchmark_eval_v1.py --split test \
    --layers pattern_only pattern_plus_statistical embedding transformer full_stack
```

### Individual datasets (supporting benchmarks)

- `benchmark_deepset.py` — the 116-sample deepset test split kept as a continuity check against the 1.0 release.
- `benchmark_pint.py --dataset path/to/pint.jsonl` — PINT benchmark (dataset license-restricted; download separately).
- `benchmark_garak.py --probes path/to/garak_probes_dir` — garak promptinject probes.
- `benchmark_latency.py` — per-layer wall-clock latency on 16 representative prompts × 10 iterations.
- `benchmark_multilingual.py` — candidate non-gated multilingual transformer classifiers against the 15,637-sample non-English eval corpus (Octavio-Santana multilingual + non-English rows from deepset/spml/safe_guard + injection-sourced subset of dmtrdr Russian). Reports both micro-aggregate and language-macro-average metrics. Use this to pick the `prompt_injection_multilingual_transformer_model` default.
- `calibrate_multilingual.py` — deterministic 80/20 stratified val/test split of the multilingual corpus, threshold sweep on val, picks max-recall subject to FPR ≤ ceiling, reports held-out numbers on test. Source of the committed `prompt_injection_multilingual_transformer_threshold` default.
- `shim_latency.py` — measures inference latency of `TransformerDetector._predict` with `_neuter_torch_jit_script` active. Validates the "JIT-off is functionally identical" claim with numbers.
- `benchmark_rag.py` — `PromptGuard.protect_rag_content()` on a 180-sample synthetic corpus (benign documents with embedded injection payloads at varying positions + pure-benign negatives). Reports detection-layer attribution so you can see which layer contributes what.

## Results

Each script writes `results/<dataset>.json` with precision / recall / F1 / accuracy / FPR per layer (and per language for `eval_v1`), plus up to 20 FN/FP samples for debugging. Commit updated result files to track regressions in PRs.

### eval_v1 test split (committed, 7,128 samples)

Measured without threshold calibration (threshold=0.5 on every layer). **Calibrated operating points land in `results/calibration.json` and become the `SecurityConfig` defaults in Phase 1c.**

| Layer | P | R | F1 | FPR |
|---|---|---|---|---|
| `pattern_only` | 0.852 | 0.523 | 0.648 | 0.117 |
| `pattern_plus_statistical` | 0.852 | 0.523 | 0.648 | 0.117 |

Transformer, embedding, and full-stack numbers on the full test split are filled in by Phase 1b (`benchmark_models.py` run on MPS / CUDA).

### Per-language breakdown on eval_v1 test

| Language | N | P | R | F1 | FPR |
|---|---|---|---|---|---|
| English (en) | 7,045 | 0.851 | 0.527 | 0.651 | 0.119 |
| German (de) | 48 | 1.000 | 0.188 | 0.316 | 0.000 |
| Dutch (nl) | 13 | 0.000 | 0.000 | 0.000 | 0.000 |
| Other (xx, fr, es, it, ru, zh, tr, pt) | 22 | varies | varies | varies | varies |

The test split is overwhelmingly English (98.8%). Non-English coverage in the benchmark is therefore indicative, not statistically significant; actual non-English recall is low and the current pattern library + English-only transformer do not generalise.

### Multilingual (committed, 15,637 non-English samples across 11 languages)

Threshold = 0.5, MPS backend. Corpus = Octavio-Santana multilingual + non-English slices of deepset/spml/safe_guard + injection-sourced subset of dmtrdr Russian (9,958 Russian positives from Lakera Mosscap / hackaprompt / jackhhao / openai_synthetic sources). Full per-language breakdown in `results/multilingual.json`. Both **micro** (sample-weighted) and **macro** (language-equal-weighted) metrics reported.

| Model                                                          | Micro P | Micro R | Micro FPR | **Macro R** | **Macro FPR** |
|----------------------------------------------------------------|---------|---------|-----------|-------------|---------------|
| `proventra/mdeberta-v3-base-prompt-injection` **(default)**    | **0.995** | 0.525 | 0.010 | **0.814** | **0.007** |
| `protectai/deberta-v3-base-prompt-injection-v2`                | 0.970 | 0.486 | 0.059 | 0.545 | 0.081 |
| `robustintelligence/pi-mmbert-v3.5`                            | 0.999 | 0.349 | 0.001 | 0.483 | **0.001** |
| `madhurjindal/Jailbreak-Detector-Large`                        | 0.994 | 0.285 | 0.007 | 0.263 | 0.007 |
| `protectai/deberta-v3-base-prompt-injection` (English default) | 0.903 | 0.241 | 0.100 | 0.365 | 0.125 |

The English default drops to macro R=0.365 / FPR=0.125 on non-English traffic — one in eight benign non-English prompts flagged. Enabling language routing with the default proventra mdeberta lifts macro recall to **0.814** with macro FPR 0.007 (language-equal-weighted, excluding ru/pl which lack enough negatives for FPR). The micro R=0.525 is dragged down by Russian's 10k-positive dmtrdr corpus where every model caps at R≈0.3-0.5 — a hard dataset even for SOTA multilingual classifiers. mmBERT (`robustintelligence/pi-mmbert-v3.5`) is a lower-FPR alternative (macro 0.001 vs 0.007) at the cost of ~33 macro-recall points. DeBERTa-v2 triggers a `@torch.jit.script` deprecation warning in current `transformers` that we neuter at load time via `TransformerDetector._neuter_torch_jit_script`. Meta's Prompt-Guard family excluded — every variant requires license acceptance and an HF token.

### Honest framing

- **The 1.000 precision / 0.000 FPR numbers previously reported against the 116-sample deepset test split were a small-sample illusion.** On 7,128 samples from the same library defaults we measure FPR 0.117 — roughly 1 in 8 benign prompts trips the pattern library.
- The ProtectAI DeBERTa model's upstream card claims ">99% accuracy". Measured recall at threshold 0.5 on eval_v1 test is substantially lower (numbers appear in `results/models_test.json`). Calibrate the threshold against your own validation data before trusting any published accuracy figure.
- Pattern + statistical layers are **identical in practice** on natural-language inputs. The statistical signal only moves on obfuscated or encoded payloads (base64, zero-width joins, homoglyphs). On regular chat text they produce the same verdict.

## Reproduction

```bash
# One-time: install the optional ML deps for transformer / embedding layers
uv pip install "guard-core[prompt_injection]"

# (Re)build the eval_v1 manifest if upstream datasets change
uv run python -c "
import sys; sys.path.insert(0, 'benchmarks/prompt_injection')
from dataset_loaders import load_all, stratified_split, write_manifest
from pathlib import Path
samples = load_all(jayavibhav_max=20000)
splits = stratified_split(samples)
write_manifest(splits, Path('benchmarks/prompt_injection/manifests/eval_v1.json'))
"

# Pattern layers only (no extras required)
uv run python benchmarks/prompt_injection/benchmark_eval_v1.py --split test

# All five layers (requires [prompt_injection] extra)
uv run python benchmarks/prompt_injection/benchmark_eval_v1.py --split test \
    --layers pattern_only pattern_plus_statistical embedding transformer full_stack

# Multi-model transformer comparison (requires extra)
uv run python benchmarks/prompt_injection/benchmark_models.py --split test

# Threshold calibration on val split
uv run python benchmarks/prompt_injection/calibrate_thresholds.py

# Latency profile
uv run python benchmarks/prompt_injection/benchmark_latency.py \
    --layers pattern_only pattern_plus_statistical full_stack --iterations 10
```

## Regression targets

Committed baselines live in `results/baseline_v1.json` and the CI workflow
`.github/workflows/prompt_injection_benchmark.yml` fails a PR if:

- Recall on `eval_v1 test` drops by more than 1 pp.
- FPR on `eval_v1 test` rises above 0.13.
- Any hand-curated "known benign" regression sample flips to a false positive.

These numbers ratchet down (stricter) as Phase 1c calibration and future pattern work
lands. The targets are floors, not aspirations.
