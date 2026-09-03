#!/usr/bin/env bash
set -euo pipefail

repo="$1"
sync_extra="$2"
pytest_args="$3"
wheel_dir="$4"
expected_version="$5"
redis_prefix="${6:-}"
consumer_ref="${7:-}"

clone_dir="consumer"

resolve_latest_release_tag() {
  local repo="$1" tag
  tag="$(gh api "repos/$repo/releases/latest" --jq '.tag_name' 2>/dev/null || true)"
  if [ -z "$tag" ] || [ "$tag" = "null" ]; then
    echo "gh api releases/latest returned nothing, falling back to tag version-sort" >&2
    tag="$(
      git ls-remote --tags "https://github.com/$repo" \
        | grep -v '\^{}' \
        | awk -F'refs/tags/' '{print $2}' \
        | while read -r t; do echo "${t#v} $t"; done \
        | sort -rV -k1,1 \
        | head -1 \
        | awk '{print $2}'
    )"
  fi
  echo "$tag"
}

echo "::group::Resolve $repo ref (consumer_ref=${consumer_ref:-<default branch>})"
if [ -z "$consumer_ref" ]; then
  ref="$(gh api "repos/$repo" --jq '.default_branch')"
elif [ "$consumer_ref" = "latest-release" ]; then
  ref="$(resolve_latest_release_tag "$repo")"
else
  ref="$consumer_ref"
fi
if [ -z "$ref" ]; then
  echo "Could not resolve a ref for $repo" >&2
  exit 1
fi
echo "Resolved ref for $repo: $ref"
echo "::endgroup::"

echo "::group::Clone $repo@$ref"
git clone --branch "$ref" --depth 1 "https://github.com/$repo" "$clone_dir"
cd "$clone_dir"
echo "::endgroup::"

echo "::group::uv sync $sync_extra"
# shellcheck disable=SC2086 # sync_extra is a deliberate multi-flag string, e.g. "--extra dev"
uv sync $sync_extra
echo "::endgroup::"

echo "::group::Force-install the PR guard-core wheel"
wheel="$(ls "$wheel_dir"/*.whl)"
echo "Installing $wheel over whatever guard-core $repo resolved"
uv pip install --python .venv/bin/python --no-deps --force-reinstall "$wheel"
echo "::endgroup::"

echo "::group::Assert guard-core is the PR build"
actual_version="$(.venv/bin/python -c "import guard_core, importlib.metadata as m; print(m.version('guard-core'))")"
echo "guard-core version resolved by $repo's venv: $actual_version"
if [ "$actual_version" != "$expected_version" ]; then
  echo "Expected guard-core $expected_version, got $actual_version" >&2
  exit 1
fi

guard_core_file="$(.venv/bin/python -c "import guard_core; print(guard_core.__file__)")"
venv_abs="$(cd .venv && pwd)"
echo "guard_core.__file__ = $guard_core_file"
case "$guard_core_file" in
  "$venv_abs"/*) ;;
  *)
    echo "guard_core did not load from $repo's own venv ($venv_abs): $guard_core_file" >&2
    exit 1
    ;;
esac
echo "::endgroup::"

echo "::group::Run $repo's test suite"
run_env=(IPINFO_TOKEN="${IPINFO_TOKEN:-test_token}" REDIS_URL="${REDIS_URL:-redis://localhost:6379}")
if [ -n "$redis_prefix" ]; then
  run_env+=(REDIS_PREFIX="$redis_prefix")
fi
set +e
# shellcheck disable=SC2086 # pytest_args is a deliberate multi-flag string, e.g. "-v --cov=guard --cov-branch"
env "${run_env[@]}" uv run pytest $pytest_args 2>&1 | tee pytest-output.txt
status="${PIPESTATUS[0]}"
set -e
echo "::endgroup::"
exit "$status"
