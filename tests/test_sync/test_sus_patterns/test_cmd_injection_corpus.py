import pytest

from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

STILL_UNDETECTED_COMMAND_SUBSTITUTION_PAYLOADS = [
    pytest.param("`echo pwned`", id="backtick_echo_no_separator"),
    pytest.param("`printf pwned`", id="backtick_printf_no_separator"),
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
]


@pytest.mark.parametrize("payload", STILL_UNDETECTED_COMMAND_SUBSTITUTION_PAYLOADS)
def test_bare_backtick_substitution_without_separator_remains_undetected(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


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
