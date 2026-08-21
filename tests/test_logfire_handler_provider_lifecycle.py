import subprocess
import sys
import textwrap

_PREAMBLE = textwrap.dedent(
    """
    import asyncio
    import os
    import threading

    os.environ["LOGFIRE_SEND_TO_LOGFIRE"] = "False"
    os.environ["LOGFIRE_CONSOLE"] = "False"
    os.environ["LOGFIRE_IGNORE_NO_CONFIG"] = "True"

    import logfire

    from guard_core.core.events.logfire_handler import LogfireHandler

    cfg = logfire.DEFAULT_LOGFIRE_INSTANCE.config

    class Config:
        def __init__(self, service_name):
            self.logfire_service_name = service_name
    """
)


def _run_snippet(body: str) -> subprocess.CompletedProcess[str]:
    script = _PREAMBLE + "\n\n" + textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_start_never_reconfigures_a_pre_existing_host_configuration() -> None:
    result = _run_snippet(
        """
        async def main():
            logfire.configure(service_name="host-app-service")
            assert cfg.service_name == "host-app-service"

            handler = LogfireHandler(Config("guard-core"))
            await handler.start()

            assert cfg.service_name == "host-app-service"
            assert handler._configured_by_guard is False

            await handler.stop()

            assert cfg.service_name == "host-app-service"
            assert cfg._initialized is True

        asyncio.run(main())
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_start_retries_after_a_failed_configure_call() -> None:
    result = _run_snippet(
        """
        async def main():
            real_configure = logfire.configure
            calls = []

            def flaky_configure(**kwargs):
                calls.append(1)
                if len(calls) == 1:
                    raise RuntimeError("simulated transient configure failure")
                return real_configure(**kwargs)

            logfire.configure = flaky_configure

            handler = LogfireHandler(Config("guard-core"))

            raised = False
            try:
                await handler.start()
            except RuntimeError:
                raised = True

            assert raised
            assert handler._started is False
            assert handler._configured_by_guard is False

            await handler.start()

            assert len(calls) == 2
            assert handler._started is True
            assert handler._configured_by_guard is True
            assert cfg.service_name == "guard-core"

            logfire.configure = real_configure
            await handler.stop()

        asyncio.run(main())
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_second_instance_never_owns_or_reconfigures_the_first_instance() -> None:
    result = _run_snippet(
        """
        async def main():
            handler_a = LogfireHandler(Config("guard-core-a"))
            handler_b = LogfireHandler(Config("guard-core-b"))

            await handler_a.start()
            assert handler_a._configured_by_guard is True
            assert cfg.service_name == "guard-core-a"

            await handler_b.start()

            assert handler_b._configured_by_guard is False
            assert cfg.service_name == "guard-core-a"

            await handler_b.stop()

            assert cfg.service_name == "guard-core-a"
            assert cfg._initialized is True

            await handler_a.stop()
            assert handler_a._configured_by_guard is False

        asyncio.run(main())
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_stop_before_start_and_double_stop_are_safe() -> None:
    result = _run_snippet(
        """
        async def main():
            handler = LogfireHandler(Config("guard-core"))
            await handler.stop()
            assert handler._started is False

            await handler.start()
            assert handler._configured_by_guard is True

            await handler.stop()
            assert handler._configured_by_guard is False

            await handler.stop()
            assert handler._configured_by_guard is False

        asyncio.run(main())
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_start_after_stop_is_safe_though_functionally_inert() -> None:
    result = _run_snippet(
        """
        async def main():
            handler = LogfireHandler(Config("guard-core"))
            await handler.start()
            await handler.stop()

            await handler.start()
            assert handler._started is True
            assert handler._configured_by_guard is False, (
                "logfire.configure() has no way to detect that the still-installed "
                "configuration was previously guard_core's own; it stays marked "
                "as already configured after this instance's own shutdown"
            )

            await handler.stop()

        asyncio.run(main())
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_shutdown_arriving_again_after_stop_already_ran_is_safe() -> None:
    result = _run_snippet(
        """
        async def main():
            handler = LogfireHandler(Config("guard-core"))
            await handler.start()
            await handler.stop()
            assert handler._configured_by_guard is False

            logfire.shutdown()

        asyncio.run(main())
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_concurrent_start_across_many_instances_yields_exactly_one_owner() -> None:
    result = _run_snippet(
        """
        def main():
            n = 6
            handlers = [LogfireHandler(Config(f"svc-{i}")) for i in range(n)]
            errors = []
            barrier = threading.Barrier(n)

            def run_start(h):
                barrier.wait()
                try:
                    asyncio.run(h.start())
                except BaseException as e:
                    errors.append(e)

            threads = [threading.Thread(target=run_start, args=(h,)) for h in handlers]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert errors == [], errors
            owners = [h for h in handlers if h._configured_by_guard]
            assert len(owners) == 1, len(owners)

            stop_errors = []
            barrier2 = threading.Barrier(n)

            def run_stop(h):
                barrier2.wait()
                try:
                    asyncio.run(h.stop())
                except BaseException as e:
                    stop_errors.append(e)

            stop_threads = [
                threading.Thread(target=run_stop, args=(h,)) for h in handlers
            ]
            for t in stop_threads:
                t.start()
            for t in stop_threads:
                t.join()

            assert stop_errors == [], stop_errors

        main()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr
