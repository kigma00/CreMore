"""A scanning worker: one control loop and N task-runner processes.

One worker process used to run one task at a time and poll its triggers only
between tasks, so schedules, change feeds and queues stalled while a scan ran,
and scans of different connections never ran side by side in one worker. Here
the control loop polls the triggers (every 5 s, maintenance every 60 s; JobWorker
keeps that pace), touches the heartbeat file and runs the periodic hooks; it
never claims a task. Work no control-loop pass may delay (Slack alerts) runs on
a thread of its own beside it (``alongside``). Task runners are spawned
processes, each with its own settings, database engine and JobWorker, running
``process_next(poll=False)`` one task at a time. The control and remediator
roles keep their single loop.

The stop flag and each runner's liveness are lock-free shared values: a runner
may be terminated at any moment, and one that dies holding a lock (or waiting on
a multiprocessing Event's condition) would hang the supervisor's next use of it.
"""

from __future__ import annotations

import logging
import multiprocessing
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger("cremore.worker")

TICK_SECONDS = 0.5
IDLE_SECONDS = 2.0  # the pause of an empty queue, as JobWorker.run_forever has it
STALE_SECONDS = 30 * 60
BACKOFF_CAP_SECONDS = 60.0
GRACE_SECONDS = 5.0  # with a tick and the terminate step, inside the 30 s stop period Compose and Helm give
# Every runner crashed this often in a row, none lasting a minute: nothing scans, so the heartbeat stops and the
# liveness probe says so; this often, the worker exits non-zero for the orchestrator to restart and report it.
UNHEALTHY_FAILURES = 5
EXIT_FAILURES = 8

# target(stop flag, liveness value, slot, *target_args): a top-level function a spawned process can import.
# ``stop.value`` turns true when the runner should end; it sets ``liveness.value`` on every sign of life.
Target = Callable[..., None]


def run_task_loop(worker, stop, liveness, *, idle: float = IDLE_SECONDS) -> None:
    """A task runner: one task at a time until the supervisor stops it or is gone.

    The triggers, the heartbeat file and the AWS identity report are the control
    loop's. A long task's lease renewal calls ``worker.beat``; here that marks the
    runner alive instead of touching the heartbeat file.
    """

    def mark(_path=None) -> None:
        liveness.value = time.monotonic()

    worker.beat = mark
    worker.reports_identity = False  # its probe still decides its own holds
    parent = multiprocessing.parent_process()
    while not stop.value and (parent is None or parent.is_alive()):
        mark()
        if not worker.process_next(poll=False):
            time.sleep(idle)


class Repeater:
    """``hook`` about every ``seconds`` on its own daemon thread, so no control-loop pass delays it.

    A failure is logged by its exception type only, and the next call waits twice the last pause (up to
    BACKOFF_CAP_SECONDS): a database or destination that keeps failing is neither hammered nor allowed to end the
    thread, and a call that succeeds brings the pause back to ``seconds``. ``stop`` sets ``stopped`` (a hook may read
    it to end its call early) and waits up to ``grace`` seconds for the call in hand.
    """

    def __init__(self, name: str, seconds: float, hook: Callable[[], object], *, grace: float = GRACE_SECONDS) -> None:
        self.name, self.seconds, self.hook, self.grace = name, float(seconds), hook, float(grace)
        self.stopped = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._loop, name=self.name, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stopped.set()
        if self.thread is not None:
            self.thread.join(self.grace)

    def _loop(self) -> None:
        pause = self.seconds
        while not self.stopped.is_set():
            try:
                self.hook()
                pause = self.seconds
            except Exception as exc:  # noqa: BLE001 -- only its type is logged; the hook runs again after the pause
                pause = min(BACKOFF_CAP_SECONDS, pause * 2)
                logger.warning("%s failed: %s; trying again in %.0f s", self.name, type(exc).__name__, pause)
            self.stopped.wait(pause)


@dataclass
class _Runner:
    liveness: object  # a shared double the runner sets on every sign of life
    process: multiprocessing.process.BaseProcess | None = None
    started_at: float = 0.0
    seen: float = 0.0  # the liveness value last read
    seen_at: float = 0.0  # when it last changed, on the supervisor's clock
    failures: int = 0
    restart_at: float = 0.0


def _end(processes, wait: float) -> None:
    """SIGTERM (TerminateProcess on Windows), then SIGKILL whatever still runs after ``wait`` seconds."""
    for process in processes:
        process.terminate()
    deadline = time.monotonic() + wait
    for process in processes:
        process.join(max(0.0, deadline - time.monotonic()))
    for process in processes:
        if process.is_alive():
            process.kill()
            process.join(wait)


class Supervisor:
    def __init__(self, worker, concurrency: int, *, target: Target, target_args: tuple = (),
                 heartbeat_path: str | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        if concurrency < 1:
            raise ValueError("WORKER_CONCURRENCY_INVALID")
        self.worker = worker  # the control loop's JobWorker: it polls, it never claims
        self.concurrency = concurrency
        self.target = target
        self.target_args = target_args
        self.heartbeat_path = heartbeat_path
        self.clock = clock
        # spawn on every platform: a runner never inherits this process's database connections or threads.
        self.context = multiprocessing.get_context("spawn")
        self.stop = self.context.RawValue("b", 0)
        self.hooks: list[tuple[float, Callable[[], object]]] = []
        self.repeaters: list[Repeater] = []
        self.runners: list[_Runner] = []
        self._hook_runs: dict[int, float] = {}
        self._signalled = False
        self._unhealthy = False

    def every(self, seconds: float, hook: Callable[[], object]) -> None:
        """Call ``hook`` from the control loop about every ``seconds`` (a tick is 0.5 s).

        A failure is logged and the hook runs again at its next interval. Hooks run
        between trigger polls in this one loop, so a hook keeps its own work short.
        """
        self.hooks.append((float(seconds), hook))

    def alongside(self, name: str, seconds: float, hook: Callable[[], object], *, grace: float = GRACE_SECONDS) -> Repeater:
        """Call ``hook`` about every ``seconds`` on a thread of its own from ``start`` until ``shutdown``: work no
        trigger poll or maintenance pass may delay (Slack alerts). Once per worker, never in a task runner. Its
        ``stopped`` is set as soon as ``shutdown`` begins, and the call in hand is waited for up to ``grace`` seconds."""
        repeater = Repeater(name, seconds, hook, grace=grace)
        self.repeaters.append(repeater)
        return repeater

    def request_stop(self) -> None:
        """End ``run`` from any thread: the way to stop it where no SIGTERM reaches the process (Windows)."""
        self.stop.value = 1

    def stopping(self) -> bool:
        """True from the signal or ``request_stop`` on: a thread beside the loop reads it to end its call before the
        tick in hand returns and ``shutdown`` reaches it."""
        return self._signalled or bool(self.stop.value)

    def run(self) -> None:
        """Start the runners and loop until SIGTERM, SIGINT or ``request_stop``; the runners stop before it returns.

        Raises SystemExit(1) when every runner keeps crashing, so the orchestrator restarts the worker and alerts.
        """
        previous = {}
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, self._on_signal)
        crashed = False
        try:
            self.start()
            logger.info("worker ready: %d task runners", self.concurrency)
            while not self._signalled and not self.stop.value:
                self.tick()
                if self._crashing(EXIT_FAILURES):
                    logger.error("every task runner crashed %d times in a row; exiting for a restart", EXIT_FAILURES)
                    crashed = True
                    break
                time.sleep(TICK_SECONDS)
        finally:
            self.shutdown()
            for signum, handler in previous.items():
                signal.signal(signum, signal.SIG_DFL if handler is None else handler)
        if crashed:
            raise SystemExit(1)

    def _on_signal(self, _signum, _frame) -> None:
        self._signalled = True

    def start(self) -> None:
        now = self.clock()
        self.runners = [_Runner(self.context.RawValue("d", 0.0)) for _ in range(self.concurrency)]
        for slot in range(self.concurrency):
            self._spawn(slot, now)
        for repeater in self.repeaters:
            repeater.start()

    def tick(self) -> None:
        """One pass of the control loop: heartbeat file, due hooks, trigger polling, the runners' health.

        The heartbeat file says the worker scans, not only that this loop runs: while every runner is in a crash
        loop it is left alone, so the liveness probe fails instead of staying green over a worker that does nothing.
        """
        if self._crashing(UNHEALTHY_FAILURES):
            if not self._unhealthy:
                logger.error("every task runner crashed %d times in a row without lasting a minute; "
                             "the heartbeat file is no longer touched", UNHEALTHY_FAILURES)
            self._unhealthy = True
        else:
            if self._unhealthy:
                logger.info("a task runner lasted a minute again; the heartbeat file is touched again")
            self._unhealthy = False
            self.worker.beat(self.heartbeat_path)
        now = self.clock()
        for index, (seconds, hook) in enumerate(self.hooks):
            if now - self._hook_runs.get(index, float("-inf")) >= seconds:
                self._hook_runs[index] = now
                try:
                    hook()
                except Exception as exc:  # noqa: BLE001 -- the hook runs again at its next interval
                    logger.warning("worker hook failed: %s", type(exc).__name__)
        try:
            self.worker.poll_triggers()
        except Exception as exc:  # noqa: BLE001 -- the runners stay supervised; the next tick polls again
            logger.warning("trigger polling failed: %s", type(exc).__name__)
        self.check(self.clock())

    def check(self, now: float) -> None:
        """Restart a runner that died after a growing pause (1 s doubling to 60 s), and replace one with no sign
        of life for 30 minutes: neither a finished loop pass nor a lease renewal of the task in hand."""
        for slot, runner in enumerate(self.runners):
            process = runner.process
            if process is None:
                if now >= runner.restart_at:
                    self._spawn(slot, now)
                continue
            if process.is_alive():
                if runner.failures and now - runner.started_at >= BACKOFF_CAP_SECONDS:
                    runner.failures = 0  # it has lasted a minute: the crashes before it were not a loop
                value = runner.liveness.value
                if value != runner.seen:
                    runner.seen, runner.seen_at = value, now
                    continue
                if now - runner.seen_at < STALE_SECONDS:
                    continue
                logger.warning("task runner %d showed no sign of life for %d minutes; replacing it",
                               slot, STALE_SECONDS // 60)
                _end([process], 5.0)
            self._restart_later(slot, now, f"exited with code {process.exitcode}")

    def _spawn(self, slot: int, now: float) -> None:
        runner = self.runners[slot]
        runner.started_at = now
        # daemon: a supervisor that exits never leaves a runner behind. A runner may start subprocesses (the
        # document parser does), not multiprocessing children.
        process = self.context.Process(target=self.target, args=(self.stop, runner.liveness, slot, *self.target_args),
                                       name=f"cremore-task-runner-{slot}", daemon=True)
        try:
            process.start()
        except OSError as exc:  # out of processes or memory: wait like a runner that died at once
            self._restart_later(slot, now, f"could not start ({type(exc).__name__})")
            return
        runner.process = process
        runner.seen, runner.seen_at = runner.liveness.value, now

    def _crashing(self, failures: int) -> bool:
        return bool(self.runners) and all(runner.failures >= failures for runner in self.runners)

    def _restart_later(self, slot: int, now: float, reason: str) -> None:
        runner = self.runners[slot]
        if now - runner.started_at >= BACKOFF_CAP_SECONDS:
            runner.failures = 0  # it ran a while: a new failure, not a crash loop
        delay = min(BACKOFF_CAP_SECONDS, 2.0 ** runner.failures)
        runner.failures += 1
        runner.process, runner.restart_at = None, now + delay
        logger.warning("task runner %d %s; restarting in %.0f s", slot, reason, delay)

    def shutdown(self, grace: float = GRACE_SECONDS) -> None:
        """Stop the runners: each ends after the task in hand, and one still busy after ``grace`` seconds is
        terminated; that task's lease then expires and another runner takes it over. A thread beside the loop is told
        to stop at once, finishes its call in hand meanwhile and is waited for up to its own grace afterwards."""
        self.request_stop()
        for repeater in self.repeaters:
            repeater.stopped.set()
        processes = [runner.process for runner in self.runners if runner.process is not None]
        deadline = time.monotonic() + grace
        for process in processes:
            process.join(max(0.0, deadline - time.monotonic()))
        _end([process for process in processes if process.is_alive()], 3.0)
        for repeater in self.repeaters:
            repeater.stop()
