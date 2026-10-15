"""The worker supervisor: a control loop that never claims, and spawned task runners it keeps alive.

The runners here are tiny functions in a module written for the test, so a spawned process imports
nothing of CreMore (the worker package alone takes seconds to import) and the tests stay quick on every
platform. The real runner, cremore.cli.worker.task_runner, runs the loop tested in-process below.
"""

from __future__ import annotations

import importlib
import logging
import signal
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.db.task_store import TaskStore
from cremore.domain.models import ScanJob
from cremore.worker import JobWorker
from cremore.worker import supervisor as supervision
from cremore.worker import worker as worker_module
from cremore.worker.supervisor import (
    BACKOFF_CAP_SECONDS,
    STALE_SECONDS,
    UNHEALTHY_FAILURES,
    Repeater,
    Supervisor,
    run_task_loop,
)

RUNNERS = '''
import time


def idle(stop, liveness, slot):
    while not stop.value:
        liveness.value = time.monotonic()
        time.sleep(0.05)


def exits(stop, liveness, slot):
    liveness.value = time.monotonic()


def marks_once(stop, liveness, slot):
    liveness.value = time.monotonic()
    deadline = time.monotonic() + 120
    while not stop.value and time.monotonic() < deadline:
        time.sleep(0.05)


def adds(stop, liveness, slot, first, second):
    liveness.value = slot + first + second
'''


@pytest.fixture(scope="module")
def runners(tmp_path_factory):
    folder = tmp_path_factory.mktemp("runners")
    (folder / "cremore_test_runners.py").write_text(RUNNERS, encoding="utf-8")
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(folder))  # a spawned process starts with the parent's sys.path
        yield importlib.import_module("cremore_test_runners")
        sys.modules.pop("cremore_test_runners", None)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Control:
    """Stands in for the control loop's JobWorker."""

    def __init__(self):
        self.polls = self.beats = 0

    def poll_triggers(self):
        self.polls += 1

    def beat(self, path):
        self.beats += 1


def wait_for(condition, timeout=60.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def test_runners_run_in_their_own_processes_and_stop_after_the_task_in_hand(runners):
    supervisor = Supervisor(Control(), 2, target=runners.idle)
    supervisor.start()
    try:
        wait_for(lambda: all(runner.liveness.value for runner in supervisor.runners))
        processes = [runner.process for runner in supervisor.runners]
        assert len({process.pid for process in processes}) == 2
    finally:
        supervisor.shutdown()
    assert all(not process.is_alive() and process.exitcode == 0 for process in processes)  # stopped, not killed


def test_a_runner_that_dies_is_restarted_after_a_growing_pause(runners):
    clock = Clock()
    supervisor = Supervisor(Control(), 1, target=runners.exits, clock=clock)
    supervisor.start()
    runner = supervisor.runners[0]
    try:
        pauses, previous = [], None
        for _ in range(3):
            process = runner.process
            assert process is not None and process is not previous
            process.join(60)
            supervisor.check(clock())
            assert runner.process is None
            pauses.append(runner.restart_at - clock())
            clock.now = runner.restart_at - 0.01
            supervisor.check(clock())
            assert runner.process is None  # not before its pause is over
            clock.now = runner.restart_at
            supervisor.check(clock())
            previous = process
        assert pauses == [1.0, 2.0, 4.0]
        runner.process.join(60)
        runner.failures = 10
        supervisor.check(clock())
        assert runner.restart_at - clock() == BACKOFF_CAP_SECONDS
        # One that ran a while before it died starts the pauses over.
        clock.now = runner.restart_at
        supervisor.check(clock())
        runner.process.join(60)
        clock.now += BACKOFF_CAP_SECONDS
        supervisor.check(clock())
        assert runner.restart_at - clock() == 1.0
    finally:
        supervisor.shutdown()


def test_runners_that_keep_crashing_stop_the_heartbeat_until_one_lasts_a_minute(runners, caplog):
    clock, control = Clock(), Control()
    supervisor = Supervisor(control, 2, target=runners.exits, clock=clock)
    supervisor.start()
    beats = []
    try:
        with caplog.at_level(logging.INFO, logger="cremore.worker"):
            for _ in range(UNHEALTHY_FAILURES):
                for runner in supervisor.runners:
                    runner.process.join(60)
                supervisor.tick()  # both deaths seen: one more failure each, restarts scheduled
                beats.append(control.beats)
                clock.now = max(runner.restart_at for runner in supervisor.runners)
                supervisor.tick()  # both restarted
                beats.append(control.beats)
            # Every tick beat until both runners had crashed five times in a row; the last one did not.
            assert beats == list(range(1, 2 * UNHEALTHY_FAILURES)) + [2 * UNHEALTHY_FAILURES - 1]
            assert [r.levelname for r in caplog.records if "heartbeat file" in r.getMessage()] == ["ERROR"]
            # One runner that lasts a minute is enough: the worker scans again, so the heartbeat comes back.
            supervisor.target = runners.idle
            for runner in supervisor.runners:
                runner.process.join(60)
            supervisor.tick()
            marks = [runner.liveness.value for runner in supervisor.runners]
            clock.now = max(runner.restart_at for runner in supervisor.runners)
            supervisor.tick()
            wait_for(lambda: all(runner.liveness.value != mark for runner, mark in zip(supervisor.runners, marks)))
            clock.now += BACKOFF_CAP_SECONDS
            supervisor.tick()  # lasted a minute: failures cleared
            before = control.beats
            supervisor.tick()
            assert control.beats == before + 1
            assert any(r.levelname == "INFO" and "touched again" in r.getMessage() for r in caplog.records)
    finally:
        supervisor.shutdown()


def test_a_worker_whose_runners_keep_crashing_exits_for_the_orchestrator(runners, monkeypatch):
    monkeypatch.setattr(supervision, "EXIT_FAILURES", 1)  # the real bound only takes longer to reach
    supervisor = Supervisor(Control(), 1, target=runners.exits)
    with pytest.raises(SystemExit) as stopped:
        supervisor.run()
    assert stopped.value.code == 1
    assert all(not runner.process or not runner.process.is_alive() for runner in supervisor.runners)


def test_a_runner_gets_the_supervisors_target_arguments_after_its_own(runners):
    supervisor = Supervisor(Control(), 2, target=runners.adds, target_args=(10, 20))
    supervisor.start()
    try:
        for runner in supervisor.runners:
            runner.process.join(60)
        assert [runner.liveness.value for runner in supervisor.runners] == [30.0, 31.0]
    finally:
        supervisor.shutdown()


def test_a_runner_without_a_sign_of_life_for_30_minutes_is_replaced(runners):
    clock = Clock()
    supervisor = Supervisor(Control(), 1, target=runners.marks_once, clock=clock)
    supervisor.start()
    runner = supervisor.runners[0]
    try:
        stuck = runner.process
        wait_for(lambda: runner.liveness.value != 0.0)
        supervisor.check(clock())  # its one mark is seen now
        clock.now += STALE_SECONDS - 1
        supervisor.check(clock())
        assert runner.process is stuck and stuck.is_alive()
        clock.now += 2
        supervisor.check(clock())
        assert runner.process is None and not stuck.is_alive() and stuck.exitcode != 0
        clock.now = runner.restart_at
        supervisor.check(clock())
        assert runner.process is not None and runner.process is not stuck
    finally:
        supervisor.shutdown()


@pytest.mark.parametrize("stop_by", ["SIGTERM", "SIGINT", "request"])
def test_a_stop_ends_the_control_loop_and_then_its_runners(runners, stop_by):
    supervisor = Supervisor(Control(), 1, target=runners.idle)
    signum = getattr(signal, stop_by, None)
    before = signal.getsignal(signum) if signum else None

    def send():
        # The handlers are installed before the first runner starts.
        wait_for(lambda: supervisor.runners and supervisor.runners[0].liveness.value)
        if signum:
            signal.raise_signal(signum)
        else:
            supervisor.request_stop()  # Windows has no SIGTERM to send a process

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    supervisor.run()
    sender.join(5)
    process = supervisor.runners[0].process
    assert not process.is_alive() and process.exitcode == 0
    assert supervisor.worker.polls >= 1
    if signum:
        assert signal.getsignal(signum) is before


def test_the_control_loop_beats_runs_its_hooks_and_polls_but_never_claims(runners, tmp_path):
    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="inline", payload={"text": "nothing to find here"}))
    worker = JobWorker(repo)
    polls = []
    worker.poll_triggers = lambda: polls.append(True)
    clock = Clock()
    supervisor = Supervisor(worker, 1, target=runners.idle, heartbeat_path=str(tmp_path / "heartbeat"), clock=clock)
    calls = []
    supervisor.every(1.0, lambda: calls.append(clock()))
    supervisor.every(1.0, lambda: 1 / 0)  # a failing hook is logged and retried; the loop goes on
    for _ in range(5):
        supervisor.tick()
        clock.now += 0.5
    assert calls == [1000.0, 1001.0, 1002.0] and len(polls) == 5
    assert (tmp_path / "heartbeat").exists()
    assert repo.get_job(job.id).status == "QUEUED" and TaskStore(repo).list_for_run(job.id) == []


def test_a_task_runner_works_the_queue_without_polling_and_shows_it_is_alive(tmp_path):
    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="inline", payload={"text": "nothing to find here"}))
    worker = JobWorker(repo)
    worker.poll_triggers = lambda: pytest.fail("a task runner never polls the triggers")
    stop, liveness = SimpleNamespace(value=0), SimpleNamespace(value=0.0)
    passes = []
    process_next = worker.process_next

    def counted(poll=True):
        passes.append(poll)
        if len(passes) == 2:
            stop.value = 1
        return process_next(poll=poll)

    worker.process_next = counted
    run_task_loop(worker, stop, liveness, idle=0)
    assert passes == [False, False] and repo.get_job(job.id).status == "SUCCEEDED" and liveness.value
    assert worker.reports_identity is False  # the control loop's report stands for the worker
    # A long task's lease renewal marks the runner alive and leaves the control loop's heartbeat file alone.
    liveness.value = 0.0
    worker.beat(str(tmp_path / "heartbeat"))
    assert liveness.value and not (tmp_path / "heartbeat").exists()


def test_a_supervisor_needs_at_least_one_runner(runners):
    with pytest.raises(ValueError, match="WORKER_CONCURRENCY_INVALID"):
        Supervisor(Control(), 0, target=runners.idle)


def test_a_thread_beside_the_loop_runs_while_a_tick_is_busy_and_stops_with_the_runners(runners):
    stuck, calls = threading.Event(), []

    class Busy(Control):
        def poll_triggers(self):
            super().poll_triggers()
            stuck.wait(30)  # a slow maintenance pass or trigger poll

    supervisor = Supervisor(Busy(), 1, target=runners.idle)
    supervisor.alongside("probe", 0.01, lambda: calls.append(time.monotonic()))
    supervisor.start()
    ticking = threading.Thread(target=supervisor.tick, daemon=True)
    try:
        ticking.start()
        wait_for(lambda: supervisor.worker.polls == 1)
        before = len(calls)
        wait_for(lambda: len(calls) >= before + 3)  # the loop is stuck in its tick; the thread goes on
    finally:
        stuck.set()
        ticking.join(30)
        supervisor.shutdown()
    [repeater] = supervisor.repeaters
    assert not repeater.thread.is_alive()
    stopped = len(calls)
    time.sleep(0.05)
    assert len(calls) == stopped


def test_a_failing_thread_logs_only_the_failure_type_and_backs_off_without_ending(caplog):
    outcomes = [ValueError("synthetic provider text")] * 7 + [None, ValueError("synthetic provider text"), None]
    calls = []

    def hook():
        calls.append(True)
        outcome = outcomes[len(calls) - 1]
        if outcome is not None:
            raise outcome

    repeater = Repeater("probe", 1.0, hook)
    pauses = []

    def wait(seconds):
        pauses.append(seconds)
        if len(pauses) == len(outcomes):
            repeater.stopped.set()
        return repeater.stopped.is_set()

    repeater.stopped.wait = wait  # recorded instead of slept
    with caplog.at_level(logging.WARNING, logger="cremore.worker"):
        repeater._loop()
    # Each failure doubles the pause up to the cap; a success brings it back to the interval.
    assert pauses == [2.0, 4.0, 8.0, 16.0, 32.0, BACKOFF_CAP_SECONDS, BACKOFF_CAP_SECONDS, 1.0, 2.0, 1.0]
    assert "ValueError" in caplog.text and "synthetic provider text" not in caplog.text


def _settings(**overrides):
    return Settings(AUTH_MODE="local", API_TOKEN="0" * 32, FINGERPRINT_KEY="ab" * 32, **overrides)


def test_alerts_run_once_per_container_where_its_role_sends(monkeypatch):
    from cremore.alerts import delivery
    from cremore.cli import worker as cli
    from cremore.identity import machine

    supervised = []
    monkeypatch.setattr(machine, "start_keeper", lambda *args: None)
    monkeypatch.setattr(Supervisor, "run", lambda self: supervised.append(self))
    repo = InMemoryRepository()
    mixed, collector = (JobWorker(repo, settings=_settings(WORKER_EXECUTION_ROLE=role)) for role in ("mixed", "collector"))
    for worker in (mixed, collector):
        cli.serve(worker.settings, repo, worker)
    # The mixed worker's control loop sends, on a thread beside it; never a task runner. A collector never sends.
    [repeater] = supervised[0].repeaters
    assert (repeater.name, repeater.seconds, repeater.grace) == ("slack-alerts", 1.0, worker_module.ALERT_GRACE_SECONDS)
    assert supervised[1].repeaters == []
    assert set(worker_module.ALERT_ROLES) == {"mixed", "control"}
    passes = []
    monkeypatch.setattr(delivery, "deliver_pending", lambda repo, settings, stop=None: passes.append((repo, settings, stop)))
    repeater.hook()
    # Each pass is handed a stop that a shutdown sets at once, and so does the signal while the loop's tick is in hand.
    [(seen_repo, seen_settings, stop)] = passes
    assert (seen_repo, seen_settings, stop()) == (repo, mixed.settings, False)
    repeater.stopped.set()
    assert stop() is True
    repeater.stopped.clear()
    supervised[0]._on_signal(signal.SIGTERM, None)
    assert stop() is True


@pytest.mark.parametrize("stop_by", ["SIGTERM", "SIGINT"])
def test_the_control_process_sends_alerts_until_a_stop_lets_the_pass_in_hand_finish(monkeypatch, stop_by):
    signum = getattr(signal, stop_by)
    before = signal.getsignal(signum)
    monkeypatch.setattr(worker_module, "ALERT_SECONDS", 0.01)
    control = JobWorker(InMemoryRepository(), settings=_settings(WORKER_EXECUTION_ROLE="control"))
    passes, loops, stops, busy = [], [], [], []

    def deliver_alerts(stop=None):
        passes.append(threading.current_thread().name)
        stops.append(stop)

    def process_next(poll=True):
        # A long pass (a ticket sweep): the alert thread must learn of the signal before this returns.
        loops.append(poll)
        deadline = time.monotonic() + 5
        while not (stops and stops[-1]()) and time.monotonic() < deadline:
            time.sleep(0.01)
        busy.append(bool(stops) and stops[-1]())
        return False

    control.deliver_alerts = deliver_alerts
    control.process_next = process_next

    def send():
        wait_for(lambda: len(passes) >= 2 and loops)
        signal.raise_signal(signum)

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    control.run_forever(poll_interval=0.01)
    sender.join(5)
    # The passes ran on their own thread, and none after the loop ended; each was handed the stop, set once it did.
    assert set(passes) == {"slack-alerts"} and busy[0] is True and all(stop() for stop in stops)
    ended = len(passes)
    time.sleep(0.05)
    assert len(passes) == ended and signal.getsignal(signum) is before
