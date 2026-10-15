"""Fixed resource-limited parser; never intentionally opens files, URLs or programs.

This is not an OS security sandbox: deployment isolation still applies.
"""

import json
import logging
import os
import sys
import warnings


def memory_limit(amount):
    if os.name == "posix":
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (amount, amount))
        return None
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", wintypes.DWORD), ("min_set", ctypes.c_size_t),
                        ("max_set", ctypes.c_size_t), ("active", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                        ("scheduling", wintypes.DWORD)]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        job = kernel.CreateJobObjectW(None, None)
        limits = ExtendedLimits()
        limits.basic.flags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
        limits.process_memory = amount
        if not job or not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise OSError("parser memory limit unavailable")
        if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
            raise OSError("parser memory limit unavailable")
        return job  # retain for this process lifetime
    return None


def frame(result):
    """The parser's only output: a fixed-field JSON header line, then the text bytes."""
    response = {"format": result.format, "complete": result.complete,
                "reason": result.reason, "size": len(result.data)}
    return json.dumps(response).encode("ascii") + b"\n" + result.data


def main():
    from contract import ExtractionLimits

    # Suppress parser diagnostics before loading any parser. Error messages may
    # contain content; only the fixed status vocabulary crosses back to worker.
    logging.disable(logging.CRITICAL)
    warnings.simplefilter("ignore")
    header = sys.stdin.buffer.readline(4096)
    request = json.loads(header)
    limits = ExtractionLimits(**request["limits"])
    memory_job = memory_limit(limits.memory_bytes)
    data = sys.stdin.buffer.read(limits.input_bytes + 1)
    if len(data) > limits.input_bytes:
        return
    from formats import parse

    sys.stdout.buffer.write(frame(parse(data, request["suffix"], limits)))
    sys.stdout.buffer.flush()
    del memory_job


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 -- never emit parser tracebacks or document text
        # The parent maps a nonzero exit to a safe incomplete result. In
        # particular, no memory-limit/decoder exception is printed to stderr.
        sys.exit(1)
