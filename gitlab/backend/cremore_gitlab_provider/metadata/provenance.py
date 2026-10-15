"""실행에 사용한 코드의 버전·파일 해시를 기록한다. Git 상태는 조회만 한다."""

import hashlib
import subprocess
from pathlib import Path

from . import __version__
from .model import stable_id


def code_provenance() -> dict:
    """미커밋 코드도 파일 해시로 구분한다. 토큰·환경 변수·Git 원격 URL은 읽지 않는다."""
    package = Path(__file__).resolve().parent
    files = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(package.glob("*.py"))
    }
    result = {
        "collector_version": __version__,
        "code_root": str(package.parent),
        "source_files_sha256": files,
        "source_digest": stable_id(files),
        "git": {"status": "unavailable"},
    }
    try:
        # .git이 없는 설치본도 코드 해시는 남는다. 어떤 Git 변경 명령도 실행하지 않는다.
        repository = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=package,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=package,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
        relative = str(package.parent.relative_to(repository))
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all", "--", relative],
            cwd=repository,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout
        result["git"] = {
            "status": "observed",
            "head": head,
            "collector_has_uncommitted_changes": bool(status.strip()),
        }
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return result
