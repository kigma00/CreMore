# Native QA only, preserved from GitLab 744c48c. The deployed worker never imports this module.
"""독립 QA 참조 수집기의 collect 진입점."""

import argparse
import json
import logging
import os
import sys
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path

from ..collector import Collector
from ..config import Config
from ..http import Client, CollectionError
from ._qa_storage import Store

LOG = logging.getLogger(__name__)


def export_failure(store: Store | None, code: str):
    """시작·내부 오류 때도 이미 저장한 관찰을 내보내고 완료 판정을 막는다."""
    if store is None:
        return
    try:
        with store.db:
            store.set_setting("fatal_error", {"code": code})
        store.export()
    except Exception:
        LOG.exception("stage=emergency_export code=EXPORT_FAILED SQLite 상태를 보존했습니다.")


def parser() -> argparse.ArgumentParser:
    """명령행 옵션을 정의한다. 인증 원문을 argv에 전달하는 옵션은 두지 않는다."""
    root = argparse.ArgumentParser(
        description="GitLab 1번 유형: 기존 Token 메타데이터 JSON 배열 수집"
    )
    commands = root.add_subparsers(dest="command", required=True)
    command = commands.add_parser("collect", help="실제 API 수집")
    command.add_argument("--output", type=Path, required=True, help="실행별 출력 디렉터리")
    command.add_argument(
        "--resume", action="store_true",
        help="같은 조회 범위·계정으로 중단·실패 위치에서 재개(전송 설정 조정 가능)",
    )
    command.add_argument(
        "--previous", type=Path, help="이전 inventory.json 또는 기존 inventory.jsonl과 대조"
    )
    command.add_argument("--config", type=Path, required=True, help="비밀값 없는 JSON 설정")
    command.add_argument(
        "--token-env", default="GITLAB_TOKEN", help="수집용 인증을 담은 환경 변수 이름"
    )
    return root


def main(argv=None) -> int:
    """실행·출력·종료 코드를 통합한다. 0=완주, 2=부분 수집, 1=설정/시작 실패."""
    args = parser().parse_args(argv)
    os.umask(0o077)
    store = None
    file_handler = None
    resources = ExitStack()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s:%(lineno)d %(message)s"
    )
    try:
        if args.previous and not args.previous.is_file():
            raise ValueError("--previous 파일이 없습니다.")
        config = Config.load(args.config)
        token = os.environ.get(args.token_env, "").strip()
        if not token or "\n" in token or "\r" in token:
            raise ValueError("수집용 Token 환경 변수가 비어 있거나 형식이 잘못되었습니다.")
        client = Client(config, token)
        # 같은 디렉터리에 두 실행이 기록하면 체크포인트가 섞인다. 프로세스 잠금으로 차단한다.
        args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        # 예외 처리의 긴급 export와 DB 종료까지 잠금을 유지한다.
        lock = resources.enter_context((args.output / ".collector.lock").open("a+"))
        import fcntl  # macOS/Linux 대상. 네트워크 수집과 별개인 로컬 파일 잠금이다.

        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("같은 출력 디렉터리에서 다른 수집기가 실행 중입니다.") from None
        store = Store(args.output, config.fingerprint(), args.resume)
        with store.db:
            store.set_setting("config", asdict(config))
            store.set_setting("base_url", config.base_url)
            store.set_setting("collection_mode", args.command)
        file_handler = logging.FileHandler(args.output / "collector.log", encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s:%(lineno)d %(message)s")
        )
        logging.getLogger().addHandler(file_handler)
        interrupted = False
        try:
            Collector(config, client, store).run()
        except KeyboardInterrupt:
            interrupted = True
            LOG.warning(
                "stage=shutdown code=INTERRUPTED 남은 작업은 --resume으로 재개할 수 있습니다."
            )
        result = store.export(args.previous)
        print(
            json.dumps(
                {
                    "mode": args.command,
                    "output": str(args.output.resolve()),
                    "inventory_records": result["inventory_records"],
                    "tasks": result["tasks"],
                    "requests_this_process": client.requests,
                    "retries_this_process": client.retries,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 130 if interrupted else 0 if result["all_scheduled_tasks_complete"] else 2
    except (ValueError, OSError, CollectionError) as exc:
        # 임의 응답 본문을 출력하지 않는다. JSON 구문 오류만 별도 줄/열을 안내한다.
        if isinstance(exc, json.JSONDecodeError):
            message = f"JSON 구문 오류: line={exc.lineno}, column={exc.colno}"
        else:
            message = str(exc)
        LOG.error(
            "stage=startup_or_export code=%s message=%s",
            getattr(exc, "code", type(exc).__name__),
            message,
        )
        export_failure(store, getattr(exc, "code", type(exc).__name__))
        return 1
    except Exception:
        # 예상하지 못한 구현 오류는 traceback의 파일·줄 위치를 보존한다(로컬 변수 덤프 없음).
        LOG.exception(
            "stage=internal code=UNEXPECTED_ERROR 구현 오류입니다. collector.log를 확인하세요."
        )
        export_failure(store, "UNEXPECTED_ERROR")
        return 1
    finally:
        if store:
            store.close()
        if file_handler:
            logging.getLogger().removeHandler(file_handler)
            file_handler.close()
        resources.close()


if __name__ == "__main__":
    sys.exit(main())
