# 침해 이후 피해 제한 구현·검증 기록

기준: 2026-10-06, `integration/saas-structure`. 기존 기능 기준점 `5a988673` 이후 변경이다.
운영 배포 완료 보고가 아니다. [설계·이관·잔여 경계](POST_COMPROMISE_CONTAINMENT.md)를 함께 읽는다.

## 구현 대조

| 요구 | 구현 및 근거 | 외부 조건 |
| --- | --- | --- |
| API에서 수집 비밀 복호화 권한 제거 | `secretstore/isolation.py`, 공개키 v3 admission·authority 바인딩 | 역할별 개인키 파일을 실제로 분리 배포 |
| 수집·조치 분리 | `worker/isolation.py`, SQL/memory claim 역할 분류, 별도 worker 시작 | 읽기/쓰기 cloud IAM과 workload identity 분리 |
| 독립 실행 승인 | `remediation/authorization.py`, 정확한 계획·설정 digest·만료·nonce, 웹 파일 교환 | 승인 개인키는 앱 서버 밖에서 보호 |
| 승인 재사용 차단 | `db/task_store.py`, 실행 시작과 같은 transaction에서 insert-only nonce 소비 | migration/runtime 계정 분리 |
| 기존 비밀 이관·회전 | `secretstore/migrate.py`, 원자적 재봉인·미분류 참조 거절·재실행 멱등 | 모든 writer 중지·검증된 백업, 기존 지문 키 보존 |
| 키 생성 실수 방지 | `secretstore/provision.py`, context 정규화·역할별 RSA·제어 키·외부 Ed25519, 덮어쓰기 거절 | 오프라인 보호 장비, Windows DACL 별도 확인 |
| DB 런타임 DDL·감사 변경 제한 | `db/privileges.py`, `db/startup.py`, 테이블/열 권한과 읽기 전용 schema 검사 | 독립 DB 관리자와 migration 접속정보 |
| 온보딩·수집 기능 호환 | `onboarding/credential_access.py`, 현재 owner·child·목적·대상 고정; content/metadata/Vault/접근자 조사에 적용 | 기존 scope/lease/cancellation 유지 |
| AWS 조회·기계 신원 | `coverage/aws_requests.py`, collector 작업으로 전환; API는 결과 polling, IdP test도 collector 큐 | 실제 공급자 접근·토큰 갱신 설정 필요 |
| 컨테이너 및 네트워크 구성 | `deploy/helm`, `deploy/compose/isolated` 역할별 DB·키·신원·제한된 egress 설정 | CNI/호스트 방화벽이 정책을 실제 강제해야 함 |
| 외부 증적·회수 절차 | 기존 heartbeat/chain anchor 재사용, `deploy/siem/containment` 수신기 경보 예시와 WORM 계약 | 수신기 규칙 배포·독립 보관 설정은 운영자가 적용 |

## 실제 실행한 검사

각 행은 독립 실행 결과다. 서로 겹치는 테스트가 있으므로 수를 더해 고유 검사 수로 보고하지 않는다.

| 검사 | 결과·범위 |
| --- | --- |
| Linux/PostgreSQL 통합 | **146 passed, 0 skipped**. PG 17.11 일회용 `cremore_test`, 실제 별도 DB 역할, DDL·감사 수정 거절, 정상 수집·리스·SIEM, 동시 nonce 한 번 소비, 봉인 이관, Linux 키 파일 권한, 온보딩·machine 경로 |
| focused Windows 통합 | **91 passed**. 신규 bound content/metadata·machine 흐름, 실행 역할, 독립 승인, AWS read bridge, 키 provision |
| 최종 machine/context 보완 | **43 passed**. 정규화·지원 목적 거절, 이전 revision 신원 안내 배제, machine 및 온보딩 회귀 |
| 공급자 경계 독립 실행 | **73 passed**. 봉인 길이 검증에 따른 registry import 회귀 수정 후 실행 |
| SIEM 회귀 | **235 passed, 3 skipped**. 기존 출력 계약·재시도·재시작과 강화 모드의 부적절한 DB 거절 검사. Windows 실행에서 opt-in PostgreSQL 3개는 skip |
| SIEM PostgreSQL 보완 | Linux에서 PostgreSQL·동시 최초 writer 선택 검사 **8 passed, 13 deselected**. 위 skip 경로를 별도 환경에서 확인 |
| 웹 단위 | **290 passed, 0 skipped**. polling·중단·변경 요청 재발송 금지·서명 파일 검증·이전 업로드 경합·기계 신원 상태 |
| 웹 타입·배포 빌드 | `tsc --noEmit`, production build 통과 |
| Chrome 합성 흐름 | **3/3 통과**: 인증 목적 구분, 기존 삭제 흐름, 독립 승인(실행/긴급/재확인, KO/EN·light/dark·좁은/넓은 화면) |
| 배포 모듈 검사 | 기존 Helm/Compose 110, 신규 격리 Helm 9, OIDC 후속 관련 3, 독립 Compose 53 통과. 일부가 중복이며 최종 통합 렌더도 별도로 확인 |
| wheel | `uv build --wheel --offline` 성공. 새 런타임 모듈의 wheel 포함 확인. 이 wheel의 별도 신규 환경 설치 검사는 하지 않음 |
| 정적 검사 | 변경 Python의 Ruff, 최종 `git diff --check`와 변경 경계 검토 |

통합 체크 목록은 로컬 `.unlazy/containment-20261006`에 보관하며 저장소에는 machine-specific
승인·실행 상태를 커밋하지 않는다. 최초 checker 기본 120초 제한으로 일부 큰 suite가 중단되어
제한 시간을 늘려 재실행했다. 이 중단 결과를 통과 증거로 사용하지 않는다.
최종 통합 소스에서 비밀/실행/DB 세 영역을 독립 재검증하고, Compose/Helm 통합 렌더와
온보딩·machine·소유자 조사·source 계약 회귀도 통과했다.

PostgreSQL 검사는 내부 Docker 네트워크의 tmpfs DB를 사용했고 host port를 공개하지 않았다.
테스트의 `localhost/cremore_test/PG16+` 가드를 유지했다. Linux 검사 컨테이너에는 통합 root의
`cremore` 패키지만 read-only로 mount했고 설치된 나머지 라이브러리를 사용했다. 공급자 신원이나
실제 발견된 비밀을 사용하지 않았다. Windows 실행에서 선택적 PostgreSQL 검사가 skip되는 것은
위의 실제 Linux PostgreSQL 검증과 구분한다. Starlette deprecation과 SQLite expression-index
reflection warning은 기록했고 실패로 숨기지 않았다.

## 미실행 및 운영 통합

- 실제 AWS/GCP/Azure/IdP/PAT 인증·폐기·rotation, 실티켓·SIEM 발송은 이번 검사에서 실행하지 않았다.
- 회사 Kubernetes/CNI·온프레미스 방화벽과 IAM 정책 강제, 실제 TLS/OIDC 통합·WORM 보관·경보 전달은 미검증이다.
- Splunk 예약 검색은 수신기용 구성 예시이며 실제 Splunk 엔진에서 실행하지 않았다.
- 전체 브라우저 suite와 전체 저장소 pytest 대신 변경 경계 및 관련 회귀를 실행했다.
- 이번 변경을 운영 서버에 활성화하거나 운영 DB·비밀을 이관하지 않았다. 기존 테스트 사이트의 데이터와 로그인 설정은 유지했다.
- host-root/cluster-admin, 조치 worker의 쓰기 신원 자체 탈취, HMAC 키 보유자의 새 감사 위조까지 막았다는 주장은 하지 않는다.

운영 적용 전에는 [이관 순서](POST_COMPROMISE_CONTAINMENT.md#기존-설치-이관과-복구)에 따라
분리된 배포에서 실제 최소 권한·갱신·재시작·수신기 도착을 검증해야 한다.
