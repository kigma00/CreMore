# 연속 검사·성능·Slack 알림 구현 및 적용 보고서

검토 기준: 2026-10-06, `integration/saas-structure`. 아래는 현재 코드와 합성 검증의 결과다.
실제 고객 계정의 성능, 외부 알림 수신, 운영 배포 완료를 뜻하지 않는다.
인벤토리 수집과 콘텐츠 노출 검사는 별도 계약을 유지한다. IP 보강은 요청대로 제외했다.

## 1. 구현 결과

| 요청 | 구현 및 담당 위치 | 동작·한계 |
| --- | --- | --- |
| Notion 최초·재검사 가속 | `notion/backend/cremore_notion_provider/collectors/notion.py`, `requests.py` | Markdown 우선, 3개 fetch worker, 탐지된 페이지만 블록 위치 보강. 수정 시각·실패 목록 기반 증분 검사. 변경 중인 페이지는 완료로 처리하지 않음 |
| 여러 worker의 Notion API 제한 | `cremore/db/scan_store.py`, `collectors/base.py`, `worker/runtime.py` | 같은 DB·token·origin의 2.5회/초 간격과 Retry-After 공유. 별도 설치·다른 token의 workspace 전체 합산 제한은 아님 |
| 공통 문서 추출 | `cremore/scanning/extraction/`, `service.py`, `domain/mapping.py` | 아래 문서 유형을 메모리에서 추출해 기존 탐지기로 전달. parser에 비밀 환경변수·상속 핸들을 전달하지 않음. 시간·메모리·압축 해제 예산 적용 |
| 추출 실패의 정확한 상태 | `db/scan_state.py`, `api/source_presenters.py`, `scanning/scope.py`, 콘솔 수집 현황 | 미지원·암호화·잘림·예산 초과는 부분 수집과 안전한 이유 코드로 표시. 미검사 파일을 깨끗한 완료·삭제 근거로 쓰거나 성공 캐시로 저장하지 않음 |
| 전체·변경분 독립 일정 | `domain/models.py`, `onboarding/sessions.py`, `scanning/triggers.py`, 콘솔 연결/대상 편집 | 신규 연결에 일 1회 전체 검사를 제안. 전체는 0(끔) 또는 60~1440분, 변경분은 0(끔) 또는 5~43200분. 서로 독립적으로 변경·비활성화 가능 |
| 기존 연결 호환 | API·온보딩·worker의 같은 profile 계약 | 기존 전체 주기의 null은 이전 일일 reconciliation 의미를 유지. 편집에서 생략한 주기를 덮어쓰지 않음. 주기는 접근 승인을 늘리지 않음 |
| 무인 자동 실행 | 기존 worker의 지속 트리거 polling | 사용자 로그인·열린 브라우저 없이 실행. 설치 잠금·현재 승인·중지·취소·예산은 매 실행/요청에서 유지 |
| 변경 이벤트 | `scanning/changes.py`, `triggers.py`, 공급자 변경 조회기 | 아래 공급자 표의 이벤트·변경 조회기를 기존 승인 scope 작업으로 변환. 삭제 이벤트 자체로 제거 완료를 판정하지 않음 |
| Notion 공식 webhook | 공급자 `webhooks.py`, 플랫폼 `scanning/notion_webhooks.py`, 전용 API/Next 경로·설정 카드 | 관리자 구독 검증과 원문 HMAC, identity·시각·scope 검사 후 영속 접수. 새 페이지 이벤트는 선택 범위를 확대하지 않음 |
| 동시 검사·실행 중 새 변경 | `db/task_store.py`, migration 11, worker runtime | 독립 연결은 worker 수에 따라 병렬. 같은 연결은 직렬화. busy 시 폐기하지 않고 대기열에 저장. 기존 리스·fencing·취소·공정성 유지 |
| Slack 발견 알림 | `cremore/siem/`, `packages/cremore-siem-slack`, repository/SQL 노출 저장 | 새 발견·새 노출 위치·제거 후 재출현을 같은 저장 트랜잭션의 outbox에 기록. 동일 위치의 변화 없는 재탐지는 추가 알림을 만들지 않음 |
| Slack 필수 정보·링크 | 출력 플러그인의 고정 projection | 심각도·유형·발급/발견 공급자·시각·내부 ID·로그인 필요한 상세 링크. 원문·토큰·파일명·제목·digest를 전송하지 않음 |
| Slack 장애 복구 | 기존 outbox lease·ACK·재시도·보류 상태 | 재시도·재시작 후 전송 지속. 수신 후 응답 유실 시 중복 가능(at-least-once). 무손실·즉시·exactly-once를 무조건 보장한다고 표시하지 않음 |

## 2. 모든 등록 콘텐츠 공급자 대조

`cremore/sources/registry.py`의 실제 등록 목록을 기준으로 대조했다. 각 공급자의 읽기 승인,
scope·예산·불완전 수집 계약은 그대로 사용한다. IdP와 발급 인벤토리 전용 공급자는 콘텐츠 스캐너가 아니다.

| 공급자 | 최초/반복 읽기 최적화 | 자동 변경 경로 | 이번 보완 |
| --- | --- | --- | --- |
| AWS S3 | LIST revision(ETag·크기·수정 시각), 동일 위치 결과 재사용, 선택적 Inventory 보고서 | SQS의 S3/EventBridge/CloudTrail 알림·예약 | 공통 문서 추출·독립 전체 일정·영속 이벤트·병렬 연결에 통합 |
| Google Cloud Storage | generation으로 같은 위치의 본문 생략 | Pub/Sub storage 알림·예약 | 동일 공통 경로 및 등록 타입 `gcp` 검사 |
| Azure Blob Storage | ETag로 같은 위치의 본문 생략 | Service Bus의 Event Grid/CloudEvents·예약 | 동일 공통 경로 |
| GitHub | 고정 tree/blob SHA, 허용된 전체 repo의 archive + 검증/누락 보완 | head/compare 변경 조회, 중계 큐 push·예약 | 동일 공통 경로 |
| GitLab | blob ID 기반 지연 다운로드·동일 내용 재사용 | commit/merge-base/compare, 중계 큐 push·예약 | 동일 공통 경로 |
| Bitbucket Cloud / Data Center | 고정 commit+경로 기반 지연 다운로드 | diffstat/changes, 중계 큐 push·예약 | 기존 누락된 revision cache 연결. commit을 blob ID로 간주하지 않음 |
| Azure DevOps Git | blob ID 기반 지연 다운로드 | refs/diffs, Service Bus git.push·예약 | 동일 공통 경로 |
| Azure DevOps TFVC | 현재 수집 계약의 버전·경로 조회 | 예약 검사 | 전용 변경 조회기를 있다고 표시하지 않음 |
| Confluence | 페이지 변경 시각, 첨부 ID/버전 | CQL 변경 조회·예약 | 첨부 문서의 공통 추출 |
| Notion | Markdown, 3 workers, 수정 시각·실패 재검사 | 서명된 공식 webhook·예약 | 본문/블록 보강 통합, DB 공유 rate limit, 설정·공개 ingress |
| 회사 website | 확인된 도메인·승인된 시작 URL의 bounded fetch | 예약 검사 | PDF/Office/HWP MIME을 버리던 필터 제거. 임의 문서 링크 추적을 추가하지 않음 |

변경 조회·큐·webhook 설정은 [변경 감지 스캔](CHANGE_FEEDS.md), [Notion 알림](NOTION_CHANGE_WEBHOOKS.md)을 따른다.
공급자의 API가 제공하지 않는 전체 과거 이벤트를 복원하거나 구독·권한을 자동 부여하지 않는다.

## 3. 문서 유형과 안전한 처리

지원: UTF 계열 텍스트/설정 파일, PDF의 텍스트층, DOCX/PPTX/XLSX, Word DOC(97~2003),
HWP 5/HWPX, ODF, RTF, ZIP/TAR/gzip/bzip2/xz 안의 지원 문서. 파일명만 신뢰하지 않고 형식도 확인한다.
같은 위치를 유지하며 추출된 문서의 내부 항목·페이지 등 안전한 근거만 연결한다.

이미지·스캔 PDF의 OCR, 암호화/DRM 파일, HWP 3, 구형 XLS/PPT, 7z/RAR 및 지원하지 않는
내장 개체는 명시적인 미지원/부분 수집이다. 바이너리 전체에 문자열 검색을 해 놓고 문서를
완독했다고 처리하지 않는다. 상세 범위와 제한은 [문서 검사](DOCUMENT_SCANNING.md)를 따른다.

기본 예산: 입력 50 MiB, 누적 압축 해제 64 MiB, 개별 멤버/추출 텍스트 16 MiB,
512개 멤버, PDF 500페이지, 중첩 3단계, parser 15초/512 MiB.
parser 프로세스 제한은 OS 수준 보안 sandbox가 아니다. [격리 배포](POST_COMPROMISE_CONTAINMENT.md)의
비root·read-only·capability 제거·네트워크/역할 분리까지 적용해야 피해 범위를 더 줄일 수 있다.

## 4. 이번에 측정한 성능

모두 합성 공급자와 실제 탐지 경로다. 실제 계정 속도나 API 요금을 측정한 수치가 아니다.

| 실험 | 이전 전략/최초 | 개선 전략/재검사 | 확인 |
| --- | ---: | ---: | --- |
| Notion 500페이지, 요청당 가짜 지연 5ms, pacing 제외 | 순차 블록 17.4200초·3,005요청 | Markdown/3worker 3.8621초·1,305요청 | 두 전략 모두 50개 탐지, 최대 동시 fetch 1→3 |
| S3 10,000개 × 4KiB, 1% 변경, 1회 측정 | 26.2726초·10,000 GET·40,960,000바이트 | 0.2647초·100 GET·409,600바이트 | 각 10 LIST, 변경 없는 9,900개 본문/엔진 생략 |

실행 명령:

```bash
python -m scripts.benchmark_notion_markdown --pages 500 --latency-ms 5
python -m scripts.benchmark_s3_scan --variant worktree --objects 10000 --repeats 1
```

Notion의 2.5요청/초를 적용한 요청 간격 하한은 각각 1,201.6초와 521.6초다.
현재의 변경 중 페이지 검증·블록 근거 보강을 유지하는 조건에서 ‘500페이지 4분’ 또는
‘변경분 무조건 30초’를 주장할 수 없다. 페이지 수·명시적 선택 방식·429·수정 비율에 따라 달라진다.
S3는 네트워크 지연과 실제 DB 부하를 재현하지 않은 단일 실행이다.

## 5. 배포 시 추가로 필요한 설정

1. **같은 버전의 API·web·worker·SIEM으로 배포**한다. 운영 DB 백업/복원 검증 후 migration 11과
   additive scope/pacing schema를 migration 계정으로 적용한다. 구버전 writer와 섞지 않는다.
   격리 DB 역할은 새 `scan_request_pacing` 권한을 포함해 다시 적용한다.
2. **무인 신원**을 설치 환경에 맞게 제공한다. EC2 role, EKS workload identity, 온프레미스/K8s
   federation 또는 고정된 AWS Roles Anywhere helper를 사용한다. Roles Anywhere 인증서·키·trust anchor·profile/role ARN과
   helper hash는 운영자가 준비해야 한다. 대시보드에 임의 `credential_process` 명령을 입력받지 않는다.
   [무인 운영](UNATTENDED_DEPLOYMENT.md)의 신원 갱신/재시작 절차를 따른다.
3. **자동 검사**는 승인된 콘텐츠 범위와 설치의 스케줄 스위치를 켠다. 전체/변경분 주기를 선택한다.
   실행 병렬도는 실제 worker 수와 DB/CPU/API 예산에 맞춰 늘린다. 한 worker만 운영하면서 모든 연결이 동시에
   실행된다고 기대하지 않는다. 로그인 세션은 수집 실행 조건이 아니다.
4. **변경 이벤트**는 선택 기능이다. 공급자 큐·전달·권한 또는 Notion webhook 검증과 정확한 POST
   ingress 예외를 구성한다. 큐는 전용이어야 한다. 이벤트를 끄더라도 예약·수동 검사는 가능하다.
5. **Slack**은 보안팀 채널의 Incoming Webhook, exporter 전용 Secret, 신뢰한 dashboard HTTPS origin,
   destination 설정과 exporter 실행이 필요하다. [Slack 설정](SLACK_ALERTS.md)의 ACK/보류 상태를 확인한다.
   이번 검증에서는 실제 채널로 메시지를 보내지 않았다.
6. **침해 피해 제한 모드**는 기본 자동 활성화되지 않는다. 역할별 DB/프로세스/비밀/네트워크 분리,
   API 공개키 봉인·worker 개인키·독립 조치 승인 키, ingress/egress 정책을 운영자가 배치해야 한다.
   [구현 기록](CONTAINMENT_IMPLEMENTATION_2026-10-06.md)의 이관 절차를 따른다.
   호스트 root 권한까지 탈취되었을 때 애플리케이션 코드만으로 완전한 보호를 보장하지 않는다.

## 6. 기존 사용 절차의 변화

기존의 계정 인증 → 권한 점검 → 범위 선택 → 승인 흐름과 수동 검사 버튼은 유지된다.
추가된 것은 전체/변경분 검사 주기, 문서 읽기 한계 표시, Notion 변경 알림 설정 카드다.
Slack destination 하나가 공급자 구분 없이 모든 지원 콘텐츠의 새 노출 이벤트를 받는다.
별도 SaaS별 Slack 연결은 필요하지 않다. 격리 모드를 적용하면 파괴적 조치는 독립 서명 승인을 거친다.

## 7. 실제 검증 기록

- 넓은 Python 회귀: 1,312개 통과 후 7개 실패를 확인했다. 새 revision 근거가 없는 Notion fake,
  기존 busy/defer 가정, 구형 IAM 평가 fixture, 동일 생성 시각의 작업 순서 가정이 원인이었다.
  해당 네 파일 재검사 173개 통과, 추가한 legacy 위험 근거 2개가 예상 문구 차이로 실패했다.
  문구 정정 후 관련 memory/SQLite 4개 모두 통과했다. 제품의 revision·권한 근거 기준은 낮추지 않았다.
- 격리 PostgreSQL 17의 pacing/webhook/일정/동시성: 106개 통과.
- Linux 설치 wheel, 네트워크 없음·비root·read-only 컨테이너: 139개 통과·7개 skip.
  `/tmp` noexec 때문에 합성 Roles Anywhere helper 실행 검사 1개가 실패했다.
  테스트 helper만 실행 가능한 별도 tmpfs로 옮겨 Roles Anywhere 18개 통과. 운영의 noexec 설정은 바꾸지 않았다.
  Linux suite의 PostgreSQL skip은 이 network-none 컨테이너에 DB URL을 주지 않은 결과이며 별도 PG 검사로 보완했다.
- 콘솔 실브라우저: auth-first, integration-edit, literal-scope, Notion webhook setup 통과.
  한국어/영어·light/dark·360px·키보드·서명 전 활성화 차단·서버 거절/재시도를 포함한다.
- 웹 단위 검사, TypeScript, production build, 변경 Python Ruff 및 diff 검사는 최종 실행 결과를 아래에 기록한다.
- 배포 template 검사 최초 172개 통과/1개 실패(SIEM 전용 Slack 환경변수 예상 목록), fixture 보완 후 해당 검사 통과.
  Slack 비밀이 API/collector에 전달되지 않는 것도 확인했다.
- 운영 서버 배포, 실제 Notion 구독, 실제 Slack 수신, 실제 대규모 공급자 성능 및 회사 K8s 네트워크는
  이번 합성 검사에서 실행하지 않았다. 구성 코드와 실제 적용/실환경 검증을 구분한다.

최종 실행 결과: 웹 단위 293개 통과, TypeScript 통과, Next production build 통과,
변경 Python Ruff 통과, `git diff --check` 통과. 이전 실행의 넓은 Python 실패는 위의 해당 회귀 재실행으로 확인했다.
