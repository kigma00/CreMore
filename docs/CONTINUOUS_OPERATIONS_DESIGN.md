# 통합 온보딩·24시간 운영·IdP·변경 감지 스캔 설계안 (제안)

상태: **구현 중**, 2026-09-28. 2026-09-27에 정한 결정 13건과 코드 대조 검토를 반영한 설계이며([9절](#9-결정-사항-2026-09-27)),
`integration/saas-structure`에서 단계별로 구현한다. 단계별 구현·검증 상태는 [10절](#10-구현-현황)에 적는다.
공통 인증·API·DB·배포·SIEM 계약을 바꾸는 항목은 [AGENTS.md](../AGENTS.md)의 공통 변경 절차를 따른다.

## 0. 요약

한 번 같은 방식으로 연결하면, 사람 없이 24시간 바뀐 것을 몇 분 안에 잡아 SIEM에 보내고,
감시가 약해지거나 퇴사자의 자격증명이 남아 있으면 그것도 SIEM에 알리는 운영 형태를 목표로 한다.

| 갈래 | 한 줄 설명 | 주로 맡는 목표 |
| --- | --- | --- |
| B. 24시간 운영 | 연결 상태를 하나의 모델로 보고, 감시 공백을 SIEM에 알리며, SIEM 전송을 상시 운영한다 | 무중단, 감시 공백 가시화 |
| IdP | 사람은 IdP로 로그인하고, 기계는 비밀 없는 워크로드 신원으로 접근하며, 퇴사자의 남은 자격증명을 찾는다 | 사람 세션과 수집의 분리 |
| C. 변경 감지 스캔 | 바뀐 것만 몇 분 안에 검사하고, 하루 한 번 전체를 대조한다 | 속도, 정확성 |
| A. 통합 온보딩 | 모든 공급자를 같은 4단계 마법사로 연결하고, 공급자당 연결 하나를 여러 용도가 공유한다 | 일관성 |

권장 순서는 B → IdP → C → A다. B가 모든 갈래의 토대이고, A는 앞 단계가 만든 공통 모델 위에 화면을 통일한다.
기업이 쓰는 어떤 금고와도 대조할 수 있게 하는 범용 금고 연결(4.7)은 1단계 바로 다음에 구현한다.

## 1. 배경과 목표

요구는 다음과 같다. 공급자마다 다른 온보딩을 통일한다. 세션·자격증명 만료로 수집이 멈추지 않게 한다.
SIEM과 24시간 연동한다. 기업의 IdP(Okta, Keycloak, Entra ID 등)를 전제로 한다. 주기 스캔과 변경 감지 스캔을 지원한다.
퇴사자의 자격증명을 찾아 준다.

| 목표 | 확인 방법 |
| --- | --- |
| G1. 운영 배포에서 사람 세션에 의존하는 수집 경로가 없다 | 연결마다 갱신 방식(자동·수동·사람 세션)을 기록하고, 운영 배포에서 사람 세션 방식이면 경고 |
| G2. 모든 연결이 같은 인증 상태·만료 경고를 가진다 | 콘텐츠·관리정보·금고·AWS 계정 연결이 같은 상태 필드를 반환 |
| G3. 감시 공백이 SIEM에 도착한다 | 인증 실패, 수집 실패, 데이터 오래됨, 플랫폼 중단이 운영 이벤트로 전달 |
| G4. 변경은 조회 주기 안에 검사되고, 놓친 것은 하루 안에 메워진다 | 변경 조회 주기(기본 5분 제안)와 일일 전체 대조 |
| G5. 새 공급자도 같은 4단계로 연결된다 | 공급자 설명서(descriptor)만 추가해 마법사가 동작 |
| G6. 퇴사 처리 후 퇴사자의 자격증명이 판정된다 | IdP 상태 변경 이후 판정 결과와 이벤트 생성 |

하지 않는 것: 자동 폐기를 기본으로 켜지 않는다. 고객 인프라 설정(버킷 알림, 이벤트 선택기, 웹훅 설정)을 바꾸지 않는다.
인사 정보(퇴사 사유 등)를 받지 않는다. 특정 IdP나 SIEM 제품을 강제하지 않는다.

## 2. 현재 상태 (코드 기준)

| 영역 | 있는 것 | 없는 것 |
| --- | --- | --- |
| 온보딩 | 연결 창구 네 곳(연결된 소스, 공급자 관리 목록, AWS 계정 역할 연결, 금고 보관 대조). schema 2 descriptor의 인증 방식·비밀 역할·선택 역할·필요 권한([GitHub descriptor](../github/backend/cremore_github_provider/metadata/descriptor.py), [등록](../cremore/coverage/providers/__init__.py)). 콘텐츠 source는 [별도 registry](../cremore/sources/registry.py) | 공통 마법사, 공급자당 공유 연결. 같은 공급자를 용도별로 두 번 등록 |
| 인증 상태 | 콘텐츠 연결의 READY·REAUTH_REQUIRED·AUTH_EXPIRED·24시간 내 만료 판정([presenter](../cremore/api/source_presenters.py)), 관리자 운영 현황 `/api/v1/operations/status`(콘텐츠 연결 인증 상태 집계, 작업 실패·부분 완료, AWS 로그인 대기 경보, [routes](../cremore/api/routes/misc.py)). GCP OAuth 재인증 필요 시 예약 수집 건너뜀([scheduling](../cremore/coverage/scheduling.py)). AWS 로그인 만료 시 `AWS_LOGIN_REQUIRED`([aws_support](../cremore/api/aws_support.py)). worker 생존 신호는 컨테이너 liveness용 파일([worker](../cremore/worker/worker.py)) | 관리정보·금고·AWS 계정 연결의 공통 상태, 만료 사전 경고, 데이터 신선도 판정, DB·SIEM으로 가는 생존 신호 |
| 사람 로그인 | OIDC 모드: issuer·JWKS·audience 검증, groups claim을 Viewer·Analyst·Remediator·Admin에 매핑([config](../cremore/config.py), [reverse-proxy](../deploy/compose/reverse-proxy/README.md)). 공유 서버 overlay는 개인 AWS SSO를 잠금 | 특정 IdP(Okta, Keycloak, Entra ID)로 한 실환경 검증 |
| 기계 신원 | SDK 기본 인증 경로 사용: AWS botocore 기본 세션([aws_identity](../aws/backend/cremore_aws_provider/aws_identity.py)), Azure `DefaultAzureCredential`, GCP `google.auth.default`. Helm은 AWS IRSA·EKS Pod Identity·스캐너 역할 고정, GCP 외부 계정(WIF) 설정 Secret·GKE 워크로드 신원, Vault 쿠버네티스 인증(비밀 저장소)을 지원([values](../deploy/helm/values.yaml)). AWS 멤버 계정 역할(External ID)과 PC의 IAM Identity Center | Helm의 Azure 워크로드 신원(pod label), compose의 신원 전달(웹 신원 토큰 파일, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_*`; EC2 역할은 compose 기본값 `AWS_EC2_METADATA_DISABLED=true` 변경 필요), 쿠버네티스 밖의 IdP 토큰 갱신기, 온보딩 안내 |
| 스캔 트리거 | 승인 범위별 예약 스캔(주기마다 DELTA, 하루 첫 주기 RECONCILE), S3 전용 SQS 이벤트([triggers](../cremore/scanning/triggers.py)). 변경 없는 객체 건너뛰기는 S3·Notion이 기준 시각(watermark) 이후 수정되지 않은 것을 읽지 않는 방식이며 목록 조회는 전부 한다([scoped](../cremore/collectors/scoped.py)). 코드 저장소 수집기는 GitHub(트리의 blob SHA), GitLab(트리의 blob ID), Azure DevOps(`objectId`)가 파일별 해시를 받고, Bitbucket 파일 목록은 해시를 주지 않는다. 관리정보 연결별 `schedule_minutes`, AWS 인벤토리 주기 | 코드 저장소·Confluence·GCS·Azure Blob의 변경분 스캔, SaaS 변경 감지. 서명 웹훅은 제거됨 |
| SIEM | DB outbox와 목적지별 전달 상태, at-least-once 재시도([outbox](../cremore/siem/outbox.py)). `finding.created` 이벤트([events](../cremore/siem/events.py)). 출력기 jsonl·http_json·splunk_hec·logscale와 플러그인([registry](../cremore/siem/registry.py)). 별도 `cremore-siem`([cli](../cremore/cli/siem.py)), compose 선택 override([siem compose](../deploy/compose/siem/compose.yml)). 재시도 간격은 5초에서 두 배씩 최대 1시간이고 횟수 상한은 없음([runner](../cremore/siem/runner.py)). Splunk 출력기의 sourcetype은 `cremore:finding` 고정([splunk_hec](../cremore/siem/sinks/splunk_hec.py)) | 다른 이벤트 종류, 표준 형식, syslog·다른 인증 방식, 전송 상태 화면, 재시도 상한·보존, Helm 포함, 실제 SIEM 검증([보고서](SIEM_IMPLEMENTATION_REPORT.md)) |
| 금고 대조 | 금고 연결은 `aws_secrets_manager`·`aws_ssm`·`vault`·`openbao`·`gcp_secret_manager`만 받는다([models](../cremore/coverage/models.py)). 관리정보 연결의 값 읽기로 GCP Secret Manager·Azure Key Vault·GitLab CI 변수. 고객 환경 CLI가 값을 지문으로만 바꿔 보냄([cli](../cremore/cli/coverage.py)). Vault는 토큰 또는 Vault Agent 토큰 파일. 서버 쪽 Vault 수집은 이 설치의 비밀 저장소와 같은 주소일 때만 되고 다른 Vault 클러스터는 고객 환경 CLI로 대조([job](../cremore/coverage/job.py)) | 목록 밖 금고(CyberArk, Delinea, 1Password, Doppler, Akeyless, Bitwarden, Keeper, Infisical, 쿠버네티스 Secret, SOPS 파일)를 넣을 범용 통로 |
| 퇴사자 | 발급 목록의 소유자·생성자(GitHub owner, GitLab user, Atlassian account·createdBy, Notion creator, Azure DevOps user)와 일부 계정 상태(Atlassian userStatus, GitLab 정지, AWS IAM 사용자 상태). 거버넌스 티켓의 퇴사 처리 항목([tickets](../cremore/governance/tickets.py)) | IdP 사용자 상태 수집, IdP 사람과 공급자 계정의 연결, 퇴사자 자격증명 판정 |

## 3. 설계 원칙

- **사람과 기계를 나눈다.** 사람은 IdP로 로그인하고, 수집은 사람 세션에 기대지 않는다.
- **조용히 멈추지 않는다.** 인증 실패, 수집 실패, 오래된 데이터, 플랫폼 중단은 모두 신호로 만든다.
- **이벤트는 "현재 상태를 보러 가라"는 신호다.** 승인 범위를 넓히거나 삭제를 증명하지 않는다.
- **고객 인프라를 바꾸지 않는다.** 공급자 API와 고객이 만든 큐를 읽기만 한다.
- **수집한 비밀 원문은 메모리에서만 처리한다.** HMAC 지문과 필요한 메타데이터만 남기고 가역 암호화 형태도 보관하지 않는다.
  GCP 전용 저장 예외는 폐기했다. 공급자 접속용 인증 자격증명의 봉인 저장은 별도 계약이다.
- **정확한 식별자로만 연결한다.** 애매하면 후보로 표시한다.
- **보이지 않음은 해결이 아니고, 목록에 없음은 없음이 아니다.**
- **자동 조치는 기본 꺼짐이다.** 사람이 승인하고 설치 정책으로 켠 경우에만 실행한다.
- **특정 제품에 묶이지 않는다.** IdP와 SIEM은 표준 경로를 먼저 지원하고 제품별 기능은 선택이다.

## 4. 설계

### 4.1 B. 24시간 운영 기반과 SIEM 보완

**배포 형태.** 운영은 서버 배포(compose 공개 overlay 또는 Helm)로 하고 모든 프로세스는 자동 재시작한다.
1인용 PC compose는 개발·평가용으로 명시한다. 배포 설정에 손대는 단계마다 compose 공개 overlay와 Helm을 함께 고치고
함께 검사한다(결정 1). `cremore-siem`을 두 방식 모두에 상시 서비스로 포함하고 Helm에서는 값으로 켜고 끈다.
Helm은 CI의 문법·렌더링 검사에 더해 로컬 쿠버네티스(kind)로 실제 기동을 확인하고, 클라우드 신원 연동은 실제 클러스터에서 최종 확인한다.

**통합 연결 상태 모델.** 콘텐츠 연결에 있는 판정을 일반화해 콘텐츠·관리정보·금고·AWS 계정 연결이 같은 필드를 쓴다.

| 필드 | 값 |
| --- | --- |
| `auth_state` | `READY`, `EXPIRING`, `REAUTH_REQUIRED`, `PERMISSION_LIMITED`, `SECRET_UNAVAILABLE`, `DISABLED`, `UNKNOWN` (만료 14일 안이면 아직 읽지 않은 `UNKNOWN`도 `EXPIRING`) |
| `auth_renewal` | `AUTO`(App·역할·워크로드 신원·OAuth refresh), `MANUAL`(개인 토큰·API 키), `HUMAN_SESSION`(PC의 AWS SSO), `EXTERNAL`(고객 환경 CLI가 자격증명을 쥐고 있어 업로드가 계속 오는지만 본다), `UNKNOWN`(아직 신원 보고가 없음) |
| `expires_at` | 공급자가 알려 준 값(예: GitHub 응답 헤더, GitLab 토큰 조회, AWS SSO 로그인 캐시). 알려 주지 않으면 관리자가 입력한 만료일(`PUT /api/v1/operations/connections/{key}/expiry`, 감사 기록)을 출처와 함께 쓴다. 추정하지 않는다 |
| `last_success_at`, `last_failure_code` | 마지막 성공 수집 시각과 실패 코드 |
| `freshness` | `FRESH`, `STALE`, `NEVER_COLLECTED`, `NOT_SCHEDULED`. 콘텐츠 연결은 실제로 도는 예약 범위의 가장 짧은 주기 3배와 24시간 중 큰 값을 넘으면 `STALE`이고, 예약이 없으면 `NOT_SCHEDULED`다. 금고·관리정보 연결은 비교 판정이 이미 쓰는 `freshness_hours`와 예약 주기 3배 중 큰 값을 쓴다 |

경고 규칙: `MANUAL`은 만료 14일·3일 전, `AUTO`는 갱신 실패 즉시, `HUMAN_SESSION`은 운영 배포에서 상시 경고하고 권장 방식을 안내한다.
운영 이벤트는 상태가 바뀔 때만 보낸다(edge-triggered). 같은 상태를 반복해서 보내지 않는다. 판정은 여러 worker 복제본
(Helm 기본 2개)에서 한 번만 돌도록 기존 DB 리스·수신 기록 방식을 쓰고, 마지막으로 보낸 상태를 저장해 중복을 막는다.
판정기는 기존 세 저장소(콘텐츠 연결, AWS 계정, 금고·관리정보 연결의 실행 기록)를 읽으며 연결 테이블 구조는 바꾸지 않는다.

**운영 이벤트.** SIEM 이벤트 schema v1에 event_type을 추가한다(기존 필드는 유지하는 additive 변경).

| event_type | 뜻 |
| --- | --- |
| `connection.auth_expiring`, `connection.auth_failed`, `connection.auth_recovered` | 연결 인증의 만료 임박·실패·회복 |
| `collection.failed`, `collection.stale`, `collection.recovered` | 수집 실패·데이터 오래됨·회복 |
| `platform.heartbeat` | 정해진 주기의 생존 신호. 끊기면 SIEM이 중단을 판단 |
| `siem.delivery_backlog` | 한 목적지의 대기열이 기준을 넘음. 다른 목적지로 알린다 |
| `finding.updated` | 탐지 상태 변경(해결, 오탐, 검증 결과) |
| `audit.action` | 관리자 활동(범위 승인, 설정 변경, 조치 승인) |
| `identity.credential_orphaned` | 퇴사자의 자격증명 판정(4.2) |
| `coverage.verdict_changed` | 금고 대조 판정 변경 |

모든 이벤트는 허용 목록 필드, 내부 UUID, 알려진 코드만 쓴다. 원문·경로·이메일·이름은 넣지 않는다.
여러 설치를 한 SIEM에 모을 수 있게 설치별 무작위 `installation_id`를 추가한다.

**SIEM 출력 보완.** 고객이 어떤 SIEM을 쓸지 모르는 상태를 전제로 공용 통로 세 개를 갖춘다.

| 통로 | 내용 | 받는 쪽 예 |
| --- | --- | --- |
| HTTPS | 기존 `http_json`에 인증 방식 추가: Bearer, API key 헤더, 사용자 지정 헤더, OAuth client credentials(토큰 자동 갱신) | Sentinel Logs Ingestion API, Elastic, Datadog, 사내 게이트웨이 |
| syslog over TLS | RFC 5424, 형식 JSON·CEF·LEEF 선택 | QRadar, ArcSight, syslog 수집기 |
| JSONL | 기존 표준 출력. 로그 수집기(Fluent Bit, Vector, Filebeat, Logstash)로 전달 | 수집기를 두는 모든 SIEM |

새 event_type을 보내려면 출력기의 고정 라벨을 이벤트 종류별로 바꾼다(Splunk sourcetype `cremore:finding`, LogScale tags).
형식은 기존 `native`(schema v1)를 기본으로 두고 공개 표준 **OCSF**를 선택지로 더한다(결정 3). 탐지는
[Detection Finding](https://schema.ocsf.io/1.3.0/classes/detection_finding)(class_uid 2004, Findings 분류, 필수 속성 finding_info·severity_id·activity_id·time·metadata 등)으로 옮기고
나머지는 의미가 맞는 것만 옮긴다(결정 11): 퇴사자 자격증명·금고 대조 판정은 보안 탐지 성격이라 Detection Finding,
관리자 활동은 [API Activity](https://schema.ocsf.io/1.3.0/classes/api_activity)(class_uid 6003)로 보내고, 인증 만료·수집 실패·생존 신호는
맞는 클래스가 없어 `native` 형식으로 둔다.
주요 SIEM별 필드 매핑 문서를 제공한다. 공용 통로를 먼저 만들고, Splunk·LogScale 외 전용 출력기(Sentinel, Elastic, Google SecOps)는
고객 수요에 따라 기존 플러그인 경계로 추가한다.

운영 기능: 목적지별 대기 수·마지막 성공·연속 실패 API와 대시보드 카드, 테스트 이벤트 보내기,
재시도 상한 이후 보류 상태 표시와 수동 재시도, 보존 기간 설정을 추가한다. 이벤트량이 늘면 목적지별 묶음 전송과
목적지 병렬 처리를 선택으로 둔다.

**헬스.** worker는 이미 컨테이너 liveness용 생존 파일을 쓴다. 이를 DB의 생존 기록과 `platform.heartbeat` 이벤트로 넓히고,
`/healthz` 외에 worker 생존과 작업 대기 지연을 운영 현황 API에 더해 외부 모니터링이 읽게 한다.

### 4.2 IdP 연동

**사람 로그인.** 기존 OIDC를 유지한다. Okta → Entra ID → Keycloak 순서로 설정 예(그룹 매핑)를 문서화하고 실환경에서 검증한다(결정 2).
IdP 세션 만료는 해당 사용자의 화면에만 영향을 준다. IdP별 확인 항목: Entra ID는 groups claim에 그룹 이름 대신 객체 ID가 오고
그룹이 많으면 claim이 빠질 수 있다(overage). Keycloak은 그룹을 토큰에 넣는 mapper가 필요하다. Okta는 인증 서버에 groups claim을 추가해야 한다.

**기계 신원(클라우드).** CreMore 서버의 워크로드 신원 하나를 각 클라우드가 한 번 신뢰하게 한다. CreMore는 이미 SDK 기본 인증 경로를
쓰므로 웹 신원·WIF·federated 토큰은 대부분 **배포 설정 연결**로 받을 수 있다.

| 클라우드 | 쿠버네티스(Helm) | 서버 한 대(compose) | 새로 할 일 |
| --- | --- | --- | --- |
| AWS | IRSA·EKS Pod Identity 지원(서비스 계정 annotation, `eksPodIdentity`, 스캐너 역할 고정 `scannerPrincipalArn`) | EC2 역할은 기본값 `AWS_EC2_METADATA_DISABLED=true`를 바꿔야 한다. IdP 토큰은 `AWS_ROLE_ARN`·`AWS_WEB_IDENTITY_TOKEN_FILE` 전달 필요 | compose 전달과 안내 |
| GCP | 외부 계정(WIF) 설정 Secret(`gcp.adcSecretName`)과 GKE 워크로드 신원 지원 | `GOOGLE_APPLICATION_CREDENTIALS` 설정 파일 전달 필요 | compose 전달과 안내 |
| Azure | 서비스 계정 annotation은 있으나 AKS 워크로드 신원에 필요한 pod label이 없다 | `AZURE_CLIENT_ID`·`AZURE_TENANT_ID`·`AZURE_FEDERATED_TOKEN_FILE` 전달 필요 | Helm pod label, compose 전달 |
| Vault(비밀 저장소) | 쿠버네티스 인증 지원(projected 토큰) | 토큰 | 없음 |

쿠버네티스 밖에서 IdP(Okta, Keycloak)의 client credentials 토큰을 쓰려면 짧은 토큰을 받아 파일로 갱신하는 작은 갱신기가 새로 필요하다.
쿠버네티스 서비스 계정 토큰은 IdP 장애의 영향을 받지 않아 권장 경로로 둔다. 멤버 계정 역할·External ID와 스캐너 신원 승인 흐름은 그대로 쓴다.
PC의 AWS SSO는 개발·평가용으로 두고 운영에서 쓰면 `HUMAN_SESSION` 경고를 낸다.

**SaaS 기계 자격증명.** SaaS API는 IdP 토큰을 받지 않는다. 공급자별로 자동 갱신되는 방식을 기본으로 권하고
descriptor에 갱신 종류와 권장 순서를 데이터로 적는다: GitHub App, Atlassian 서비스 계정 OAuth(client credentials),
Azure DevOps의 Entra 서비스 주체, GitLab 서비스 계정 토큰(만료 추적과 교체), Notion integration.

**퇴사자 자격증명 점검.**

1. IdP 사용자 상태 수집: 읽기 전용으로 사용자 ID, 상태(재직·정지·비활성), 상태 변경 시각을 받는다.
   Okta는 Users API(`statusChanged`가 상태 변경 시각이라 System Log는 필요 없다), Entra ID는 `accountEnabled`와 삭제된 사용자,
   Keycloak은 사용자와 관리 이벤트를 쓴다. 수집기도 로그인과 같은 순서(Okta → Entra ID → Keycloak)로 만든다.
   권한은 최소 권한 전용 앱으로만 받는다(결정 12): Okta는 서비스 앱의 `okta.users.read`, Entra ID는 앱 권한 `User.Read.All`,
   Keycloak은 서비스 계정의 `view-users`(관리 이벤트를 쓸 때 `view-events`). 개인 관리자 계정의 토큰은 그 관리자가 퇴사하면 끊기므로 쓰지 않는다.
   구현과 운영은 [퇴사자 점검](LEAVER_CHECK.md)에 있다.
2. 사람과 공급자 계정 연결: SCIM·SAML 외부 ID, IdP 고유 ID 매핑, 확인된 회사 이메일의 정확 일치 순으로만 연결한다.
   출처 예: GitHub Enterprise의 SAML external identity, GitLab identity의 `extern_uid`, Atlassian managed account,
   AWS IAM Identity Center 사용자, Entra 연동 Azure DevOps 사용자. 이름 유사성으로 연결하지 않고 애매하면 후보로 둔다.
3. 판정과 산출: 퇴사자가 소유하거나 만든 자격증명을 공급자 전체에서 모아 판정한다.

| 판정 | 조건 |
| --- | --- |
| `USED_AFTER_DEPARTURE` | 마지막 사용 시각이 퇴사 이후 |
| `ACTIVE` | 폐기·만료되지 않음 |
| `REVOKED_OR_EXPIRED` | 이미 꺼짐 |
| `UNKNOWN` | 공급자가 사용자별 목록이나 상태를 주지 않음 |

노출 여부와 금고 보관 여부를 함께 표시한다. 결과는 대시보드 목록, `identity.credential_orphaned` 이벤트, 거버넌스 티켓으로 내보낸다.
모든 공급자는 보고와 티켓이 기본이고, 폐기는 처음에는 AWS 액세스 키만 기존 조치 승인 흐름(Remediator 계획, Admin 승인)으로
실행하며 기본 꺼짐이다(결정 4). 조치 모듈의 키 비활성화([key_actions](../aws/backend/cremore_aws_provider/remediation/key_actions.py))를
`ACTION_EXECUTION_ENABLED`가 켜진 경우에만 쓴다. IdP 수집기는 새 schema 2 관리정보 공급자로 만들어 기존 수집 작업 종류를 쓴다.
GitHub SAML·SCIM 신원 조회는 조직 소유자(`read:org`)나 엔터프라이즈 소유자(`read:enterprise`, EMU·엔터프라이즈 SAML)의 classic PAT가 필요해 GitHub App과 다른 별도 연결(`github_identity`)로 둔다. 저장하는 개인정보는 IdP 사용자 ID, 상태,
상태 변경 시각, 연결된 계정 ID로 제한하고 접근 역할을 정한다. 보존 기간은 퇴사 후 기본 1년이며 설정으로 바꿀 수 있고,
기간이 지나면 삭제한다(결정 13). 기존 판단 축(발급 목록 × 노출 × 금고)에
소유자 상태(재직·퇴사·알 수 없음)가 더해진다([metadata_correlation](../cremore/coverage/metadata_correlation.py), [issuer_coverage](../cremore/coverage/issuer_coverage.py)).

### 4.3 C. 주기·변경 감지 스캔

기존 모드(BASELINE, DELTA, EVENT, RECONCILE)를 유지하고 공급자별 **변경 조회기**를 더한다.

| 대상 | 변경을 아는 방법 | 다시 읽는 범위 |
| --- | --- | --- |
| GitHub, GitLab, Azure DevOps | 트리 목록의 파일별 해시(GitHub blob SHA, GitLab blob ID, Azure DevOps `objectId`)를 지난 검사와 비교. 커밋 비교는 목록 조회를 줄이는 선택 | 해시가 바뀐 파일만 |
| Bitbucket | 파일 목록에 해시가 없어 커밋 사이 변경 파일 목록을 받는다. Cloud는 `diffstat`, Data Center는 `changes`(아래) | 바뀐 파일만. Data Center는 blob ID(`contentId`)도 받는다 |
| Notion | 기존 기준 시각(watermark) 방식 | 수정된 페이지 |
| Confluence | CQL의 수정 시각 조건 | 수정된 페이지 |
| S3 | 기존 기준 시각 방식과 SQS | 바뀐 객체 |
| GCS, Azure Blob | generation·ETag·수정 시각 | 바뀐 객체 |

Bitbucket 변경 목록은 공식 OpenAPI 명세([Cloud 2.0](https://dac-static.atlassian.com/cloud/bitbucket/swagger.v3.json),
[Data Center 10.4](https://dac-static.atlassian.com/server/bitbucket/10.4.swagger.v3.json))로 확인했다(2026-09-27).

- Cloud: [`diffstat/{새 커밋}..{지난 커밋}`](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-commits/)에 `topic=false`를 주면
  두 커밋의 단순 비교가 나온다. 범위는 `git diff`와 반대로 새 커밋을 먼저 쓴다. 항목은 상태(added·removed·modified·renamed)와
  이전·새 경로이고 blob 해시는 없다. 한 페이지 기본 500개, 최대 5000개이며 `next`로 넘긴다. 계산 시간이 넘으면 HTTP 555를 준다.
- Data Center: 저장소 경로의 [`changes?since={지난 커밋}&until={새 커밋}`](https://developer.atlassian.com/server/bitbucket/rest/v1004/api-group-repository/).
  항목은 종류(ADD·COPY·DELETE·MODIFY·MOVE·UNKNOWN), 노드 종류(FILE·DIRECTORY·SUBMODULE), 경로, blob ID(`contentId`·`fromContentId`)다.
  서버 설정 `page.max.changes`(기본 1,000, [Atlassian KB](https://support.atlassian.com/bitbucket-data-center/kb/the-diff-for-this-file-is-too-large-to-render/))를
  넘으면 뒤 내용을 받을 수 없고, 응답에 잘렸다는 표시가 없다.
- 다음 경우에는 그 저장소를 전체 다시 읽는다: 지난 커밋을 찾을 수 없을 때(강제 푸시 뒤 정리 등), Cloud가 555를 줄 때,
  Data Center에서 받은 항목 수가 한도(연결 설정, 기본 1,000)에 이르거나, 마지막 페이지(`isLastPage: true`)까지 가지 못하거나,
  디렉터리 항목이 나올 때(그 안의 파일을 알 수 없다).
  종류가 `UNKNOWN`인 항목은 바뀐 파일로 보고 읽는다.

변경 조회는 worker의 기존 폴링(`poll_triggers`)에 더하고, 결과는 SQS 이벤트와 같은 기존 경로(`enqueue_event` → scope 작업 DELTA)로 넣는다.
새 작업 종류를 만들지 않으므로 활성 스캔 인덱스·마이그레이션을 바꾸지 않는다.

조회 주기는 기본 5분이고 공급자별로 바꿀 수 있다(결정 5). 공급자 API 한도는 기존 요청 예산으로 지킨다. 강제 푸시나 이력 재작성을 감지하면 그 범위를
BASELINE으로 다시 읽는다. 이전 결과는 blob 해시가 같을 때만 재사용한다. 하루 한 번의 전체 대조가 안전망이다.

선택 기능으로 큐 이벤트를 일반화한다. 공급자 이벤트나 웹훅을 고객이 만든 큐(SQS, Pub/Sub, Service Bus)로 보내게 하고
CreMore는 큐를 읽기만 한다. CreMore는 공개 수신 엔드포인트를 열지 않는다(서명 웹훅을 제거한 이유를 유지).
관리정보 수집도 같은 스케줄러와 연결 상태 모델에 합친다.

코드 저장소의 푸시 알림은 커밋 목록에 상한이 있어(GitHub 2,048개, GitLab 20개) 파일 목록을 믿지 않는다. 그 저장소의 변경 조회기가
커서를 가지고 있으면 조회기를 깨우고, 없으면 저장소를 DELTA로 다시 읽는다. 구현과 공급자별 규칙은 [변경 감지 스캔](CHANGE_FEEDS.md)에 있다.

### 4.4 A. 통합 온보딩

모든 공급자를 "공급자 연결" 마법사 하나에서 같은 4단계로 연결한다.

1. 무엇을: 공급자·에디션과 용도(노출 스캔, 발급 목록, 금고)를 고른다.
2. 어떻게: descriptor의 권장 순서대로 인증 방식을 제시한다. 클라우드는 워크로드 신원 연동, SaaS는 앱·서비스 계정이 먼저이고 수동 토큰은 고급이다.
3. 권한 점검: 고른 용도에 필요한 권한 체크리스트와 실제 점검 결과를 보여 준다(GitHub `source_permissions` 방식 일반화).
4. 범위와 첫 실행: 범위를 고르고 승인한 뒤 첫 실행을 예약한다.

공급자 연결(자격증명 하나)을 콘텐츠 스캔·관리정보·금고 용도가 공유하는 모델로 **교체**한다. 첫 공개 릴리스 전이므로
호환 계층이나 전환 도우미를 두지 않고 기존 네 창구를 마법사로 대체한다(결정 6). 개발 중 만든 DB는 새로 시작하며
CHANGELOG의 업그레이드 안내에 명시한다. 모든 공급자 모듈을 같은 단계에서 새 모델로 옮긴다(결정 8). descriptor에 용도별 필요 권한, 인증 방식 권장 순서, 갱신 종류, 점검 절차를 더한다.
구현한 모델·API·공급자 계약·계획 항목은 [공급자 연결](ONBOARDING.md)에 있다.

### 4.5 공급자별 개발 경계

이 설계 이후에도 공급자별 분업을 유지한다. 플랫폼은 엔진을 한 번 만들고, 공급자 담당자는 자기 폴더에서 연결 함수를 채운다.
플랫폼 코드에 공급자별 분기를 넣지 않는다는 기존 규칙과 경계 테스트([provider_boundaries_test](../cremore/provider_boundaries_test.py))를 그대로 적용한다.

| 기능 | 플랫폼이 한 번 만드는 것 | 공급자가 자기 폴더에서 채우는 것 |
| --- | --- | --- |
| 통합 온보딩 | 4단계 마법사, 공급자 연결 모델 | descriptor의 인증 방식·권장 순서·갱신 종류·용도별 필요 권한, 권한 점검 함수. 화면은 콘솔이 descriptor로 그린다(2026-10-01 `<vendor>/web/` 삭제) |
| 연결 상태 | 상태·만료·신선도 판정 | 자격증명 만료일 조회 함수. 없으면 만료일은 알 수 없음 |
| SIEM | 운영 이벤트, 전송기, 전송 상태 | 없음. 전용 출력기는 별도 출력 패키지 |
| 기계 신원 | 토큰 갱신기, 배포 설정 | AWS·GCP·Azure의 웹 신원·WIF·federated 인증 경로 |
| 퇴사자 점검 | 사람과 계정의 연결·판정 엔진, 승인 흐름 | 소유자의 정확한 식별자를 꺼내는 함수, 폐기 함수(처음에는 AWS만). IdP 수집기는 새 공급자 폴더 |
| 변경 감지 | 스케줄러, 스캔 모드, 일일 전체 대조 | 마지막 커서 이후 변경 조회 함수. 없으면 예약 스캔만 동작 |

연결 함수는 모두 선택이다. descriptor에 선언한 공급자에서만 해당 기능이 켜지고, 선언하지 않은 공급자는 기존대로 동작한다.
함수 모양(이름은 예시)은 다음과 같다.

| 함수 | 반환 |
| --- | --- |
| `check_connection(spec, purpose)` | 필요 권한별 확인 결과 |
| `credential_lifetime(spec, resolved)` | 공급자가 알려 준 만료 시각과 갱신 종류 |
| `changes_since(scope, cursor)` | 바뀐 리소스, 새 커서, 이력 재작성 여부 |
| `owner_identity_keys(record)` | 소유자의 정확한 식별자와 근거(외부 ID, 확인된 이메일 등) |
| `revoke_plan(credential)` | 승인 흐름에 넘길 폐기 계획(처음에는 AWS만) |
| IdP: `user_status(cursor)` | 사용자 ID, 상태, 상태 변경 시각 |

새 함수의 모양은 기존 콘텐츠 모듈 계약 테스트([module_contract_test](../cremore/sources/module_contract_test.py))와 metadata descriptor 검사에
넣어 공급자마다 같은 방식으로 검증한다. 마법사 화면은 콘솔이 descriptor로 그리며 공급자별 조각을 끼우지 않는다(이전 대시보드의 `registry.ts`는 2026-10-01 삭제).

함수 모양을 각 단계의 첫 작업으로 확정하면, 플랫폼이 엔진을 만드는 동안 공급자 담당자는 자기 함수를 동시에 만든다.
분업할 수 없는 것은 각 단계의 플랫폼 엔진(상태 판정, SIEM 이벤트, 판정 엔진, 스케줄러, 마법사 틀)뿐이다.

**연결 모델 교체.** 이번에는 한 사람이 6단계에서 모든 공급자를 한 번에 새 모델로 옮기므로 임시 변환기를 두지 않는다(결정 8).
공급자 연결 함수 구조는 유지해, 이후에는 다시 공급자별로 나눠 개발할 수 있다.

### 4.6 공급자별 IdP 적용 범위 (공식 문서 확인, 2026-09-27)

IdP는 세 곳에 쓰인다. CreMore 대시보드 로그인은 공급자와 무관하게 모두 적용된다. 기계 신원과 퇴사자 점검은 공급자에 따라 다르다.

**기계 신원: 외부 IdP·클러스터 토큰을 받는 곳**

| 공급자 | 방식 | 근거 |
| --- | --- | --- |
| AWS | OIDC 호환 IdP의 JWT를 IAM 역할의 임시 자격증명으로 교환. 기계 간 인증 지원 | [IAM OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html) |
| GCP | Workload Identity Federation. OIDC·SAML 2.0 IdP(Okta 포함), AWS, Azure, 쿠버네티스, GitHub, GitLab. 리소스 직접 권한 또는 서비스 계정 가장 | [Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation) |
| Azure(Key Vault, Entra, ARM, Blob) | Entra 워크로드 신원 연동. 쿠버네티스, GCP, AWS(IAM Outbound Identity Federation), 외부 OIDC IdP. Entra가 발급한 토큰은 연동에 쓸 수 없음 | [Workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation) |
| Azure DevOps | PAT 대신 Entra 서비스 주체·관리 신원. 서비스 주체는 워크로드 신원 연동 가능. Azure DevOps Services 기준이며 조직마다 추가하고 접근 수준(저장소는 Basic 이상)이 필요 | [Service principals & managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity) |
| Vault | JWT 인증 방식이 OIDC discovery·JWKS로 토큰을 검증해 기계 로그인 지원. OpenBao의 같은 방식 지원은 구현 단계에서 확인 | [JWT/OIDC auth](https://developer.hashicorp.com/vault/docs/auth/jwt) |

**SaaS: 외부 IdP 토큰을 받지 않는 곳과 대신 쓸 기계 자격증명**

| 공급자 | 사람과 무관한 기계 자격증명 | 만료·갱신 | 근거 |
| --- | --- | --- | --- |
| GitHub | GitHub App(REST API는 개인 토큰, App 토큰, OAuth 앱 토큰, `GITHUB_TOKEN`만 받음) | 설치 토큰 1시간, App 키로 자동 재발급 | [REST 인증](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api), [설치 토큰](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) |
| GitLab | 서비스 계정의 개인 토큰(Free·Premium·Ultimate, 모든 제공 형태). OAuth에는 기계용 client credentials가 없음 | 기본 365일(17.6부터 400일까지). 관리자가 만료를 강제하지 않으면 만료 없이 발급 가능 | [서비스 계정](https://docs.gitlab.com/user/profile/service_accounts/), [OAuth](https://docs.gitlab.com/api/oauth2/) |
| Atlassian(Confluence Cloud) | 서비스 계정 OAuth 2.0 client credentials. Confluence Cloud·Jira Cloud·Jira Align API. 중앙 사용자 관리 환경 필요 | 액세스 토큰 60분, 자동 재발급 | [서비스 계정 OAuth](https://support.atlassian.com/user-management/docs/create-oauth-2-0-credential-for-service-accounts/) |
| Bitbucket Cloud | 저장소·프로젝트·워크스페이스 access token(사람이 아니라 리소스에 묶임. 프로젝트·워크스페이스는 Premium) | 만료일 지정 가능. OAuth 액세스 토큰은 2시간이고 refresh token으로 갱신 | [access token](https://support.atlassian.com/bitbucket-cloud/docs/access-tokens/), [OAuth](https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/) |
| Notion | 내부 integration 토큰(페이지를 integration에 공유해야 읽음) | 내부 토큰의 만료는 문서에 명시돼 있지 않음. 공개 연동 OAuth 토큰은 refresh token으로 갱신 | [인증](https://developers.notion.com/docs/authorization) |

Confluence Cloud 콘텐츠 연결은 서비스 계정 OAuth(인증 방식 `service_account`)로 CreMore가 액세스 토큰을 스스로 받는다
([atlassian/README](../atlassian/README.md)의 "Confluence Cloud 서비스 계정"). 외부 금고에서 토큰을 갱신해 넣는 `token` 방식은 그대로 남는다.

**퇴사자 점검: 사람과 공급자 계정을 잇는 근거**

| 공급자 | 연결 근거 | 정확도 | 근거 |
| --- | --- | --- | --- |
| AWS | IAM Identity Center 사용자의 `ExternalIds`(IdP가 발급한 식별자)와 `UserStatus`(ENABLED·DISABLED). IAM 사용자는 IdP 연결 정보가 없어 태그가 없으면 판단 불가 | Identity Center는 정확 | [Identity Store User](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html) |
| GitHub | SAML SSO·SCIM을 쓰는 조직은 GraphQL 외부 신원(SAML NameID, SCIM `userName`·`emails`와 그 로그인). 조직 소유자의 `read:org`(또는 `admin:org`) classic PAT(SAML 승인) 필요. Enterprise Managed Users나 엔터프라이즈 SAML은 엔터프라이즈의 SAML·OIDC 공급자(`enterprise.ownerInfo`)에서 같은 값을 읽고 엔터프라이즈 소유자의 `read:enterprise` classic PAT 필요(구현 2026-10-02) | SAML·SCIM 값이면 정확, 아니면 후보·판단 불가 | [ExternalIdentity](https://docs.github.com/en/enterprise-cloud@latest/graphql/reference/objects#externalidentity) |
| GitLab | 관리자 API의 `identities`(provider, `extern_uid`)와 `extern_uid`·provider로 사용자 조회 | SSO를 쓰면 정확 | [Users API](https://docs.gitlab.com/api/users/) |
| Notion | 사람의 `person.email`(연동에 이메일 권한이 있을 때만). 봇은 `owner`(워크스페이스 또는 사용자) | 이메일 권한이 있으면 이메일 일치 | [User object](https://developers.notion.com/reference/user) |
| Azure DevOps | Entra 연동 사용자. 애플리케이션 신원은 Entra에서 지워도 Azure DevOps 구성원 자격이 자동으로 지워지지 않음 | Entra가 IdP면 정확 | 위 Azure DevOps 문서 |
| Atlassian·Bitbucket | 조직의 관리 계정(회사 도메인). 기존 Atlassian 수집기의 `managed-accounts` 조회 사용 | 관리 계정이면 정확 | 기존 코드 |
| Okta(IdP 쪽 상태) | 상태: Staged, Pending user action, Active, Password reset, Password expired, Locked out, Suspended, Deactivated. Suspended는 앱 접근만 막고, Deactivated는 앱 할당을 모두 지움 | 퇴사 신호는 Deactivated·Suspended | [Okta 사용자 상태](https://help.okta.com/en-us/content/topics/users-groups-profiles/usgp-end-user-states.htm) |

GitHub의 SAML·SCIM 신원 조회는 조직 소유자(EMU·엔터프라이즈 SAML이면 엔터프라이즈 소유자) 권한의 자격증명이 필요해 별도 연결(`github_identity`)로 두고, 없으면 GitHub 쪽은
관리자 확정과 계정 행(`UNKNOWN`)으로 표시한다. Entra ID의 `accountEnabled`·삭제된 사용자(`deletedDateTime`, `User.Read.All`)와
Keycloak의 `enabled`·관리 이벤트는 2026-09-28 공식 문서(Graph 참조, Keycloak Admin REST OpenAPI)로 확인했다.

### 4.7 범용 금고 연결

기업이 어떤 금고를 쓰는지 모르는 상태를 전제로, 목록에 없는 금고도 대조할 수 있게 한다. 지금의 고객 환경 CLI 구조
(이 설치의 지문 키로 고객 환경에서 지문만 계산하고, 원문은 보내지 않음)를 그대로 쓴다.

1. **외부 금고 종류.** 제품 이름을 고정하지 않는 금고 연결 종류(예: `external_vault`)를 추가한다. 표시 이름, 제품 이름(자유 입력),
   선언 범위를 받는다. 기존 금고 연결 종류와 대조 경로는 그대로 둔다.
2. **범용 입력.** `cremore-coverage`가 JSON Lines(한 줄에 경로·값, 선택적으로 버전·수정 시각)를 파일이나 표준 입력으로 받는다.
   고객은 자기 금고 도구의 내보내기 결과를 넣고, CLI가 그 자리에서 지문으로 바꿔 보낸다. 요청 본문에 원문이 없음을 테스트로 보증한다.
   주요 금고별 내보내기 방법(CyberArk CLI, 1Password `op`, `doppler secrets download`, `kubectl get secrets` 등)을 문서로 제공한다.
3. **읽기 플러그인.** SIEM 출력기와 같은 방식으로 명시적으로 허용한 설치형 패키지(예: entry point `cremore.vault_readers`)가
   특정 금고를 직접 읽게 한다. 비신뢰 코드를 격리하는 장치가 아니라는 점도 같다.
4. **서버 쪽 수집의 범위.** 지금 서버 쪽 Vault 수집은 이 설치의 비밀 저장소와 같은 주소일 때만 된다(비밀 저장소 신원을 다른 곳에
   보내지 않기 위한 제한). 앞으로도 기본은 고객 환경 CLI이고, 원하는 연결만 서버 읽기를 켤 수 있게 한다(결정 10).
   서버 읽기는 연결마다 따로 Vault 인증(JWT·쿠버네티스 인증 권장, 토큰 가능)을 두고, 읽기 전용·경로 제한 정책,
   주소·TLS 검증, 리다이렉트 금지를 적용한다. 이 설치의 비밀 저장소 신원은 그 연결에 쓰지 않는다.
5. **완결성 선언.** 범용 입력은 금고 전체를 읽었는지 CreMore가 확인할 수 없다. "금고에 없음" 판정은 운영자가 선언 범위를
   모두 내보냈다고 확인한 실행에서만 내고 근거를 "운영자 선언"으로 표시한다. 확인이 없으면 "판단 불가"다. API로 완결성을 확인하는
   기존 금고보다 약한 근거로 구분한다.

## 5. 합쳤을 때의 동작

1. 설치: 보안팀이 사내 서버(쿠버네티스)에 설치한다. 로그인은 Okta이고 그룹이 역할에 매핑된다.
2. 연결: Admin이 공급자 연결 마법사에서 AWS·GCP·Azure는 워크로드 신원 신뢰를 한 번 설정하고, GitHub는 App, Notion은 integration으로 연결한다.
   권한 점검이 빠진 권한을 알려 주고 Admin이 범위를 승인한다.
3. 최초 스캔: 승인 범위를 BASELINE으로 읽고 발급 목록과 금고를 수집해 "발급됐는데 금고에 없음"을 계산한다.
4. 평소: 몇 분마다 변경을 조회한다. GitHub에 AWS 키가 푸시되면 그 파일만 검사해 탐지하고 `finding.created`를 SIEM에 보낸다.
5. 매일: RECONCILE로 놓친 변경을 메운다.
6. 문제 상황: 개인 토큰이 14일 뒤 만료되면 `connection.auth_expiring`, 수집이 실패하거나 오래되면 `collection.failed`·`collection.stale`,
   CreMore가 멈추면 `platform.heartbeat`가 끊긴다. 담당자가 퇴사하거나 세션이 만료돼도 기계 신원으로 수집은 계속된다.
7. 퇴사: IdP에서 사용자를 비활성화하면 그 사람의 자격증명을 판정하고, 퇴사 이후 사용된 키는 SIEM 고위험 이벤트와 티켓이 된다.
   승인하면 폐기한다.
8. 사람의 일: 탐지 검토, 오탐 처리, 조치 승인은 IdP로 로그인한 사람이 하고 감사 기록과 `audit.action`에 남는다.

## 6. 공통 계약 변경 (플랫폼 검토 대상)

| 영역 | 변경 | 호환 영향 |
| --- | --- | --- |
| DB | 연결 상태 필드 또는 상태 테이블, IdP 사용자·연결 테이블, 공급자 연결 모델, 설치 ID 설정 | 공급자 연결 모델은 첫 공개 릴리스 전 교체(호환 없음, 개발 DB는 새로 시작). 나머지는 additive이고 기존 행은 `UNKNOWN`으로 시작 |
| API | 연결 상태 조회, 운영 현황 확장, SIEM 목적지 상태·테스트, 퇴사자 판정, 온보딩 마법사 | 연결 등록 경로는 마법사 API로 교체, 나머지는 기존 경로 유지 |
| Worker | 상태 평가기, heartbeat, 변경 조회기, 토큰 갱신기, IdP 수집기 | 기존 리스·예산·취소 계약 사용 |
| SIEM 스키마 | 새 event_type, `installation_id`, OCSF 형식 선택 | v1 additive. 수신 측이 새 필드를 무시할 수 있는지 문서화 |
| 배포 | compose 공개 overlay·Helm의 `cremore-siem`, 워크로드 신원 설정 | 기본값은 기존 동작 유지 |
| 설정 | 새 스위치와 주기 | 모두 opt-in, 설치 잠금 규칙 유지 |
| 금고 연결 | 외부 금고 종류, CLI의 JSON Lines 입력, 읽기 플러그인 entry point, 완결성 선언 필드 | additive. 기존 금고 종류·대조 판정 유지 |

## 7. 단계와 완료 기준

| 단계 | 내용 | 완료 기준 |
| --- | --- | --- |
| 1. B 기반 | 연결 상태 통합, 만료·신선도 경고, 운영 이벤트, heartbeat, `cremore-siem` 상시 서비스, 전송 상태 화면·테스트 이벤트·재시도 상한 | 합성 테스트로 14·3일 경고, 수집 실패와 무성공 경과 이벤트, heartbeat 주기, 목적지 고장 시 backlog 이벤트. PostgreSQL 테스트, 웹·브라우저 검사 |
| 1b. 범용 금고 연결 | 외부 금고 종류, JSON Lines 입력과 금고별 내보내기 문서, 읽기 플러그인, 완결성 선언, 다른 Vault 클러스터의 연결별 서버 읽기(선택) | 요청 본문에 원문이 없음, 선언이 없는 실행은 부재를 확정하지 않음, 예시 플러그인 로드와 거절(허용 목록 밖), 대시보드 등록 |
| 2. SIEM 통로 | HTTPS 인증 확장, syslog TLS(JSON·CEF·LEEF), OCSF 형식(탐지·퇴사자·금고 판정은 Detection Finding, 관리자 활동은 API Activity), `installation_id` | 가짜 수신기 계약 테스트, 형식 스냅샷, 매핑 문서 |
| 3. IdP 기계 신원 | Helm의 Azure 워크로드 신원 pod label, compose의 AWS·GCP·Azure 신원 전달, 쿠버네티스 밖 IdP 토큰 갱신기, 운영 배포 안내(대부분 배포 설정 연결) | 가짜 토큰 교환 합성 테스트. 실환경 검증은 별도 항목 |
| 4. 퇴사자 점검 | IdP 사용자 수집기(Okta → Entra ID → Keycloak, 최소 권한 전용 앱), 계정 연결, 판정, 이벤트, 티켓, 보존 기간(기본 1년) | 합성 IdP·공급자 데이터로 판정 표와 연결 규칙(정확 일치·후보) 검증 |
| 5. C 변경 감지 | 변경 조회기(GitHub 먼저), 코드 저장소 증분 스캔, 큐 이벤트 일반화 | 변경 파일만 읽는지, 강제 푸시 시 BASELINE, Bitbucket의 한도 도달·555·지난 커밋 없음에서 전체 다시 읽기, RECONCILE 안전망을 합성 저장소로 검증 |
| 6. A 통합 온보딩 | 마법사, 공급자 연결 모델 교체, descriptor 확장, 기존 네 창구 대체, 모든 공급자 모듈 동시 전환 | 모든 공급자가 같은 4단계로 등록되는지 웹·브라우저 검사 |

이번에는 한 사람이 단계마다 플랫폼 엔진과 모든 공급자의 연결 함수를 함께 적용하고, 단계마다 PR 하나로 main에 올린다(결정 8).
6단계 동안에는 팀원에게 제품 쪽 공급자 폴더 변경을 멈춰 달라고 요청하고, 3단계에서 AWS 로그인·세션 모듈을 고칠 때는
[AGENTS.md](../AGENTS.md)의 공동 검토를 받는다. 각 단계는 산출물마다 검증한 커밋으로 나누고 관련 문서를 함께 갱신한다. 실계정(AWS, GCP, Azure, Okta, Keycloak, SIEM)
검증은 별도 환경과 허용 범위가 정해질 때 수행하고 미검증 항목으로 기록한다.

## 8. 위험과 대응

| 위험 | 대응 |
| --- | --- |
| 범위가 넓다 | 단계마다 독립 가치가 있게 나누고 B부터 한다 |
| 기존 API·DB 호환 | 공개 전이라 연결 모델은 교체하고 CHANGELOG에 새로 시작을 안내. 첫 공개 릴리스 전에 끝내며 이후에는 호환을 지킨다 |
| 실환경 검증 부족 | 합성 검증을 기본으로 하고 실환경 항목을 분리 기록 |
| 퇴사자 개인정보 | 최소 저장, 역할 제한, 보존 기간, 이벤트에 개인 식별 정보 미포함 |
| SIEM 이벤트 과다 | 상태 변화 시에만 전송, 요약 이벤트 |
| IdP 장애 의존 | 쿠버네티스 서비스 계정 토큰을 권장 경로로 둠 |
| 증분 스캔 누락 | 일일 RECONCILE, 강제 푸시 감지 시 BASELINE |

## 9. 결정 사항 (2026-09-27)

| 번호 | 항목 | 결정 | 이유 |
| --- | --- | --- | --- |
| 1 | 운영 배포 | compose 공개 overlay와 Helm을 같은 단계에서 함께 갱신 | 기능 대부분은 코드라 배포 설정 부분만 늘어나고, 나중에 맞추면 Helm이 뒤처진다(SIEM 전송기가 Helm에 빠진 전례) |
| 2 | IdP 순서 | Okta → Entra ID → Keycloak | 사용자 결정. Okta 검증에는 개발용 계정이 필요하고 Keycloak은 Docker로 언제든 검증 가능 |
| 3 | SIEM | `native` 기본 + OCSF 선택, syslog·HTTPS 인증 확장 등 공용 통로 먼저, 전용 출력기는 수요에 따라 | 고객 SIEM을 모르는 상태에서 가장 넓게 받을 수 있고, 국내 SIEM은 syslog 수집을 기본으로 지원하는 경우가 많다 |
| 4 | 퇴사자 폐기 | 보고·티켓 기본, 폐기는 AWS 액세스 키만 승인 후 | 잘못된 연결로 서비스 키를 끄는 사고를 막고, 이미 있는 승인 흐름을 쓴다 |
| 5 | 변경 조회 주기 | 기본 5분, 공급자별 조정 | 탐지 속도와 API 한도의 균형. 놓친 것은 일일 RECONCILE이 메운다 |
| 6 | 연결 전환 | 호환 계층 없이 공급자 연결 모델로 교체, 개발 DB는 새로 시작 | 저장소 비공개·릴리스 없음으로 외부 사용자가 없다. 이름 변경 때와 같은 판단. 첫 공개 릴리스 전에 끝낸다 |
| 7 | 공급자별 개발 | 플랫폼 엔진 + 공급자 연결 함수(선택) 구조 | 이 설계 이후에도 공급자별로 나눠 개발할 수 있게 한다 |
| 8 | 이번 진행 방식 | 한 사람이 단계마다 모든 공급자에 일괄 적용, 단계마다 PR 하나, 임시 변환기 없음 | 지금은 main이 조용하고 팀원 브랜치가 제품 폴더와 겹치지 않는다. 한 번에 옮기면 변환기가 필요 없다 |
| 9 | 범용 금고 | 외부 금고 종류와 JSON Lines 입력, 읽기 플러그인, 완결성 선언을 1단계 바로 다음(1b)에 구현 | 기업이 쓰는 금고를 모르는 상태에서 발급 목록 × 노출 × 금고 비교의 폭을 정하는 기능이고, 기존 금고 대조에 더하는 변경이라 독립적으로 할 수 있다 |
| 10 | 다른 Vault 클러스터 | 기본은 고객 환경 CLI, 원하는 연결만 서버 읽기(연결별 JWT·쿠버네티스 인증 권장) | 보안을 우선하는 고객과 운영 편의를 원하는 고객을 모두 받는다 |
| 11 | 운영·감사 이벤트의 OCSF | 퇴사자·금고 대조는 Detection Finding, 관리자 활동은 API Activity, 운영 상태는 `native` | 억지 매핑 없이 SIEM 호환성을 얻는다 |
| 12 | IdP 수집기 권한 | 최소 권한 전용 앱만(Okta 서비스 앱, Entra 앱 권한, Keycloak 서비스 계정) | 개인 관리자 토큰은 권한이 넓고 그 관리자의 퇴사로 끊긴다 |
| 13 | 퇴사자 데이터 보존 | 퇴사 후 기본 1년, 설정 가능, 지나면 삭제 | 사고 조사 이력과 개인정보 최소 보관의 균형 |

### 구현 전 확인

- 마지막 항목이던 Bitbucket 변경 파일 목록 API를 2026-09-27 공식 명세로 확인했다(4.3절). 남은 구현 전 확인은 없다.
- Data Center 서버가 한도를 넘었을 때의 실제 응답 모양은 명세에 없다. 그래서 받은 항목 수로 판단하고, 실서버 동작은 실환경 검증 항목으로 남긴다.

## 10. 구현 현황

단계마다 산출물별로 검증한 커밋을 `integration/saas-structure`에 올린다. 실계정 검증은 별도 항목이다.

| 단계 | 상태 | 구현 | 검증 |
| --- | --- | --- | --- |
| 1. B 기반 | 구현 | 연결 상태 통합·만료 입력(19c7ce0), 운영 이벤트·heartbeat·SIEM 전송 운영, compose·Helm 상시 출력기(7cfe923), 운영 탭(2e03a70) | 합성·PostgreSQL·웹·브라우저 검사. kind(쿠버네티스 1.37)에서 API·worker 2개·SIEM 출력기 실제 기동, 한 replica만 매분 `platform.heartbeat`를 보내 jsonl로 전달됨, 재시작 0회 확인(2026-09-28) |
| 1b. 범용 금고 | 구현(대시보드 등록은 화면 개편과 함께) | `external_vault`, JSON Lines 입력과 `--declare-complete`, `cremore.vault_readers`와 내장 `kubernetes_secrets`, 실행별 `completeness`와 `absence_basis`, 연결 자신의 로그인으로 다른 Vault 클러스터 서버 읽기([범용 금고](EXTERNAL_VAULT.md)) | `cremore/coverage/external_vault_test.py`(요청 본문 원문 없음, 선언 없는 실행의 부재 미확정, 가장 약한 근거, 플러그인 허용·거절, 설치 신원 미사용·토큰 파일 경계·리다이렉트·CA) |
| 2. SIEM 통로 | 구현 | `installation_id`, `finding.updated`·`audit.action`·`coverage.verdict_changed`, `http_json` 인증 확장(Bearer·ApiKey, API 키 헤더, 사용자 지정 헤더, OAuth client credentials), 배열 본문·query·`{event_id}` 경로, `syslog_tls`(RFC 5424/5425, JSON·CEF·LEEF 2.0, 상호 TLS), OCSF 1.3.0 선택 형식, [필드 매핑](SIEM_FIELD_MAPPING.md) | `cremore/siem/transports_test.py`(가짜 HTTP 수신기, 로컬 TLS syslog 수신기), `formats_test.py`(OCSF 필수 속성·CEF·LEEF 스냅샷), `events_changes_test.py`, `cremore/operations/coverage_verdicts_test.py`. 실제 SIEM 제품 수신은 실환경 검증 항목 |
| 3. IdP 기계 신원 | 구현 | Helm `azure.workloadIdentity`(파드 라벨·서비스 계정 어노테이션)와 `vaultConnections`(Vault 클러스터별 audience 토큰), compose `deploy/compose/identity/`(AWS 웹 신원, Azure 연합, GCP WIF, Vault 로그인), 쿠버네티스 밖 토큰 갱신기 `cremore-token-refresher`, 하트비트·보존 설정 노출, [기계 신원](MACHINE_IDENTITY.md) | `cremore/cli/token_refresher_test.py`, `deploy/helm/tests/chart.test.cjs`, kind에서 Azure 라벨·어노테이션과 worker에만 audience `vault-pay` 토큰이 투사됨 확인. 실제 AWS·GCP·Azure·IdP 연동은 실환경 검증 항목 |
| 4. 퇴사자 점검 | 구현(화면은 개편과 함께) | IdP 수집기 `okta`(private_key_jwt, 선택 DPoP)·`entra_id`·`keycloak`(관리 이벤트 선택)과 GitHub SAML·SCIM 신원 `github_identity`를 공통 수집 엔진(`cremore/identity/idp.py`)으로, 이메일·로그인은 keyed digest로만 저장. 공급자별 소유자 함수(GitHub·GitLab·Azure DevOps·Atlassian·Notion·AWS), 정확 연결과 후보·관리자 확정, 판정 네 가지, `identity.credential_orphaned`, `DEPARTED_OWNER` 티켓, AWS 키 비활성화 계획(`OWNER_DEPARTED`), 보존 `LEAVER_RETENTION_DAYS`·수집 이력 30일, API([퇴사자 점검](LEAVER_CHECK.md)) | IdP 수집기·소유자 함수 테스트, `cremore/identity/leavers_test.py`(메모리·SQLite), `cremore/api/leavers_routes_test.py`, 로컬 Keycloak 26.3 실서버 수집과 판정(2026-09-28). 실제 Okta·Entra ID·GitHub 조직 연동은 실환경 검증 항목 |
| 5. C 변경 감지 | 구현(화면은 개편과 함께) | 변경 조회기 GitHub(compare)·GitLab(merge base·compare)·Azure DevOps(`diffs/commits`)·Bitbucket Cloud(`diffstat`·merge base)·Data Center(`changes`, 연결별 `max_changes`)·Confluence(CQL 수정 시각), 공급자별 주기(기본 5분)와 `SCAN_CHANGE_FEEDS_MODE`, 커서 테이블 `scan_change_cursors`, 이력 재작성의 BASELINE과 일일 RECONCILE. 리비전 재사용을 GitLab·Azure DevOps(blob ID)·GCS(generation)·Azure Blob(ETag)·Confluence 첨부로 확대하고 worker 스캔은 읽기를 미룬다. 큐 소비를 SQS·Pub/Sub·Service Bus 공용으로 일반화하고 Cloud Storage 알림, Event Grid Blob 이벤트, Azure DevOps `git.push` 후크, GitHub·GitLab·Bitbucket 푸시를 읽는다([변경 감지 스캔](CHANGE_FEEDS.md)) | `cremore/scanning/changes_test.py`, `cremore/scanning/queues_test.py`, 공급자별 변경·알림 테스트(Bitbucket 한도·555·지난 커밋 없음 포함), `cremore/collectors/enterprise_test.py`(바뀌지 않은 blob 미다운로드), `cremore/worker/runtime_test.py`(BASELINE 이벤트). 실제 공급자 API와 Pub/Sub·Service Bus·Event Grid 연동은 실환경 검증 항목 |
| 6. A 통합 온보딩 | 서버 구현(화면은 개편과 함께) | 공급자 연결 모델(`provider_connections`, `provider_connection_children`), 카탈로그와 공급자 16종의 descriptor·권한 점검·레코드 함수(`<vendor>/.../onboarding.py`), 4단계 API와 `provider-check` worker 작업, 한 트랜잭션의 2·4단계, 중지된 연결의 레코드 인계와 번호 붙인 소스 이름, 사용 중 인증 방식 고정, 용도별 계획(값 읽기·이전 버전·감사·GitLab 인스턴스·GCP 조직·폴더와 Azure 구독 찾기·Storage 키 지문·Vault accessor·lease), 고객 환경 CLI(AWS·GCP·Vault), AWS 발견 계정 편입, 기존 등록 창구 제거([공급자 연결](ONBOARDING.md)) | `cremore/onboarding/*_test.py`(모든 공급자·에디션·방식·용도와 계획 항목을 켠 레코드가 실행할 저장소의 검증 통과, 모의 서버 권한 점검, 메모리·SQLite·PostgreSQL 마법사 전 과정과 실패 시 되돌림), 옛 등록 경로를 쓰던 API 테스트 이전. 웹 마법사와 브라우저 검사는 화면 개편과 함께. 실제 공급자 계정의 점검·수집은 실환경 검증 항목 |

## 11. 관련 문서

[SIEM 출력 연동](SIEM_INTEGRATION.md), [SIEM 구현 보고서](SIEM_IMPLEMENTATION_REPORT.md),
[공통 정규화 설계](UNIFIED_METADATA_CONTRACT.md), [AWS 인벤토리 계약](AWS_CREDENTIAL_INVENTORY_PLAN.md),
[봉인 키 보관](CREDENTIAL_ROOTS.md), [값 읽기 정책(제안)](SECRET_VALUE_READING_POLICY.md).
