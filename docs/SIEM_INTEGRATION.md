# SIEM 출력 연동과 팀별 플러그인

CreMore는 새 finding의 최초 관측, finding의 상태 변화, 관리자 활동, 금고 대조 판정 변화와 연결 상태 변화(운영 이벤트)를
DB에 저장하고, 별도 `cremore-siem` 프로세스가 정제된 이벤트를 관제 시스템에 전달한다.
SIEM별 필드 대응은 [필드 매핑](SIEM_FIELD_MAPPING.md)을 본다. 수집기·자격증명 검증·조치 실행과 분리된 출력 경로다.
이 문서는 현재 구현과 설정을 설명한다. 검증 범위와 남은 제약은
[구현 보고서](SIEM_IMPLEMENTATION_REPORT.md)를 참고한다.

## 1. 전달하는 이벤트의 범위

업그레이드된 API/worker가 **finding을 처음 생성할 때** `finding.created` 이벤트 하나를
같은 저장 트랜잭션에 기록한다. 그 뒤의 상태 변화는 `finding.updated`로 따로 보낸다(아래).
`finding.created`는 생성 시점의 스냅샷으로 남고 바뀌지 않는다. 담당자 변경은 이벤트를 만들지 않는다.
업그레이드 이전 finding의 과거 이력을 채우는 backfill은 없다.
기존 credential에 대해 처음 finding이 만들어지는 경우에는 그 새 finding이 대상이다.

이벤트는 생성 당시의 관측이다. 이후 검증·오탐 판정·조치가 반영된 현재 상태나
**발견한 자격증명이 실제로 유효하다는 보증이 아니다.** 관제 규칙에서도 발견과 유효성 확인을 구분한다.

예시 payload는 다음과 같다. UUID는 예시이며 실제 AWS 계정 번호나 키가 아니다.

```json
{
  "schema_version": 1,
  "event_id": "b21e4c6a-ce3f-54e7-9320-02d31ddc9568",
  "event_type": "finding.created",
  "occurred_at": "2026-09-24T03:00:00Z",
  "product": "CreMore",
  "finding": {
    "id": "11111111-1111-4111-8111-111111111111",
    "credential_id": "22222222-2222-4222-8222-222222222222",
    "severity": "HIGH",
    "workflow_status": "OPEN"
  },
  "credential": {
    "provider": "github",
    "credential_type": "GITHUB_TOKEN",
    "status": "UNKNOWN"
  },
  "exposure": {
    "id": "33333333-3333-4333-8333-333333333333",
    "source_type": "github",
    "source_connection_id": "44444444-4444-4444-8444-444444444444",
    "aws_account_id": null,
    "line_number": 12
  }
}
```

필드는 허용 목록으로 생성한다. 원문 자격증명, identifier와 마스킹 hint, fingerprint,
코드·문맥·redacted line, 파일 경로·리소스 이름·URL, principal·사용자 입력·임의 metadata는
내보내지 않는다. 공급자/자격증명 종류는 알려진 catalog 코드만 쓰며 알 수 없으면 `UNKNOWN`,
사용자 정의 탐지기의 종류는 `CUSTOM`이다. 위치 정보는 내부 UUID, 알려진 source 종류,
범위가 제한된 행 번호만 포함한다. `exposure.aws_account_id` 역시 플랫폼 내부 UUID다.

SOC가 상세 정보를 조회할 때는 신뢰하는 CreMore 주소와 `finding.id` UUID로
기존 인증된 `GET /api/v1/findings/{finding_id}`를 사용한다. SIEM 이벤트가 제공한 임의 URL을
따라가는 방식은 쓰지 않는다. 이 조회에는 별도의 사용자/API 권한이 필요하며 exporter의
DB 계정은 finding 상세 조회 권한을 갖지 않는다.

### 운영 이벤트

worker는 1분마다 연결 상태(`GET /api/v1/operations/connections`와 같은 판정)를 계산하고,
**상태가 바뀔 때만** 아래 이벤트를 같은 outbox에 기록한다. worker 복제본이 여러 개여도 1분 슬롯을
DB 설정 행 잠금으로 한 곳만 차지하므로 한 번만 판정한다. 직전에 보낸 상태를 저장해 같은 상태를
반복해서 보내지 않고, 이벤트를 기록한 뒤 상태를 저장하므로 중간에 멈춰도 같은 `event_id`로 다시 만들어져 한 번만 남는다.

| event_type | 보내는 때 |
| --- | --- |
| `connection.auth_failed` | 인증 상태가 `REAUTH_REQUIRED`·`PERMISSION_LIMITED`·`SECRET_UNAVAILABLE`이 되거나 그 사이에서 바뀜 |
| `connection.auth_recovered` | 위 상태에서 `READY`·`EXPIRING`으로 돌아옴 |
| `connection.auth_expiring` | 스스로 갱신하지 않는 자격증명의 만료가 14일, 3일 이내로 들어옴 |
| `collection.failed` | 마지막 수집이 실패로 바뀜(연속 실패는 한 번만) |
| `collection.stale` | 마지막 성공 이후 신선도 기준을 넘음 |
| `collection.recovered` | 실패(`recovered_from: FAILED`)나 오래됨(`STALE`)에서 회복 |
| `siem.delivery_backlog` | 한 목적지가 밀림: 보류 이벤트가 있거나, 연속 실패 5회 이상이거나, 15분 넘게 기다린 이벤트가 있음. `delivery`에 목적지 ID·남은 수·보류 수·가장 오래 기다린 초·연속 실패·오류 코드 |
| `siem.delivery_recovered` | 그 목적지가 다시 따라잡음 |

### 탐지 변경 `finding.updated`

finding의 상태가 실제로 바뀐 트랜잭션 안에서 한 번 기록한다. `change`는 바뀐 이유다.

| `change` | 보내는 때 |
| --- | --- |
| `WORKFLOW` | 분석가가 처리 상태를 바꿈(확인·해결·오탐·무시·재개) |
| `VERIFICATION` | 검증 결과로 자격증명 상태가 바뀜(`Active`·`Inactive`·`Revoked`·`Expired`) |
| `ROLLUP` | 스캔이 노출 위치를 다시 모아 처리 상태나 심각도가 바뀜 |

같은 상태로 다시 저장하면 보내지 않는다. `event_id`는 finding·변경 종류·변경 시각·전후 상태에서 정해진다.
분석가 메모(해결 사유)와 담당자 이름은 넣지 않는다.

```json
{
  "schema_version": 1, "event_id": "c21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "finding.updated",
  "occurred_at": "2026-09-25T03:00:00Z", "product": "CreMore", "installation_id": "0b5c6a0e-8a8f-4d9a-9e5b-2c0a4e1f7b62",
  "change": "WORKFLOW",
  "finding": {"id": "11111111-1111-4111-8111-111111111111", "credential_id": "22222222-2222-4222-8222-222222222222",
              "severity": "HIGH", "previous_severity": null, "workflow_status": "RESOLVED", "previous_workflow_status": "OPEN"},
  "credential": {"provider": "github", "credential_type": "GITHUB_TOKEN", "status": "Revoked", "previous_status": null}
}
```

### 관리자 활동 `audit.action`

감사 기록에 남는 사람의 조치(범위 승인, 설정 변경, 조치 승인, 연결 토큰 교체 등)를 같은 트랜잭션에서 보낸다.
키 조치 계획은 요청·승인·실행 접수·실행 시작·검증·실패·결과 불명·재확인·취소(`ACTION_PLAN_*`, worker가 실행하는 다른 공급자
자격증명의 계획은 `ACTION_PLAN_QUEUED`와 상태 `QUEUED`도)와 거절된 시도(`ACTION_PLAN_REFUSED`)를
계획 변경과 같은 트랜잭션에서 남기며 `target_type`은 `action_plan`이다(발급 목록 항목에 대한 계획 요청 거절은 `coverage_entity`). 키 소유자의 승인 요청·결정·기록(`OWNER_APPROVAL_*`),
긴급 차단(`ACTION_PLAN_EMERGENCY`)과 사후 통지(`OWNER_NOTIFIED_AFTER`, 보내지 못하면 `OWNER_NOTICE_NOT_SENT`)도 같은 대상으로 남기며, 링크로 결정한 소유자의
`actor_ref`는 그 사람의 로그인 주체에서 만든다. 회사 티켓 시스템 플러그인에서 물은 승인은 티켓 열림(`OWNER_APPROVAL_TICKET_OPENED`), 물은 계정이 아닌
사람의 응답(`OWNER_APPROVAL_TICKET_REFUSED`)도 남기고, 그 결정의 `actor_ref`는 티켓 시스템의 계정(`<system>:user:<id>`, 2026-10-12 전 GLPI는
`glpi:user:<id>`)에서 만든다. 대응 요청을 링크로 보내면 `RESPONSE_LINK_SENT`, 보내지 못하면 `RESPONSE_NOT_SENT`(상태 `NOT_SENT`)를 남기고,
링크 화면의 응답은 담당자의 로그인 주체에서 `actor_ref`를 만든다. 받는 사람의 주소·링크·메시지 본문은 보내지 않는다. 티켓 시스템
설정 저장·확인은 `TICKET_SYSTEM_SAVED`·`TICKET_SYSTEM_CHECKED`(`target_type` `ticket_system`)다.
소유자 조사 변경(`OWNERSHIP_REVIEW_UPDATED`)은 저장한 조사마다 한 건이며 `from_status`·`to_status`는 finding 처리 상태가 아니라 조사 상태
(`OPEN`, `IN_PROGRESS`, `WAITING_OWNER`, `CLOSED`)다. 스캐너·스케줄러처럼 사람이 아닌 기록은 보내지 않는다. `actor_ref`는 로그인 주체에서 만든 고정 UUID라
같은 사람의 조치를 묶을 수 있지만, 이름·이메일·IdP subject와 감사 메모는 넣지 않는다. 누가 했는지는
CreMore 감사 기록(`GET /api/v1/audit`)에서 확인한다.

```json
{
  "schema_version": 1, "event_id": "d21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "audit.action",
  "occurred_at": "2026-09-25T04:00:00Z", "product": "CreMore", "installation_id": "0b5c6a0e-8a8f-4d9a-9e5b-2c0a4e1f7b62",
  "audit": {"id": "55555555-5555-4555-8555-555555555555", "action": "COVERAGE_VAULT_TOKEN_SET",
            "target_type": "coverage_connection", "target_id": "66666666-6666-4666-8666-666666666666",
            "finding_id": null, "actor_ref": "77777777-7777-5777-8777-777777777777", "from_status": null, "to_status": null}
}
```

### 금고 대조 판정 `coverage.verdict_changed`

worker 하나가 5분마다 `GET /api/v1/coverage`와 같은 대조를 계산해, 노출되거나 발급된 자격증명마다 판정
(`MATCHED`, `NO_VAULT_MATCH`, `UNKNOWN`, `IDENTIFIER_ONLY`, `IDENTIFIER_NOT_OBSERVED`, 공개 인증서 판정)이
바뀌거나 새로 생기면 보낸다. 처음 실행은 기준만 기록하고 보내지 않는다. 금고 대조 범위를 확인하지 않은 동안에는
대조가 멈춘 것으로 보고 보내지도 기록하지도 않는다. 한 번에 최대 500건이고 나머지는 다음 주기에 이어서 보낸다.
판정 행은 내부 UUID와 고정 참조(`ref`)로만 가리키며 키 ID·경로·지문은 넣지 않는다. 부재 판정에는
[근거 수준](EXTERNAL_VAULT.md#1-부재-판정의-근거-수준)(`absence_basis`)을 함께 보낸다.

```json
{
  "schema_version": 1, "event_id": "e21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "coverage.verdict_changed",
  "occurred_at": "2026-09-25T05:00:00Z", "product": "CreMore", "installation_id": "0b5c6a0e-8a8f-4d9a-9e5b-2c0a4e1f7b62",
  "verdict": {"ref": "88888888-8888-5888-8888-888888888888", "origin": "EXPOSURE",
              "credential_id": "22222222-2222-4222-8222-222222222222", "finding_id": "11111111-1111-4111-8111-111111111111",
              "entity_id": null, "credential_type": "GITHUB_TOKEN", "state": "NO_VAULT_MATCH", "previous_state": "MATCHED",
              "match_basis": "NONE", "absence_basis": "API_LISTING"}
}
```

### 탐지 전달 `finding.forwarded`

분석가가 Credential 상세의 "웹훅 이벤트 보내기"로 확인한 뒤 finding을 지금 상태 그대로 모든 SIEM·웹훅 출력에 보낸다
(`POST /api/v1/findings/{finding_id}/forward`). `event_id`는 보낸 사람·finding·분마다 하나라 1분 안에 다시 누르면 같은 이벤트이고
한 번만 쌓인다. `change`는 `FORWARDED`, 상태는 바뀌지 않았으므로 `previous_workflow_status`는 지금 상태와 같다. 이름·메모·위치와
보낸 사람은 넣지 않는다. 요청은 같은 트랜잭션에서 감사 기록(`FORWARDED_TO_SIEM`)에 남고, 보낸 사람은 함께 가는 `audit.action`의
`actor_ref`에 있다. Splunk sourcetype은 다른 탐지 이벤트와 같은 `cremore:finding`이다. 30일 넘게 exporter가 보고하지 않은
목적지는 없는 것으로 보고, 받을 곳이 없으면 `409 SIEM_NOT_CONFIGURED`다.

```json
{
  "schema_version": 1, "event_id": "a31e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "finding.forwarded",
  "occurred_at": "2026-09-29T05:00:00Z", "product": "CreMore", "installation_id": "0b5c6a0e-8a8f-4d9a-9e5b-2c0a4e1f7b62",
  "change": "FORWARDED",
  "finding": {"id": "11111111-1111-4111-8111-111111111111", "credential_id": "22222222-2222-4222-8222-222222222222",
              "severity": "HIGH", "workflow_status": "OPEN", "previous_workflow_status": "OPEN"},
  "credential": {"provider": "github", "credential_type": "GITHUB_TOKEN", "status": "UNKNOWN"}
}
```

### 퇴사자 자격증명 `identity.credential_orphaned`

worker 하나가 5분마다 [퇴사자 점검](LEAVER_CHECK.md)을 평가해, 퇴사한 사람과 이어진 자격증명의 판정
(`USED_AFTER_DEPARTURE`, `ACTIVE`, `REVOKED_OR_EXPIRED`, `UNKNOWN`)이 새로 생기거나 바뀌면 보낸다. 이미 꺼진 채 처음 본
자격증명은 보내지 않는다. 한 번에 최대 500건이다. 사람·계정·자격증명은 내부 참조로만 가리키며 이메일·로그인·IdP 사용자 ID·
키 ID는 넣지 않는다. 공급자가 사용자의 모든 자격증명을 나열하지 않는 계정 행은 `credential_ref`가 계정 참조다.

```json
{
  "schema_version": 1, "event_id": "f31e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "identity.credential_orphaned",
  "occurred_at": "2026-09-28T05:00:00Z", "product": "CreMore", "installation_id": "0b5c6a0e-8a8f-4d9a-9e5b-2c0a4e1f7b62",
  "orphan": {"ref": "99999999-9999-5999-8999-999999999999", "verdict": "USED_AFTER_DEPARTURE", "previous_verdict": null,
             "credential_ref": "44444444-4444-4444-8444-444444444444", "person_ref": "33333333-3333-5333-8333-333333333333",
             "provider": "NOTION", "credential_type": "NOTION_PERSONAL_ACCESS_TOKEN",
             "departed_at": "2026-09-18T08:00:00Z", "departure_basis": "PROVIDER_REPORTED", "link_basis": "VERIFIED_EMAIL",
             "last_used_at": "2026-09-26T02:10:00Z", "exposed": false, "vault_state": "NO_VAULT_MATCH"}
}
```

### 설치 ID

모든 이벤트에 설치마다 한 번 무작위로 만든 `installation_id`(UUID)를 넣는다. 여러 설치를 한 SIEM에 모을 때
설치를 구분하는 값이며, 관리자는 `GET /api/v1/siem/status`에서 확인한다. 이 값을 기록하는 쪽은 API·worker이고
exporter는 설치 설정을 읽지 않는다.

`siem.test`는 관리자가 요청한 시험 이벤트이며 `test.nonce` UUID 하나만 담는다.
처음 판정한 연결이 이미 실패·오래됨 상태면 그 상태를 한 번 보낸다. 운영자가 중지한 연결(`DISABLED`)은 보내지 않는다.
필드는 허용 목록이며 연결 이름·경로·공급자 응답·비밀은 넣지 않는다. 공급자는 코드에 정의된 이름만, 사유는
`^[A-Z][A-Z0-9_]*$` 형태의 코드만 쓴다. SOC는 `connection.id`와 `kind`로 인증된 연결 상태 API를 조회한다.

```json
{
  "schema_version": 1,
  "event_id": "5e0b1a57-0d8e-5c1f-9a44-0b0c7d3f2e11",
  "event_type": "connection.auth_failed",
  "occurred_at": "2026-09-27T10:36:00Z",
  "product": "CreMore",
  "connection": {"id": "44444444-4444-4444-8444-444444444444", "kind": "CONTENT", "provider": "github"},
  "health": {
    "auth_state": "REAUTH_REQUIRED", "previous_auth_state": "READY", "reason": "GITHUB_APP_REJECTED",
    "auth_renewal": "AUTO", "expiry_stage": "NONE", "expires_at": null, "freshness": "FRESH",
    "last_status": "COMPLETE", "last_success_at": "2026-09-27T10:20:00Z", "last_failure_code": null,
    "recovered_from": null
  }
}
```

### 생존 신호 `platform.heartbeat`

worker 하나가 `OPERATIONS_HEARTBEAT_MINUTES`(기본 5분, 1~60) 주기마다 `platform.heartbeat`를 한 번 기록한다.
복제본이 여러 개여도 주기 슬롯을 한 곳만 차지하며, `event_id`는 주기와 슬롯에서 정해진다. 내용은 살아 있는 worker 수,
대기 작업 수, 가장 오래 기다린 작업의 대기 초뿐이고 호스트 이름이나 worker ID는 넣지 않는다.
SIEM에서는 **두 주기 동안 이 이벤트가 오지 않으면 경보**를 거는 규칙을 둔다. CreMore 전체, DB, `cremore-siem` 중 어느 것이
멈춰도 이벤트가 끊기므로, CreMore가 스스로 중단을 알리지 못하는 경우도 잡는다.

```json
{
  "schema_version": 1,
  "event_id": "0f3c3a5e-8a8f-5d9a-9e5b-2c0a4e1f7b62",
  "event_type": "platform.heartbeat",
  "occurred_at": "2026-09-27T10:40:00Z",
  "product": "CreMore",
  "platform": {"interval_seconds": 300, "workers_alive": 2, "queued_jobs": 0, "oldest_queued_seconds": null}
}
```

### 감사 기록 체인 앵커 `audit.chain_anchor`

감사 기록의 모든 행은 worker가 1분마다 키 해시 체인으로 봉인한다. 각 행의 MAC은 순번, 내용, 앞 행의 MAC을 덮는다.
키는 `AUDIT_CHAIN_KEY`, 없으면 `FINGERPRINT_KEY`에서 파생하며 DB에 두지 않는다. API·worker가 쓰는 행에는 쓰는 순간의
MAC도 붙어 DB에 직접 넣은 행을 가려낸다. worker 하나가 1시간마다 체인 전체를 검증해, 체인 안에 앵커 행(체인 끝의 순번·MAC)을
남기고 결과와 체인 시작·앵커 번호·체인 끝을 이 이벤트로 보낸다. 같은 내용은 worker 로그에도 남긴다(DB가 아닌 사본).
`chain_state`가 `INTACT`가 아니면 심각도 9다. 행 내용·행위자·메모는 넣지 않는다.

DB 쓰기 권한이 있는 사람이 남은 마지막 앵커 뒤의 행을 다시 쓰면서 그 뒤 앵커를 지우고 worker를 다시 시작하거나, 체인 전체의
봉인을 풀고 시작 행과 앵커 행까지 지우면 DB 안에는 비교할 근거가 남지 않는다. 이런 경우는 SIEM이 가진 이전 이벤트로만 드러나므로
다음 경보를 둔다. outbox 사본은 DB만큼만 안전하므로 가능하면 worker 로그 사본으로 평가한다.

- `chain_state != INTACT`, `open_problems` 증가
- `genesis_mac`이 바뀜(체인을 다시 시작함)
- `anchor_no`가 직전 값 + 1이 아님(앵커를 지우거나 되돌림)
- `chain_seq`가 줄어듦
- 두 시간 넘게 이벤트가 오지 않음(생존 신호와 함께 확인)

저장한 앵커는 `GET /api/v1/audit/integrity?anchor_seq=…&anchor_mac=…`로 대조한다.

```json
{
  "schema_version": 1,
  "event_id": "5b0d7f5e-3c5a-5d8e-9f3a-6a2f0c1d7e44",
  "event_type": "audit.chain_anchor",
  "occurred_at": "2026-09-29T04:00:00Z",
  "product": "CreMore",
  "audit": {"chain_state": "INTACT", "chain_seq": 1843, "chain_mac": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "genesis_seq": 212, "genesis_mac": "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752",
            "anchor_no": 37, "open_problems": 0, "problem_seq": null, "problem_reason": null, "unauthenticated": 0, "pending": 2}
}
```

`chain_state`는 `INTACT`, `BROKEN`, `UNAUTHENTICATED`(CreMore 프로세스가 쓰지 않은 행), `ANCHOR_MISMATCH`, `UNKNOWN`(검증 실패)이다.
`BROKEN`의 `problem_reason`은 `SEQUENCE_GAP`(삭제), `SEQUENCE_INVALID`(체인에 없는 위치), `MAC_MISMATCH`(변경),
`ANCHOR_CLAIM_MISMATCH`(봉인을 풀었다가 다시 봉인),
`ANCHOR_SEQUENCE_GAP`(앵커 삭제), `CHAIN_REWOUND`(worker가 봉인한 끝이 옮겨짐), `CHAIN_RESET`(체인 위치가 사라짐),
`GENESIS_MISSING`(체인 시작 삭제), `GENESIS_INVALID`(봉인기가 쓰지 않은 시작 행), `GENESIS_MOVED`(시작 앞 행이 다시 봉인돼 시작이 옮겨짐), `KEY_MISMATCH`(이 키로 검증되는 행이 없음)이다. 관리자가 확인한 문제는 점검 결과의 `ack` 값으로
`POST /api/v1/audit/integrity/acknowledge`에 보내 수용한다. 수용은 문제의 종류·위치·내용에 묶인다. 간격은 그 범위와 앞 행의 MAC,
바로 뒤 행에 묶여 간격이 넓어지거나 뒤 행이 바뀌면 다시 열린다. CreMore가 쓰지 않은 행은 ID와 내용에 묶여 봉인 전후에 같게 적용된다.
수용 자체도 체인에 남는다. `CHAIN_REWOUND`·`GENESIS_MOVED`·`ANCHOR_CLAIM_MISMATCH`는 점검 결과만으로 확인할 수 없으므로 백업이나
SIEM이 가진 이전 이벤트와 비교한 뒤에만 수용한다.

## 2. 기본 출력기와 실제 수신 계약

| provider | 전송과 성공 조건 | 설정 예제 |
| --- | --- | --- |
| `jsonl` | 이벤트 하나를 stdout의 compact JSON 한 줄로 쓰고 flush | [JSONL](../deploy/siem/jsonl.example.json) |
| `http_json` | 지정한 HTTPS URL에 이벤트 자체를 POST; HTTP 2xx | [HTTP JSON](../deploy/siem/http-json.example.json) |
| `splunk_hec` | `/services/collector/event`에 HEC envelope; HTTP 200 및 JSON의 정수 `code: 0` | [Splunk HEC](../deploy/siem/splunk-hec.example.json) |
| `logscale` | `/api/v1/ingest/humio-structured`에 structured envelope; **HTTP 200만** 성공 | [Falcon LogScale](../deploy/siem/logscale.example.json) |
| `syslog_tls` | RFC 5424 메시지를 RFC 5425(TLS, 기본 6514) octet-counting 프레임으로 전송. 본문은 JSON·CEF·LEEF 2.0; TLS 스트림에 쓰기가 끝나면 성공 | [QRadar LEEF](../deploy/siem/syslog-qradar-leef.example.json), [ArcSight CEF](../deploy/siem/syslog-arcsight-cef.example.json) |

`http_json`으로 받는 예: [Microsoft Sentinel(Logs Ingestion API, OAuth)](../deploy/siem/sentinel.example.json),
[Elasticsearch(`_create/{event_id}`)](../deploy/siem/elasticsearch.example.json), [Datadog](../deploy/siem/datadog.example.json).
[OCSF로 받는 예](../deploy/siem/ocsf.example.json)도 있다.

Splunk envelope는 `event`, UTC Unix 초인 `time`, `source: cremore`와 이벤트 종류별 `sourcetype`이다.
`finding.created`·`finding.updated`·`finding.forwarded`는 기존과 같은 `cremore:finding`, 운영 이벤트는 `cremore:connection`, `cremore:collection`,
`cremore:platform`, `cremore:siem`, 관리자 활동은 `cremore:audit`, 금고 판정은 `cremore:coverage`, 퇴사자 판정은
`cremore:identity`이며 알 수 없는 종류는 `cremore:other`다. HEC 수신 성공은 indexer acknowledgment나 관제 탐지 규칙 실행
완료가 아니다. 별도 HEC ACK channel/polling은 구현하지 않는다.

LogScale은 `[{"tags":{"source":"cremore","family":"finding"},"events":[{"timestamp":...,"attributes":event}]}]`
형식이다. `family` 태그는 이벤트 종류(`finding`, `connection`, `audit` 등 고정된 몇 가지)라 종류별로 데이터 소스가 나뉜다. 공식 문서는 attributes의 중첩 JSON을 허용한다. 이 출력기는 **Falcon LogScale**
Ingest API용이며 Falcon Next-Gen SIEM의 Connectors 구현이나 모든 CrowdStrike 제품 지원을 뜻하지 않는다.

JSONL 또는 HTTP JSON을 Fluent Bit, Vector, Filebeat, Logstash, Wazuh나 자체 gateway에 연결할 수
있지만 수신 input, 필드 매핑, parser/decoder, deduplication, 관제 규칙은 해당 팀이 구성한다.
CreMore가 이 제품별 native/certified connector를 제공한다는 의미는 아니다.

## 3. 설정

[여러 목적지 예제](../deploy/siem/multi-destination.example.json)는 같은 이벤트를 목적지별로 전달한다.
예제의 `.example` 호스트는 실제 운영 주소로 바꿔야 한다. JSON에는 토큰 값을 넣지 않는다.

| 최상위 필드 | 계약 |
| --- | --- |
| `schema_version` | 기본 `1`, 현재 `1`만 지원 |
| `destinations` | 1–32개; 각 항목은 `id`, `provider`, 선택적 `options` |
| `id` / `provider` | 소문자로 시작하는 소문자·숫자·`_`·`-`, 최대 64자; destination `id`는 유일해야 함 |
| `options` | 기본 `{}`, 최대 32개 키; 각 출력기가 허용하는 키만 사용 |
| `allow_plugins` | 기본 `[]`, 최대 32개; 중복 없이 실제 선택한 외부 provider ID만 명시 |
| `poll_seconds` | 기본 `5.0`, `0.2`–`3600`; 전체 목적지 처리 뒤 다음 반복까지 기다리는 시간 |
| `batch_size` | 기본 `100`, 정수 `1`–`1000`; 반복당 **목적지별 최대 이벤트 수** |
| `max_attempts` | 기본 `0`(상한 없음, 백오프 최대 1시간으로 계속 재시도), `0`–`1000`; 양수면 그 횟수를 실패한 이벤트를 **보류**하고 관리자가 해제할 때까지 다시 보내지 않음 |
| destination `format` | 기본 `native`(schema v1). `ocsf`면 OCSF 1.3.0으로 옮길 수 있는 이벤트(`finding.*`, `identity.credential_orphaned`, `coverage.verdict_changed` → Detection Finding 2004, `audit.action` → API Activity 6003)를 옮기고 나머지(운영 상태·생존 신호·전송 상태)는 `native`로 보낸다. CEF·LEEF 본문과 함께 쓰면 거절한다 |

설정 파일은 최대 128 KiB이고 알 수 없는 최상위/destination 필드는 거절한다.
HTTP 요청은 이벤트당 한 번이다. `batch_size`는 여러 이벤트를 한 HTTP 요청으로 묶는 옵션이 아니다.

HTTP 계열의 공통 옵션은 `endpoint`, `token_env`, `timeout_seconds`, `ca_file`이다.
`endpoint`는 사용자 정보·query·fragment·제어 문자가 없는 HTTPS 절대 URL이어야 한다.
기업 내부 호스트도 사용할 수 있다. URL을 자동으로 조합하지 않으므로 vendor 경로까지 정확히 지정한다.
`timeout_seconds`는 기본 10초, 0초 초과 30초 이하다. `ca_file`은 선택적 PEM CA 파일 경로이며
실행 프로세스/컨테이너에서 읽을 수 있어야 한다. 기본값도 TLS 인증서를 검증한다.

`token_env`는 토큰 값이 아니라 환경 변수 이름이다. Splunk와 LogScale에서는 필수이며 각각
`Authorization: Splunk ...`, `Authorization: Bearer ...`를 사용한다. 토큰은 출력기 생성 시 읽으므로
토큰을 바꾼 뒤 프로세스를 재시작한다. JSONL에는 설정 옵션이 없다. 거절된 자격증명(HTTP 401·403)은
`AUTH_FAILED`로 따로 기록한다.

HTTP JSON은 인증 방식 하나를 고른다. 비밀값은 모두 환경 변수 이름으로 가리킨다.

| 옵션 | 뜻 |
| --- | --- |
| `token_env` + `authorization_scheme` | `Authorization: Bearer <값>` 또는 `ApiKey <값>`(Elasticsearch의 base64 `id:key`) |
| `api_key_header` | `{"name": "DD-API-KEY", "value_env": "DD_API_KEY"}`처럼 API 키 헤더 하나 |
| `oauth` | OAuth 2.0 client credentials(RFC 6749 4.4). `token_url`(HTTPS), `client_id`, `client_secret_env`, 선택 `scope`·`audience`, `auth_method`(`client_secret_post` 기본·`client_secret_basic`). 토큰은 만료 60초 전까지 재사용하고, 401을 받으면 한 번 새로 받아 다시 보낸다. 토큰 발급 실패는 `OAUTH_TOKEN_FAILED` |
| `headers` | 추가 헤더 최대 8개. 값은 `{"value_env": "..."}`로만 받으며 `Host`·`Content-Type`·`Authorization` 등은 바꿀 수 없다 |
| `body` | `object`(기본) 또는 `array`(이벤트 하나를 배열로 감쌈. Sentinel Logs Ingestion API) |
| `query` | 고정 query 매개변수 최대 8개(예: `{"api-version": "2023-01-01"}`) |
| `endpoint`의 `{event_id}` | 경로에 이벤트 ID를 넣는다(Elasticsearch `_create/{event_id}`). 이때 `conflict_is_duplicate: true`면 409를 이미 전달된 것으로 본다 |

Syslog TLS 옵션은 다음과 같다. TLS는 항상 인증서를 검증하고 TLS 1.2 이상만 쓴다.

| 옵션 | 뜻 |
| --- | --- |
| `host`, `port` | 수신기 주소와 포트(기본 6514) |
| `ca_file`, `server_name` | 신뢰할 CA 파일(없으면 시스템 CA), 인증서 이름 확인에 쓸 이름(기본 `host`) |
| `cert_file`, `key_file` | 상호 TLS용 클라이언트 인증서(둘 다 지정) |
| `message_format` | `json`(기본), `cef`(ArcSight), `leef`(QRadar LEEF 2.0, 탭 구분) |
| `framing` | `octet-counting`(기본, RFC 5425) 또는 `lf`(줄바꿈으로 끝내는 수신기) |
| `facility`, `app_name`, `hostname` | RFC 5424 헤더 값. facility 기본 10(보안·권한), app 이름 기본 `cremore` |
| `timeout_seconds` | 연결·쓰기 제한 시간(기본 10초, 최대 30초) |

syslog에는 수신 확인이 없어 TLS 스트림에 쓰기를 마치면 전달로 기록한다. 보내기 전에 수신기가 연결을 닫았는지 확인해
닫혔으면 새로 연결하고, 쓰기에 실패하면 연결을 닫고 다음 재시도에서 다시 연결한다.

리다이렉트, 환경 변수 기반 HTTP proxy, 출력기 내부 재시도는 사용하지 않는다. 응답은 최대 64 KiB로
제한한다. 재시도는 아래의 DB 전달 상태가 담당한다. 인증 토큰·endpoint·응답 원문·예외 원문은
전달 오류 기록에 넣지 않는다.

## 4. 실행과 배포

출력 프로세스는 기본 실행 구성에서 비활성이다. 업그레이드된 writer는 exporter 실행 여부와
무관하게 새 이벤트를 저장하므로, 나중에 exporter를 켜면 저장된 이벤트부터 전달한다.
API/worker를 먼저 배포하고 정상 기동을 확인한다. 이들의 기존 `create_all` 경로가
`siem_events`, `siem_deliveries` 테이블을 추가한다. **Exporter는 DDL을 수행하지 않는다.**

설치된 출력기 이름만 확인하는 명령에는 DB·토큰이 필요 없다. 플러그인 본문도 import하지 않는다.

```bash
cremore-siem --list-sinks
python -m cremore.cli.siem --list-sinks
```

실행에는 별도 `SIEM_DATABASE_URL`과 JSON 파일이 필요하다. PostgreSQL은 동기 드라이버를 명시한다.
예를 들어 `postgresql+psycopg://cremore_siem@db.internal:5432/cremore?sslmode=verify-full` 형식이다.
실제 DB 인증·CA는 운영 환경에서 별도로 주입한다. `DATABASE_URL`로 대체되지 않는다.
source 수집 토큰, `FINGERPRINT_KEY`, 봉인 키, AWS scanner 자격증명은 exporter에 주입하지 않는다.

환경을 준비한 뒤 저장소 루트에서 다음 중 필요한 명령을 실행한다.

```bash
cremore-siem --config deploy/siem/jsonl.example.json --once
cremore-siem --config deploy/siem/jsonl.example.json
```

`--once`는 목적지마다 최대 한 batch를 처리하고 종료한다. 대기열 전체를 비우는 명령이 아니다.
전송 실패 또는 lease 유실이 있으면 종료 코드 1, 해당 반복에서 문제가 없으면 0이다.
이벤트가 없거나 다음 재시도 시간이 아직 오지 않았어도 0일 수 있다. 이벤트는 stdout,
운영 로그는 stderr로 분리되므로 JSONL shipper는 stdout을 수집한다.

Compose의 [exporter 파일](../deploy/compose/siem/compose.yml)을 포함하면 exporter가 나머지 서비스와 함께 상시 실행되고
멈추면 스스로 재시작한다(`restart: unless-stopped`, 읽기 전용 파일시스템, `no-new-privileges`).
`SIEM_DATABASE_URL`, JSON 파일의 **절대 경로**인 `SIEM_CONFIG_PATH`, 선택한 목적지의
`SIEM_HTTP_TOKEN` / `SPLUNK_HEC_TOKEN` / `LOGSCALE_INGEST_TOKEN`을 운영 환경에 준비한다. 앞의 둘이 없으면 시작을 거절한다.
현재 코드로 `cremore-python` 이미지를 빌드하고 API/worker 업그레이드를 마친 뒤 실행한다.

```bash
docker compose -f docker-compose.yml -f deploy/compose/siem/compose.yml up -d
```

여러 사람이 쓰는 서버는 [공개 overlay 안내](../deploy/compose/reverse-proxy/README.md)의 6단계처럼 공개 overlay와 이 파일을
함께 포함한다. exporter는 매 반복마다 `SIEM_HEARTBEAT_FILE`(기본 `/tmp/cremore-siem.heartbeat`)을 갱신한다.

이 문서의 배포 명령은 실행 예시다. override는 config를 읽기 전용으로 mount하고 source credential
mount를 상속하지 않는다. 사용자 CA 파일이나 외부 플러그인이 필요하면 별도 image/mount 구성을 추가한다.
Helm chart는 `siem.enabled=true`일 때 exporter Deployment를 만든다. `siem.config`에 목적지 JSON을,
`siem.databaseUrlSecret`에 제한된 역할의 URL이 든 기존 Secret을, `siem.tokenSecretName`에 토큰 Secret을 지정한다
(각 키가 같은 이름의 환경 변수가 되어 `token_env`가 가리킨다). ServiceAccount 토큰은 mount하지 않고, 스캐너 비밀·
fingerprint 키는 받지 않는다. 설정이 바뀌면 checksum annotation으로 재시작하며, 생존 파일이 15분 넘게 갱신되지 않으면
liveness probe가 재시작한다. NetworkPolicy는 DNS·DB와 `siem.egressPorts`(기본 `[443]`, Splunk HEC는 흔히 `8088`)로만
`networkPolicy.httpsEgressCIDRs`(또는 `httpsCIDR`)에 나가게 한다.

### PostgreSQL 최소 권한 예시

아래는 DBA가 검토·적용할 SQL 예시이며 CreMore가 실행하는 SQL이 아니다.
이미 생성된 database/schema/전용 role 이름으로 `YOUR_DATABASE`, `YOUR_SCHEMA`,
`YOUR_EXPORTER_ROLE`을 바꾼다. role 생성·비밀번호 설정은 조직의 기존 절차를 따른다.

```sql
GRANT CONNECT ON DATABASE "YOUR_DATABASE" TO "YOUR_EXPORTER_ROLE";
GRANT USAGE ON SCHEMA "YOUR_SCHEMA" TO "YOUR_EXPORTER_ROLE";
GRANT SELECT, UPDATE (event_id) ON TABLE "YOUR_SCHEMA".siem_events TO "YOUR_EXPORTER_ROLE";
GRANT SELECT, INSERT, UPDATE ON TABLE "YOUR_SCHEMA".siem_deliveries TO "YOUR_EXPORTER_ROLE";
GRANT SELECT, INSERT, UPDATE ON TABLE "YOUR_SCHEMA".siem_destination_status TO "YOUR_EXPORTER_ROLE";
```

`siem_destination_status`에는 목적지 ID별 마지막 확인·성공·실패 시각, 오류 코드, 연속 실패 수만 기록한다.
이 권한이 없어도 전달은 계속되며 exporter는 `SIEM_STATUS_WRITE_FAILED`만 남긴다(상태 화면이 비어 보인다).

`UPDATE(event_id)`는 PostgreSQL의 `SELECT ... FOR UPDATE` row lock에 필요한 권한이다.
Exporter는 이벤트 payload를 변경하지 않는다. scanner 테이블, 테이블 생성·삭제, delivery 삭제 권한은
필요 없다. 별도 schema라면 DB 연결의 search path도 일치시킨다. 기존 role의 상속 권한은 별도로 확인한다.

## 5. 재시도, 목적지 변경, 보존과 롤백

전송은 at-least-once다. 목적지가 받은 직후 exporter가 종료되거나 DB ACK를 기록하지 못하면
같은 `event_id`로 다시 보낼 수 있다. 수신 측에서 설치별 출처와 `event_id`로 중복을 처리한다.
서로 다른 설치를 한 SIEM에 모으면 payload의 `installation_id`로 설치를 구분한다.

목적지별 lease·시도 횟수·재시도 시간·ACK를 DB에 저장한다. 한 번에 목적지당 이벤트 하나를
60초 lease로 claim하며 성공 ACK는 현재의 만료되지 않은 token일 때만 반영한다.
실패하면 bounded exponential delay 후 재시도하고 해당 목적지의 이번 batch를 중단한다.
다른 목적지의 batch는 계속 처리한다. 목적지는 순차 처리하므로 느린 출력기를 위한 별도 병렬 실행은 없다.
설정·플러그인 초기화 오류는 전체 exporter 시작을 실패시킨다.

stdout flush는 downstream shipper의 수신 ACK가 아니고, HTTP 성공은 SIEM의 최종 색인·알림 성공
보증이 아니다. 특히 지연된 ACK, 프로세스 장애, lease 만료는 중복 가능성을 남긴다.

`siem_events`에는 최초 관측 payload, `siem_deliveries`에는 destination/event별 전달 상태가 남는다.
finding이 삭제되어도 이벤트는 보존된다.

보존 정리는 worker 하나가 1시간에 한 번 한다. **최근 30일 안에 exporter가 기록한 모든 목적지가 전달받은 이벤트만** 지우며,
그런 목적지가 없으면 나이만 본다. `platform.heartbeat`와 `siem.test`는 7일 뒤 지운다. 그 밖의 이벤트(finding, 연결 상태)는
`SIEM_EVENT_RETENTION_DAYS`(기본 `0`, 보존)를 지정했을 때 그 일수가 지나면 지운다. 새 destination `id`는 남아 있는 이벤트만 받으므로,
보존 기간을 줄이면 새 목적지가 받을 과거 이력도 줄어든다. 백업·DB 용량 정책은 운영자가 관리한다.

기본은 재시도 상한이 없다. SIEM이 오래 멈췄다가 살아나도 쌓인 이벤트가 사람 개입 없이 전달되게 하려는 것이다.
`max_attempts`를 양수로 두면 그 횟수를 실패한 이벤트를 보류(`held_at`)하고 더 보내지 않는다. 다른 이벤트는 계속 흐른다.
관리자 API로 상태를 확인하고 조치한다(모두 Admin 전용, 감사 기록).

| 경로 | 내용 |
| --- | --- |
| `GET /api/v1/siem/status` | 목적지별 남은 수(`pending`), 보류 수(`held`), 가장 오래 기다린 이벤트 시각, 마지막 확인·성공·실패 시각, 오류 코드, 연속 실패 수, exporter가 2분 안에 기록했는지(`exporter_active`) |
| `POST /api/v1/siem/test-event` | 모든 목적지로 가는 `siem.test` 이벤트를 넣고 `event_id`를 돌려준다 |
| `GET /api/v1/siem/events/{event_id}/deliveries` | 그 이벤트의 목적지별 시도 수·전달·보류 시각·오류 코드(테스트 이벤트 확인용) |
| `POST /api/v1/siem/destinations/{destination}/release-held` | 그 목적지의 보류 이벤트를 시도 수 0으로 되돌려 다시 보낸다 |

API는 목적지의 endpoint나 토큰을 알지 못한다. exporter가 목적지 ID로 기록한 상태만 읽는다.

동일한 destination `id`를 유지하면 전달 이력을 이어간다. 같은 `id`의 endpoint만 바꿔도 이미
ACK한 이벤트를 다시 보내지 않는다. **새 destination `id`는 보존된 모든 이벤트를 처음부터 받는다.**
목적지를 설정에서 빼도 저장 이력은 지워지지 않으며 같은 ID로 다시 추가하면 이력을 이어간다.

롤백할 때는 먼저 exporter를 중지하고 기존 image/source 롤백 절차를 따른다. 새 테이블을 삭제하지 않는다.
구버전 API/worker는 새 SIEM 이벤트를 기록하지 않으므로 그 기간에 생성된 finding에는 공백이 생기며,
다시 업그레이드해도 자동 backfill하지 않는다. 보존된 이벤트는 이후 재개할 수 있다.

## 6. 팀별 trusted sink 패키지

외부 플러그인은 출력 전용이며 source collector 등록과 별개다. 공개 계약은
`from cremore.siem import SinkProvider, Sink, DeliveryError`다.
`Sink.send(event: dict) -> None`은 수신 성공 뒤 반환하거나 실패를 던지고,
`close() -> None`은 소유한 자원을 정리한다. 실행기는 정제 이벤트의 복사본만 인자로 넘긴다.
DB repository나 source credential resolver를 플러그인 인자로 전달하지 않는다.

그러나 설치된 Python 코드에는 프로세스 권한이 있다. **이는 sandbox가 아니다.**
신뢰하는 팀의 패키지만 검토·테스트하고 의존성과 wheel hash를 고정해 exporter image에 넣는다.
실행 중 package download/install은 제공하지 않는다. exporter 자체의 DB·출력용 권한도 최소화한다.

아래는 별도 저장소 `team-cremore-siem`에서 그대로 구성할 수 있는 작은 JSONL plugin 예시다.
팀별 배포·검사를 시작하는 예시이며 외부 제품 연동 완료를 뜻하지 않는다.

`pyproject.toml`:

```toml
[build-system]
requires = ["hatchling==1.27.0"]
build-backend = "hatchling.build"

[project]
name = "team-cremore-siem"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["cremore==0.1.0"]

[project.entry-points."cremore.siem_sinks"]
team_jsonl = "team_cremore_siem:PROVIDER"

[tool.hatch.build.targets.wheel]
packages = ["src/team_cremore_siem"]
```

`src/team_cremore_siem/__init__.py`:

```python
import json
import sys
from collections.abc import Mapping

from cremore.siem import DeliveryError, Sink, SinkProvider


class TeamJsonlSink:
    def send(self, event: dict) -> None:
        try:
            line = json.dumps({"integration": "soc_team", "event": event},
                              ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except Exception:
            raise DeliveryError("TEAM_OUTPUT_FAILED") from None

    def close(self) -> None:
        return None  # stdout belongs to the process.


def build(options: Mapping[str, object]) -> Sink:
    if options:
        raise ValueError("TEAM_OPTIONS_INVALID")
    return TeamJsonlSink()


PROVIDER = SinkProvider(id="team_jsonl", build=build,
                        api_version=1, event_schema_versions=(1,))
```

`tests/test_sink.py`:

```python
import json

import pytest

from team_cremore_siem import PROVIDER


def test_jsonl_preserves_event_id_and_does_not_close_stdout(capsys):
    event = {"schema_version": 1, "event_id": "synthetic-event"}
    sink = PROVIDER.build({})
    sink.send(event)
    sink.close()
    print("still-open")
    lines = capsys.readouterr().out.splitlines()
    assert json.loads(lines[0]) == {"integration": "soc_team", "event": event}
    assert lines[1] == "still-open"


def test_rejects_unsupported_configuration():
    with pytest.raises(ValueError, match="^TEAM_OPTIONS_INVALID$"):
        PROVIDER.build({"token": "must-not-be-a-config-secret"})
```

이 SDK를 포함한 CreMore와 pytest가 설치된 격리 개발환경에서 plugin 저장소를 작업 디렉터리로 사용한다.

```bash
python -m pip install --no-deps -e .
python -m pytest -q
python -m pip wheel --no-deps --wheel-dir dist .
```

패키지 버전 pin과 함께 **이 SDK를 포함하는 실제 CreMore wheel** 및 plugin wheel의 hash도
배포 lock에 고정한다. 버전 문자열만 같다고 모든 과거 artifact에 SDK가 있는 것은 아니다.
플러그인 설치 후 `cremore-siem --list-sinks`에서 `team_jsonl`을 확인하고
[팀 플러그인 설정](../deploy/siem/team-jsonl.example.json)을 사용한다.
설정 파일 경로를 넘기기 전 동일한 exporter DB·환경 준비가 필요하다.

entry point 이름과 `SinkProvider.id`가 같아야 한다. metadata discovery는 플러그인 코드를
import하지 않으며, `destinations[].provider`로 선택하고 `allow_plugins`에도 명시한 외부 플러그인만
load한다. ID 중복(기본 출력기와의 충돌 포함), 알 수 없는 ID, 잘못된 계약은 거절한다.
현재 `api_version`은 정수 `1`, `event_schema_versions`는 양의 정수 tuple이며 `1`을 포함해야 한다.
실제 지원하는 경우 `(1, 2)`처럼 미래 schema를 함께 선언할 수 있지만 `(2,)`만 선언하면
현재 exporter와 호환되지 않는다. 수신 계약·재시도 시 중복·오류 비노출 검사는 각 팀이 소유한다.
외부 plugin의 `options` 검증은 그 팀의 책임이며 기본 출력기의 token 제한이 자동 적용되지는 않는다.

## 공식 수신 형식 참고

- [Splunk HTTP Event Collector](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
- [Falcon LogScale structured ingestion: 중첩 attributes와 timestamp](https://library.humio.com/logscale-api/api-ingest-structured-data.html)
- [Falcon LogScale Ingest API: 인증, HTTP 200 성공 조건, NG-SIEM 구분](https://library.humio.com/logscale-api/api-ingest.html)
