# SIEM 필드 매핑

CreMore 이벤트(schema v1)를 SIEM별 필드로 옮기는 기준이다. 이벤트 종류와 전송 설정은 [SIEM 출력 연동](SIEM_INTEGRATION.md),
형식 변환 코드는 [`cremore/siem/formats.py`](../cremore/siem/formats.py)가 기준이다. 모든 값은 내부 UUID, 고정 코드, 개수와
시각이며 이름·경로·비밀은 없다.

## 1. 공통 필드

| native 필드 | 뜻 | 형식 |
| --- | --- | --- |
| `event_id` | 이벤트 ID. 재전송해도 같다(중복 제거 키) | UUID |
| `event_type` | 종류(`finding.created` 등) | 코드 |
| `occurred_at` | 발생 시각 | ISO 8601, UTC `Z` |
| `installation_id` | 설치 ID | UUID |
| `product`, `schema_version` | `CreMore`, `1` | 고정 |

종류별 본문은 `finding`·`credential`·`exposure`(탐지), `change`(탐지 변경), `connection`·`health`(연결 상태),
`platform`(생존 신호), `delivery`(전송 상태), `audit`(관리자 활동), `verdict`(금고 판정), `orphan`(퇴사자 자격증명)이다.

## 2. Splunk HEC

`sourcetype`은 `cremore:<종류 묶음>`(`finding`, `connection`, `collection`, `platform`, `siem`, `audit`, `coverage`,
`identity`)이고 `time`은 `occurred_at`의 Unix 초다. 이벤트 본문은 JSON이므로 `KV_MODE = json`(또는 HEC의 자동 추출)으로
`finding.severity`처럼 점 경로 필드가 된다. 중복 제거는 `event_id`로 한다.

## 3. Microsoft Sentinel (Logs Ingestion API)

`http_json`의 `body: "array"`, `query: {"api-version": "2023-01-01"}`, `oauth`(Entra 앱의 client credentials,
scope `https://monitor.azure.com//.default`)로 보낸다([예제](../deploy/siem/sentinel.example.json)). DCR은 이벤트를 한 열에
받고 변환에서 꺼낸다. 앱에는 DCR에 대한 **Monitoring Metrics Publisher** 역할을 준다
([Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)).

```json
"streamDeclarations": {
  "Custom-CreMoreEvents": {"columns": [
    {"name": "event_id", "type": "string"}, {"name": "event_type", "type": "string"},
    {"name": "occurred_at", "type": "datetime"}, {"name": "installation_id", "type": "string"},
    {"name": "finding", "type": "dynamic"}, {"name": "credential", "type": "dynamic"},
    {"name": "exposure", "type": "dynamic"}, {"name": "connection", "type": "dynamic"},
    {"name": "health", "type": "dynamic"}, {"name": "audit", "type": "dynamic"},
    {"name": "verdict", "type": "dynamic"}, {"name": "orphan", "type": "dynamic"},
    {"name": "platform", "type": "dynamic"}, {"name": "delivery", "type": "dynamic"}]}
},
"dataFlows": [{"streams": ["Custom-CreMoreEvents"], "destinations": ["LogAnalyticsDest"],
  "transformKql": "source | extend TimeGenerated = occurred_at, EventId = event_id, EventType = event_type",
  "outputStream": "Custom-CreMoreEvents_CL"}]
```

## 4. Elasticsearch

`http_json`의 `endpoint`를 `https://<호스트>/<인덱스>/_create/{event_id}`로, `authorization_scheme: "ApiKey"`와
`conflict_is_duplicate: true`를 쓰면 재전송이 같은 문서에 닿아 중복이 생기지 않는다([예제](../deploy/siem/elasticsearch.example.json)).
인덱스 템플릿은 ID·코드를 `keyword`, `occurred_at`을 `date`로 둔다. ECS로 옮길 때의 대응은 다음과 같다.

| native | ECS |
| --- | --- |
| `event_id` | `event.id` |
| `event_type` | `event.action` |
| `occurred_at` | `@timestamp` |
| `finding.severity` | `event.severity`(7절의 0–10 척도: CRITICAL 10, HIGH 8, MEDIUM 5, LOW 3) |
| `installation_id` | `observer.serial_number` |
| `audit.actor_ref` | `user.id` |

## 5. Datadog

`api_key_header`(`DD-API-KEY`)로 `/api/v2/logs`에 보낸다(202가 성공, [Logs API](https://docs.datadoghq.com/api/latest/logs/)).
로그 파이프라인에서 `occurred_at`을 날짜 리매퍼로, `event_type`을 카테고리로 지정한다.

## 6. IBM QRadar (syslog TLS, LEEF 2.0)

`message_format: "leef"`는 `LEEF:2.0|CreMore|CreMore|0.1.0|<event_type>|x09|` 뒤에 탭으로 나눈 속성을 보낸다.
`devTime`은 에포크 밀리초라 `devTimeFormat`이 필요 없고, `sev`는 1–10이다
([LEEF](https://ibmsecuritydocs.github.io/qradar_appfw_v2/docs/tutorials/generating_LEEF_events.html)).
Event ID는 `event_type`, 카테고리 `cat`은 종류 묶음이다. 나머지 속성은 아래 7절의 라벨 이름을 키로 쓴다.

## 7. ArcSight (syslog TLS, CEF)

`message_format: "cef"`는 `CEF:0|CreMore|CreMore|0.1.0|<event_type>|<이름>|<0–10>|` 뒤에 확장을 보낸다. 모든 이벤트에
`rt`(에포크 밀리초), `externalId`(`event_id`), `cat`(종류 묶음), `cs6`(`installationId`)이 있다. 헤더의 `|`·`\`와 확장의
`=`·`\`·줄바꿈은 CEF 규칙대로 이스케이프한다.

| 종류 묶음 | CEF 필드(라벨) |
| --- | --- |
| `finding` | `cs1` findingId, `cs2` credentialId, `cs3` credentialType, `cs4` workflowStatus, `cs5` sourceType, `act` change, `cn1` lineNumber |
| `connection`, `collection` | `cs1` connectionId, `cs2` connectionKind, `cs3` provider, `cs4` authState, `cs5` reason, `act` freshness |
| `platform` | `cn1` workersAlive, `cn2` queuedJobs, `cn3` oldestQueuedSeconds |
| `siem` | `cs1` destination, `cs2` nonce, `cs5` lastErrorCode, `cn1` pending, `cn2` held |
| `audit` | `act` action, `cs1` targetType, `cs2` targetId, `suid` actorRef, `cs4` fromStatus, `cs5` toStatus; `audit.chain_anchor`는 `cs3` chainState, `cs1` chainMac, `cs2` genesisMac, `cn1` chainSeq, `cn2` anchorNo, `cn3` openProblems |
| `coverage` | `cs1` verdictRef, `cs2` state, `cs3` previousState, `cs4` credentialType, `cs5` absenceBasis |
| `identity` | `cs1` orphanRef, `cs2` verdict, `cs3` credentialRef, `cs4` personRef, `cs5` provider |

심각도(0–10)는 탐지 CRITICAL 10·HIGH 8·MEDIUM 5·LOW 3, 퇴사 후 사용 9·활성 7, 감사 체인 이상 9, 금고 부재 5, 인증·수집 실패와 전송 적체 6,
만료 임박 4, 관리자 활동 3, 회복 2, 그 밖 1이다. syslog 심각도는 이 값에서 9 이상 2(critical), 7 이상 3(error),
5 이상 4(warning), 3 이상 5(notice), 그 밖 6(informational)이다.

## 8. Falcon LogScale

태그는 `source=cremore`와 `family=<종류 묶음>`이고 `attributes`가 이벤트 전체다. 파서에서 `occurred_at`을 타임스탬프로 쓴다.

## 9. OCSF 1.3.0

목적지의 `format: "ocsf"`에서만 쓴다. 옮길 수 없는 종류(연결 상태, 생존 신호, 전송 상태, 시험 이벤트, 감사 체인 앵커)는 native로 간다.

| native | OCSF |
| --- | --- |
| `finding.created` / `finding.updated` / `finding.forwarded` | Detection Finding(2004). `finding.forwarded`는 변경 2(메시지 "Credential exposure forwarded"). 생성 1, 해결·오탐·무시로 닫힘 3, 그 밖 변경 2. `finding_info.uid` = finding ID, `types` = [credential_type], `severity_id` = CRITICAL 5·HIGH 4·MEDIUM 3·LOW 2·INFO 1, `status_id` = OPEN 1·ACKNOWLEDGED 2·해결 4·오탐/무시 3 |
| `coverage.verdict_changed` | Detection Finding. `finding_info.uid` = 판정 `ref`, 부재 판정은 severity 3·status 1, 보관 확인은 status 4 |
| `identity.credential_orphaned` | Detection Finding. 퇴사 후 사용 severity 5, 활성 4, 그 밖 2 |
| `audit.action` | API Activity(6003). `api.operation` = 조치 코드, `actor.user.uid` = `actor_ref`, 생성·삭제·수정은 코드 끝(`_CREATED`·`_SET`·`_REMOVED` 등)에서 정함. 요청 출처는 기록하지 않아 `src_endpoint.name`이 `unknown` |
| 공통 | `time` = `occurred_at`(에포크 밀리초), `metadata.uid` = `event_id`, `metadata.tenant_uid` = `installation_id`, `metadata.log_name` = `event_type`, 옮기지 않은 native 필드는 `unmapped` |

필수 속성은 OCSF 스키마 서버(https://schema.ocsf.io/1.3.0)의 클래스 정의(선택 프로필 없음)를 2026-09-28에 확인했고,
[`formats_test.py`](../cremore/siem/formats_test.py)가 그 목록을 검사한다.

## 10. 수집기를 거치는 SIEM

Google SecOps, Wazuh, Graylog 등은 `jsonl` 출력이나 `syslog_tls`를 각 제품의 수집기로 받고 파서를 구성한다.
필드는 1절의 native 이름을 그대로 쓴다.
