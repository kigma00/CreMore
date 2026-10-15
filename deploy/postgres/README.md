# PostgreSQL 역할 분리

강화 배포는 PostgreSQL 16 이상과 **CreMore 전용 DB/schema**를 사용한다. 기본 schema는
`cremore`다. 런타임의 `ISOLATED_DEPLOYMENT=true`는 자동 DDL을 끄고, 시작할 때 실제 권한과
스키마를 읽어 검사한다. 기존 개발 배포의 기본값 `false`는 기존 자동 초기화를 유지한다.

| DB 로그인 역할 기본 이름 | 용도 |
| --- | --- |
| `cremore_migration` | schema/테이블 소유자, 별도 배포 작업에서만 DDL |
| `cremore_api` | 연결·승인·설정·조회·감사 추가, 마법사 완료 시 catalog 저장, Slack 탐지 알림 시험 메시지의 발송 간격(`scan_request_pacing`) |
| `cremore_collector` | 수집·projection·작업 lease·유지보수, 감사 체인 봉인 |
| `cremore_remediator` | 조치 실행·결과·전용 연결 갱신·승인 nonce 소비 |
| `cremore_control` | 티켓 응답·소유자 승인 상태·heartbeat, Slack 탐지 알림 전달(`siem_deliveries`·`siem_destination_status`·`scan_request_pacing` 쓰기, 메시지에 계정 이름을 넣는 `aws_accounts` 읽기) |
| `cremore_siem` | SIEM outbox 읽기·배송 lease와 상태 갱신 |

런타임에 superuser, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS, 역할 membership,
DB/schema/object 소유권, schema CREATE, DB CREATE/TEMP를 주지 않는다. `NOINHERIT`만으로는
`SET ROLE`을 막지 못하므로 membership 자체를 금지한다. 모든 로그인은 별개의 신원이어야 한다.
인증은 운영자가 SCRAM, 인증서, 플랫폼 DB 인증 등으로 별도 구성한다. 프로비저닝 도구는
비밀번호를 입력·변경·출력하지 않으며 새 LOGIN에는 비밀번호를 설정하지 않는다.

## 최초 설치와 업데이트

애플리케이션과 같은 버전의 설치본에서 아래 순서로 실행한다. 각 단계의 `DATABASE_URL`은
해당 역할만 가진 별도 프로세스에 secret으로 주입한다. URL이나 비밀번호를 셸 로그에 남기지 않는다.

1. **DB 관리자 연결**로 역할과 schema를 준비한다.

   ```sh
   python -m cremore.db.privileges prepare --schema cremore
   ```

2. **migration 역할 연결**로 스키마를 초기화·확장한다.

   ```sh
   python -m cremore.db.startup
   ```

3. **DB 관리자 연결**로 현재 버전의 명시적 권한만 적용한다.

   ```sh
   python -m cremore.db.privileges grant --schema cremore
   ```

4. API, collector, remediator, control, SIEM에 각각 자신의 DB 연결만 주입하고 강화 배포를 시작한다.
   migration/admin 연결은 런타임에 mount하지 않는다. SIEM은 `SIEM_DATABASE_URL`을 사용한다.

역할 이름은 prepare/grant 양쪽에서 `--migration-role`, `--api-role`, `--collector-role`,
`--remediator-role`, `--control-role`, `--siem-role`로 변경할 수 있다. 소문자 ASCII 식별자만
허용하며 서로 달라야 한다. prepare는 각 역할의 DB별 `search_path`를 선택 schema와
`pg_catalog`로 고정한다. 클라이언트 연결 옵션이 이 값을 덮어쓰지 않게 한다.

두 프로비저닝 단계와 스키마 초기화는 재실행 가능하다. prepare는 전용 DB의 PUBLIC CREATE/TEMP,
public schema CREATE를 철회한다. grant는 전용 schema의 이전 table/column/sequence/function
권한을 철회한 뒤 코드의 allowlist만 다시 부여한다. 새 테이블에는 기본 권한이 없다.
운영 업데이트는 런타임을 멈춘 유지보수 창에서 수행한다. 테이블·소유자가 예상과 다르면 중단한다.

기존 설치의 schema와 테이블이 공용 로그인 소유라면 먼저 런타임을 정지하고 검증된 backup을
확보한 뒤, 운영자가 **해당 설치의 객체만** migration 역할 소유로 이관한다. 이 도구는 다른
역할의 소유권을 자동으로 가져오거나 기존 데이터를 옮기지 않는다. 기존 populated legacy
identity 정리는 별도 `cremore.db.migrations`의 offline/backup 확인 절차가 필요하다.
권한 분리 CLI를 그 데이터 이관의 대체물로 사용하지 않는다. rollback은 검증된 backup과
이전 애플리케이션 버전·권한 정책을 함께 복구한다.

## 보장과 남는 경계

권한 원본은 [privileges.py](../../cremore/db/privileges.py)의 테이블별 `TABLE_ACCESS`와
열별 `COLUMN_ACCESS`다. 실제 repository/task/coverage/catalog/outbox 경로를 기준으로 작성했다.
grant에 `ALL`을 부여하지 않으며, 새 테이블은 이 정책에 명시하지 않으면 적용이 실패한다.

- `finding_events` 내용·entry MAC은 UPDATE/DELETE/TRUNCATE할 수 없다. collector만 기존
  sealer가 쓰는 `chain_seq`, `chain_mac`을 UPDATE할 수 있다. 이 열의 과거 값 변경은 기존
  MAC/anchor 검사가 탐지하는 영역이며 외부 감사 보존을 대신하지 않는다.
- `findings`, `credentials`, `exposures`에 DELETE/TRUNCATE를 주지 않는다. credential 삭제로
  감사 행이 cascade 삭제되는 경로도 막는다. 승인 nonce는 remediator의 SELECT/INSERT만 허용한다.
- SIEM의 `UPDATE(event_id)`는 PostgreSQL의 `SELECT FOR UPDATE`에 필요한 열 권한이다.
  payload 수정 권한은 없다. collector의 기존 outbox 보존기간 정리는 배송 완료 데이터의
  DELETE를 필요로 한다. 이 outbox는 변경 불가능한 외부 감사 저장소가 아니다.
- 수집 상태·설정·작업 테이블은 기존 원자적 갱신·lease 계약을 유지하기 위해 역할별 필요한
  쓰기를 허용한다. **테이블 단위 권한이며 행/설정 key/공급자별 RLS 격리는 아니다.**
  설정이나 허용된 상태의 조작을 모두 방지하지 않으며 독립 조치 서명·비밀/실행 분리와 함께 사용한다.
- `gcp_values`의 과거 원문과 `migration_archive`는 런타임에 읽기 권한도 없다.
- 시작 검사는 PUBLIC/column/grant-option 권한, 역할 membership, 소유권, 접근 가능한 사용자
  SECURITY DEFINER 함수, search_path와 스키마의 테이블·열·키·필수 index/ledger를 검사한다.
  실행 중 관리자가 권한을 바꾸는 것을 계속 감시하는 기능은 아니다.

프로비저닝 CLI는 성공 시 `DATABASE_PRIVILEGES_READY`, migration CLI는
`DATABASE_SCHEMA_READY`를 출력한다. 실패 시 URL/DB 행/driver 원문을 숨긴 고정 오류로 끝난다.
실패한 deployment에서 `ISOLATED_DEPLOYMENT=false`로 낮춰 우회하지 말고 관리자 연결로
역할과 schema 소유권·migration 상태·권한을 확인한다.

검증: `AWS_EC2_METADATA_DISABLED=true python -m pytest cremore/db/privileges_test.py
cremore/db/startup_test.py -q`. 실제 PostgreSQL 검사는 `CREMORE_TEST_POSTGRES_URL`을 지정하며
localhost/127.0.0.1의 일회용 `cremore_test` DB와 16 이상만 허용한다. 테스트 관리자는 임시 역할을
만들 수 있어야 한다. 테스트는 임의 이름의 schema/역할만 제거하고 운영 인증·공급자 호출은 하지 않는다.
