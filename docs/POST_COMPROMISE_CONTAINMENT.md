# 프로세스 침해 이후 피해 제한

2026-10-06 구현. `ISOLATED_DEPLOYMENT=true`를 위한 계약이다. 기존 설치는 기본값
`false`로 호환성을 유지한다. 옵션만 켜거나 이미지 하나만 교체하면 강화 배포가 완성되지 않는다.
[Compose](../deploy/compose/isolated/README.md) 또는 [Helm](../deploy/helm/README.md),
[DB 역할](../deploy/postgres/README.md), 독립된 신원·네트워크·키 배포가 함께 필요하다.

## 경계와 남는 권한

| 프로세스 | 보유 권한 | 주지 않는 권한 |
| --- | --- | --- |
| API | OIDC 검증, 설정/승인/작업 접수, 공개키 봉인, OAuth·티켓 제어 비밀 | 수집/조치 복호화 개인키, 클라우드 기계 신원, DB DDL |
| collector | 수집용 개인키·읽기 신원, 승인된 수집·조사·기계 토큰 갱신 | 조치용 개인키·쓰기 신원, 제어 봉인 키, 조치 계획 수정 |
| remediator | 조치용 개인키·쓰기 신원, 독립 서명 승인 검증 후 실행 | 수집 개인키, 제어 봉인 키, 서명 개인키 |
| control | 티켓 발송·응답 조회, 스케줄 제어, Slack 탐지 알림 발송(봉인된 webhook 주소·연락 발송 봇 토큰), 제어 봉인 키 | 공급자 수집/조치 개인키, 클라우드 신원 |
| SIEM | 별도 DB outbox 권한·수신 전용 전송 인증 | 공급자/제어/지문 키, 감사 원문 테이블 권한 |
| 일회성 migrator | 스키마 이관 권한 | 상시 서비스 실행, 런타임 키 |

봉인 v3은 purpose/provider/인증 authority별 RSA-OAEP-SHA256와 AES-256-GCM을 쓴다.
공개 recipient 정책은 DB 바깥의 무결성 보호된 파일이다. API는 새 비밀을 봉인할 수 있지만
기존 봉인 비밀을 열 수 없다. 입력하는 새 인증정보는 여전히 API 메모리를 지나간다.
OAuth 교환·티켓 연동·Slack 탐지 알림에 필요한 제어 비밀도 API/control 침해의 잔여 위험이다.
control은 알림을 보내려고 SIEM 전달 상태(`siem_deliveries`·`siem_destination_status`)를 쓰며, 이 스키마는 행 수준 보안을
쓰지 않으므로 control 로그인이 침해되면 외부 SIEM 목적지의 전달 행도 처리 완료나 재시도로 바꿀 수 있다. 이벤트 원본
(`siem_events`)과 감사 기록은 바꿀 수 없다.

현재 배포 단위는 **수집 역할 하나와 조치 역할 하나**다. 각 worker는 그 역할에 등록된 모든
현재 recipient 키를 가져야 한다. 시작할 때 누락·역할 혼용을 거절한다. 이것을 tenant별
수집기 격리라고 부르지 않는다. 수집기 침해 시 그 수집기가 가진 모든 읽기 권한과 메모리의
인증정보가 위험하다. provider 대상·scope 검사는 정상 실행의 오용을 차단하지만 RCE가
동일 프로세스 코드를 우회하는 것을 막는 보안 경계는 아니다.

조치 서명은 정확한 계획·종속 설정·행위·유효기간·일회용 nonce에 묶인다. API와 worker가
각각 검사하며 nonce는 실행 시작과 같은 fenced transaction에서 소비한다. 기존 승인·분리
검사는 계속 필요하다. **remediator 자체가 침해되어 이미 가진 쓰기 신원을 직접 사용하는
경우는 애플리케이션 서명 검사로 막을 수 없다.** 클라우드 최소 권한·짧은 세션·대상 제한이 필요하다.

런타임 DB 역할은 DDL, 소유자 권한, 다른 역할 전환, 감사 내용 UPDATE/DELETE를 갖지 않는다.
collector는 체인 봉인 열만 갱신한다. 작업·설정 테이블의 일부 쓰기는 정상 운영상 공유되므로
행 단위 tenant 격리나 설정 위조 방지를 보장하지 않는다. HMAC 키를 가진 침해 프로세스는
새 감사 내용을 위조할 수 있다. 외부에 이미 보관한 근거와 공급자 자체 감사 로그를 함께 확인한다.

컨테이너 설정은 non-root, 읽기 전용 rootfs, capability 제거, tmpfs, 역할별 secret mount다.
host root, Docker 관리자, Kubernetes cluster-admin, 배포 비밀 관리자, DB 관리자까지
탈취된 상황을 방어한다고 주장하지 않는다. 다른 노드/호스트와 관리 주체를 쓰면 경계가 강화된다.

## 오프라인 키 준비

서버가 아닌 보호된 운영자 장비에서, 자격증명 값이 없는 계획을 작성한다. `target`은 마법사의
인증 context이고 수집할 저장소/페이지 목록이 아니다. 예:

```json
{
  "version": 1,
  "connections": [
    {"provider":"github","edition":"cloud","auth_method":"github_app","purposes":["exposure"],"target":{}},
    {"provider":"github","edition":"cloud","auth_method":"github_app","purposes":["remediation"],"target":{}},
    {"provider":"notion","edition":"standard","auth_method":"integration","purposes":["exposure"],"target":{}},
    {"provider":"machine_identity","idp":{"token_url":"https://idp.example.test/oauth2/token","client_id":"cremore-reader"}}
  ]
}
```

```sh
python -m cremore.secretstore.provision --plan planned-contexts.json --output new-private-directory
```

출력 디렉터리는 기존에 없어야 한다. 실패 후 일부 파일이 생성됐다면 새 디렉터리로 다시
실행한다. 기존 파일을 덮어쓰지 않고 키를 stdout에 출력하지 않는다. 공급자 context는
실제 온보딩의 정규화·지원 목적 검사를 재사용한다. 역할/authority별 RSA 3072 키를 만들며
`recipients.json`, 역할별 `collector-private.json`/`remediator-private.json`,
`control-key.txt`, `approval-public.pem`, `KEEP-OFF-SERVER/approval-private.pem`을 만든다.
계획에 없는 역할의 개인키 파일은 생성하지 않는다. 해당 worker를 실행하려면 먼저 그 역할의
실제 context를 준비해야 한다. 빈 역할에 가짜 공급자를 등록하지 않는다.

`KEEP-OFF-SERVER`는 독립 승인자 장비에만 보관한다. 전체 디렉터리를 앱 서버에 mount하지 않는다.
API에는 공개 정책과 제어 키, collector/remediator에는 각자의 개인키 파일만 배포한다.
API/remediator에 동일한 승인 **공개키**를 배포한다. Linux의 생성 파일은 0600, 디렉터리는
0700이다. 배포 시 소유자 읽기 또는 통제된 0440 그룹 읽기와 read-only mount를 적용한다.
Kubernetes projected Secret의 회전 symlink는 허용한다. Windows의 mode 비트는 DACL을
보장하지 않으므로 먼저 부모 폴더 ACL을 제한하고 산출물 ACL도 확인한다.

이미 존재하는 `FINGERPRINT_KEY`와 `AUDIT_CHAIN_KEY`는 바꾸지 않는다. 기존 지문·감사 연속성에
필요하며 연결 비밀 봉인 키와 별개다. 회전할 때는 새 공개키를 해당 그룹의 `public_keys` 맨 앞에
두고 이전 키와 개인키를 유지한 채 오프라인 rewrap한다. 모든 참조와 백업 보관 정책을 확인한
뒤에만 이전 키를 폐기한다. 단순히 키 파일을 새로 생성해 덮어쓰지 않는다.

## 기존 설치 이관과 복구

1. 동일 소스 revision의 이미지와 DB·암호화된 백업 복구를 검증한다. 모든 writer와 scheduler를
   중단한다. fingerprint/audit 키는 그대로 보존한다. 운영자 CLI의 확인 flag는 프로세스 중단이나
   백업을 자동 수행하지 않는다.
2. DB 관리자와 별도 migration 계정을 사용해 [DB 절차](../deploy/postgres/README.md)의
   `privileges prepare` → `db.startup` → `privileges grant`를 적용한다. 서비스 계정에는 migration
   접속정보를 배포하지 않는다. 스키마가 맞지 않으면 runtime은 자동 DDL 대신 시작을 거절한다.
3. 보호된 오프라인 이관 프로세스에만 기존 봉인 root, 모든 현재/이전 recipient 개인키를 합친
   JSON, 새 제어 키, DB 접속을 제공한다. `SEALING_PUBLIC_KEYS_FILE`, `SEALING_PRIVATE_KEYS_FILE`,
   `CONTROL_SEALING_KEY`, 기존 root 설정과 `DATABASE_URL`을 그 프로세스에만 주입한다.

   ```sh
   python -m cremore.secretstore.migrate --offline --backup-confirmed
   ```

   현재 owner를 알 수 없는 과거 참조는 전체 transaction을 중단하고 참조의 SHA-256만 알린다.
   검토한 SHA-256 → binding JSON을 `--bindings-file`로 제공한다. 원문 인증정보를 파일에 쓰지 않는다.
   모호한 목적/대상은 추측해 이관하지 않는다. 원문 스캔 결과·지문·감사 행은 변경하지 않는다.
   진행 중이던 콘텐츠 작업은 `CREDENTIAL_SEALING_MIGRATED_REQUEUE`로 취소한다. 완료 후 새
   수동/예약 작업을 시작하며 이전 실행 계획을 강제로 재사용하지 않는다.
4. 역할별 DB 접속·키·기계 신원과 제한된 egress를 배포한 뒤 강화 모드로 시작한다. 수집·조치
   신원은 별개다. API의 AWS 신원 화면은 collector/remediator 보고를 표시하고 AWS 조사·발견·
   메타데이터 읽기는 collector 큐를 통해 실행한다. API에는 클라우드 신원이 필요하지 않다.
5. 합성 연결의 인증→목록→범위 승인→수집, 작업 취소/재시작, 티켓 응답, 서명 승인과 SIEM 도착을
   확인한다. 정상 흐름과 역할 혼용·잘못된 서명 거절을 함께 확인한다.

이관은 원자적이며 v3 재실행은 현재 키 참조를 그대로 유지한다. 이관 실패는 transaction을
롤백한다. 이관 후 이전 바이너리로 되돌릴 때는 **writer를 모두 중단한 상태에서 DB 백업과
대응하는 이전 키·설정을 함께 복구**한다. `ISOLATED_DEPLOYMENT=false`만 바꾸는 것은
v3 데이터를 구버전으로 되돌리지 않는다. 장애 후 새 감사/업무 데이터가 생겼다면 그 이력을
보존하고 검토한 forward fix를 우선한다. 운영 데이터를 무조건 덮어쓰지 않는다.

## 독립 승인과 외부 감사

대시보드에서 실행할 계획의 승인 요청 JSON을 내려받아 독립 장비에서 대상·행위·기한을
검토한 뒤 서명한다. 요청 내용은 신뢰하지 않고 원래 업무 승인과 대조한다.

```sh
python -m cremore.remediation.authorization --request request.json --private-key approval-private.pem --expires-at 2026-10-06T12:00:00Z --output signed-approval.json
```

기한은 예시이며 현재 계획 만료 이내로 지정한다. 서명 결과 파일만 대시보드에 올린다.
실행·긴급 실행·불확실 결과 재확인은 각 mode에 맞는 새 서명이 필요하다. 개인키를 업로드하지 않는다.

기존 SIEM의 `platform.heartbeat`, `audit.chain_anchor`를 독립 계정/망 수신기에 전송한다.
[수신기 규칙 예시](../deploy/siem/containment/README.md)는 미수신·불연속 경보와 외부 보관
운영 계약을 제공한다. 앱 내부 outbox나 같은 호스트 로그는 독립 보관본이 아니다.

## 침해 시 회수 순서

외부 관리 채널에서 해당 역할의 egress와 워크로드 신원을 차단하고 worker를 정지한다.
실행 결과가 불명확한 조치는 재시도하지 않는다. 공급자 원장으로 실행 여부를 대조한다.
외부 SIEM·DB 백업·공급자 감사 로그와 보존 시점을 확보한 다음, 노출된 역할의 PAT/앱 키/
인증서·DB 접속·제어 비밀을 공급자에서 회수한다. 짧은 토큰도 만료 전까지 유효할 수 있으므로
역할 세션 정책과 신뢰도 함께 차단한다. 깨끗한 호스트에 새 키·신원으로 복구하고 감사 연속성을
외부 앵커와 확인한다. 서명 장비 침해가 없으면 서명 개인키까지 앱 서버로 옮겨 교체하지 않는다.

## 검증 범위

합성 provider client, memory/SQLite, 격리 PostgreSQL의 실제 역할, Linux 파일 권한,
Compose/Helm 렌더, 웹 단위/TypeScript/build와 관련 Chrome 흐름을 검사한다.
실행 수와 결과는 [이번 검증 기록](CONTAINMENT_IMPLEMENTATION_2026-10-06.md)에 남긴다.
실제 회사 IAM·IdP·CNI·방화벽·WORM 적용, 장기간 무중단 운영과 host-root 침해 방어는
이 검사로 입증하지 않는다.
