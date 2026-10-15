# 비밀값을 읽는 선택 기능의 운영 정책 (제안)

> 작성 2026-09-26(2차 리뷰 ⑨), 원문 비저장 규칙 갱신 2026-10-02.
> **상태: 값 읽기 권한의 운영 조건은 팀 합의 전 제안. 수집 원문 비저장은 필수 규칙이다.**
> 값 읽기는 기본으로 꺼져 있고 값을 지문으로만 남긴다. 다만 켜면 수집 신원에
> 비밀값 읽기 권한이 필요하므로, 그 권한과 사용 조건을 팀이 합의해 두려는 문서다.
> 세부 동작은 공급자 문서가 기준이다: [Azure](../azure/README.md), [AWS](../aws/README.md),
> [Vault/OpenBao](../vault/README.md), [GCP](../gcp/README.md), [GitLab](../gitlab/README.md).

## 1. 코드가 이미 보장하는 것

- **기본은 꺼짐이다.** 연결을 만들거나 바꾸는 관리자(`admin`)만 켤 수 있다. 공급자 연결 4단계의 계획
  (`read_values` 등, [공급자 연결](ONBOARDING.md))에서 고를 때만 켜지고, 이후 수정은 수집 연결 PATCH다.
  - 공급자 연결은 `PROVIDER_CONNECTION_ACTIVATED`와 계획을 남긴다.
  - schema 1(`/api/v1/coverage/connections`)은 `created_by`·`updated_by`·`revision`과 `COVERAGE_CONNECTION_CREATED`를 남긴다.
  - schema 2(`/api/v2/coverage/connections`)는 감사 이벤트 `METADATA_CONNECTION_CREATED`·`METADATA_CONNECTION_CHANGED`를 남긴다.
- **켜는 조건은 연결 검증이 거부한다**(`cremore/coverage/metadata_models.py`).
  - `include_values`는 `vault_value` 또는 `issuer_value`가 있어야 한다.
  - `vault_value`는 `gcp`·`azure_key_vault`·`gitlab`에서만, `vault_metadata`와 함께 쓸 수 있다.
  - `issuer_value`는 `gcp`·`azure_resource_manager`에서만 쓸 수 있다.
  - schema 1 `value_reader_role`은 AWS Secrets Manager·SSM 서버 수집에서만, Secrets Manager는 정확한 시크릿 ARN
    (`references`)과 함께 쓸 수 있다(`cremore/coverage/models.py`).
  - 수집 원문 저장 옵션은 허용하지 않는다. GCP `store_values`·`keep_values`와 관리자 원문 조회 API는 폐기했다.
- **값은 메모리에서 HMAC 지문으로 바뀐다.** 원문은 DB·파일·checkpoint·job·로그·SIEM에 남지 않으며,
  가역 암호화·Base64로 보관하는 것도 금지한다. GCP를 포함해 저장 예외는 없다.
  - 기존 `value_match`는 노출·금고 대조에 쓰고, GCP의 payload 변경 관측은 별도의 비공개 HMAC을 쓴다.
    성공한 바이너리·빈 값 읽기도 다루며, scheme·key ID가 같은 지문만 비교한다. 공개 응답·export에는 내보내지 않는다.
  - 공급자 접속용 인증 자격증명의 봉인 저장은 수집 원문 보관과 별도 계약이다([팀 지침](AI_TEAM_CODING_GUIDE.md) 1절).
- **권한 거절·부분 수집은 `PARTIAL`로 남는다.** 금고에 없다는 근거로 쓰지 않는다.
- **등록된 수집 신원으로만 읽는다.** 콘텐츠에서 발견한 자격증명으로 로그인하거나 검증하지 않는다.
- **범위를 자동으로 넓히지 않는다.** 발견(discovery) 결과로 값 읽기 대상이 늘어나지 않는다.

## 2. 기능별 조건과 권한

| 기능 | 켜는 조건(모두 필요) | 읽는 신원 | 공급자에서 부여할 최소 권한 |
|---|---|---|---|
| Azure Key Vault 비밀 값 (schema 2 `azure_key_vault`) | `vault_metadata`·`vault_value` capability, `options.include_values=true` | 연결에 등록한 관리 신원 | 그 vault의 비밀 목록·`secrets/get`(data plane). Reader·ARM 권한과 별개 |
| Azure Storage 계정 키 `listKeys` (schema 2 `azure_resource_manager`) | `sources`의 `storage_keys`, `issuer_value`, `include_values=true`, `options.azure_storage_accounts`의 정확한 계정 ARM ID(승인된 구독 안) | ARM 수집 신원 | 지정한 계정에만 `Microsoft.Storage/storageAccounts/listKeys/action`. 키값이 응답에 들어 있는 POST다 |
| GitLab CI 변수 값 (schema 2 `gitlab`) | `sources`의 `ci_variables`, `vault_value`, `include_values=true`, 직접 명시한 group·project | 연결의 수집자 토큰 | 명시한 group·project의 CI 변수 조회 권한 |
| GCP Secret Manager 값·API 키 문자열 (schema 2 `gcp`) | `vault_value`(비밀 버전) 또는 `issuer_value`(API 키), `include_values=true` | Worker ADC·workload identity, 또는 대시보드 Google OAuth의 봉인 참조 | `secretmanager.versions.access`, API 키는 `apikeys.keys.getKeyString` |
| AWS Secrets Manager·SSM 서버 수집 (schema 1 `server_collection=true`) | 관리자가 연결에 `server_collection=true`를 명시. 값 읽기 역할은 연결 옵션(`value_reader_role`, Secrets Manager는 시크릿 ARN 목록)과 AWS 계정 관리자의 스택 배포(`EnableVaultValueRead`) | 값 읽기 역할을 지정하면 계정 스캐너 세션에서 역할 연쇄로 맡은 그 계정의 값 읽기 역할([AWS](../aws/README.md#값-읽기-역할)), 아니면 계정 스캐너 세션. 둘 다 이 작업만 `aws_readonly.VAULT_OPERATIONS`로 감싼 클라이언트를 받는다 | 값 읽기 역할: 템플릿이 스택에 적은 ARN·경로·키에 한정해 준다(`GetSecretValue`·`DescribeSecret`·`ListSecretVersionIds`, `GetParametersByPath`, 서비스 경유 `kms:Decrypt`). 스캐너 세션으로 읽으면 승인한 ARN·경로에 한정한 `secretsmanager:GetSecretValue`(이력은 `ListSecretVersionIds`, 목록은 `ListSecrets`), `ssm:GetParametersByPath`, 해당 KMS 키의 `kms:Decrypt`(템플릿 스캐너 역할은 `GetSecretValue`를 거부) |
| Vault/OpenBao 서버 수집 (schema 1 `server_collection=true`) | `server_collection=true`, 연결 `endpoint`가 설치의 `SECRET_STORE_URL`과 같음 | 설치의 비밀 저장소 신원(`kv_from_settings`) | 그 신원의 정책에 승인한 마운트·접두사의 `list`·`read`(KV v2 `metadata`)만 추가 |

값을 읽지 않는 기능은 이 정책의 대상이 아니다. GitHub `issuer_digest`는 공급자가 준 digest를 쓰고,
Vault token accessor·lease는 관리 메타데이터다.

## 3. 운영 조건 (합의안)

1. **필요할 때만 켠다.** 발급 목록과 금고를 대조해야 하는 범위에 한정한다. 기본값은 계속 꺼짐이다.
2. **요청과 승인을 기록한다.** 켤 때 요청자, 승인자, 이유, 대상 ID, 기간을 팀 변경 기록에 남긴다.
   CreMore에는 누가 바꿨는지만 남는다(§1). 이유와 기간은 남지 않는다.
3. **대상은 정확한 ID로 적는다.** Azure 계정 ARM ID, AWS ARN·파라미터 경로, Vault 마운트·접두사,
   GitLab group·project, GCP project·비밀로 적는다. 공급자 권한도 같은 범위로 제한한다.
   와일드카드 권한과 구독·계정 전체 권한은 쓰지 않는다.
4. **가능하면 신원을 나눈다.**
   - schema 2 연결이 자체 자격증명(봉인 참조)을 쓰면, 값 읽기는 별도 연결(별도 신원)로 만들고 메타데이터 연결에는
     값 권한을 주지 않는다. Worker ADC를 쓰는 GCP 연결은 Worker 신원을 함께 쓴다.
   - AWS 서버 수집은 계정별 수집 역할이면 별도 값 읽기 역할을 쓸 수 있다(스캐너 세션은 값 권한이 없고 값 읽기 역할을
     맡기만 한다). 지정하지 않으면 계정 스캐너 역할을, Vault 서버 수집은 설치 신원을 함께 쓴다(Vault는 별도 신원 미지원).
     서버가 값 권한을 가지면 안 되는 환경에서는 고객 측 CLI 수집을 쓴다. 값은 고객 환경에 머물고 지문만 전송된다.
5. **Worker를 고가치 대상으로 다룬다.** 값은 Worker 메모리에만 있다. 켠 기간에는 Worker의 접근 계정,
   네트워크 egress, 호스트 접근을 평소보다 좁히고 로그 수집 설정을 점검한다.
6. **주기 수집은 필요할 때만 쓴다.** 기본은 수동 수집이다. 서버 수집의 `schedule_minutes`는 5분 이상이다.
   Vault는 설치의 스케줄 허용 설정(`scan_schedules_allowed`)이 켜져 있을 때만 주기로 돈다. AWS는 설치 전체 자동 수집
   설정이나 온보딩에서 정한 연결 자신의 주기로 돌고, 둘 다 계정 스캐너 승인·스케줄 잠금·기능 중지를 따른다. AWS 값 읽기
   역할로 읽는 연결은 연결 자신의 주기에 더해
   설치의 AWS 자동 수집 설정(`enabled`와 `account_ids`)이 그 계정을 허용하고 계정 승인·스케줄 잠금·기능 중지가
   모두 허용할 때만 주기로 돈다(소유자 결정 2026-10-08, 아니면 `VALUE_READER_AUTOMATION_DISABLED`). 요청할 때의
   수집은 이 설정과 무관하다.
7. **정기적으로 검토한다.** 켜진 연결과 부여된 권한을 정해진 주기마다 다시 확인한다.
   필요 없어진 기능은 끄고 공급자에서 권한을 회수한다. CreMore는 공급자 권한을 회수하지 않는다.
   끈 뒤에도 남은 지문은 과거 관측이다. 현재 보관의 근거가 아니다.
8. **과거 GCP 원문 보관 설치는 정리한다.** 업그레이드만으로 이미 남은 값이 지워지지는 않는다.
   [이관 절차](integration/GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관)로 원문 행과 백업·WAL·복제본을
   별도로 정리하고, 정리 완료 전에는 과거 원문까지 제거했다고 보고하지 않는다.
9. **검증 범위를 구분한다.** CI와 기본 테스트는 fake client와 합성 데이터만 쓴다.
   실계정 확인은 허용된 별도 환경에서 하고, 그 결과를 따로 기록한다.

## 4. 팀이 정할 것

- [ ] §3 조건의 채택 여부
- [ ] 켜기 승인자(예: 보안 책임자와 해당 공급자 담당자)
- [ ] 정기 검토 주기
- [ ] 과거 GCP 원문 보관 설치의 정리 담당자·일정과 백업·WAL·복제본 처리 확인
- [ ] AWS·Vault 서버 수집에 별도 신원을 요구할지. 요구하면 코드 변경이 필요하다(플랫폼 담당).
  AWS는 별도 값 읽기 역할로 정했다([값 읽기 역할 설계안](AWS_VAULT_VALUE_READER_DESIGN.md) 6절, 2026-10-08, 구현됨·실계정 미검증).
  켜기 승인은 AWS 계정 관리자의 스택 배포(처음 배포 때 함께)와 CreMore 관리자의 옵션 켜기 두 단계다.
