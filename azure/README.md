# azure 공급자 소유 영역

### 추가 인벤토리·금고 선택 옵션 (2026-10-05)

Microsoft 온보딩의 `credential_sign_ins`는 Graph **beta** 서비스 주체 로그인 기록을 읽는다.
`AuditLog.Read.All`과 Microsoft Entra ID P1 또는 P2가 필요하며 기본 해제다(라이선스가 없는 테넌트의 거절은
권한이 아니라 `AZURE_ENTRA_PREMIUM_REQUIRED`로 알린다). 성공한 로그의 앱·키 ID가
실제 수집한 자격증명과 정확히 연결될 때만 사용 근거를 저장한다. v1.0에는 이 키 ID가 없어 대체하지 않는다.
IP·로그 원문은 저장하지 않으며 빈 결과는 미사용을 뜻하지 않는다. `audit_days`는 1–30일이다.
`directory_audits`는 별도 선택한 v1.0 디렉터리 감사에서 성공한 자격증명 추가의 생성자를 보완한다.
정확한 앱/SP·추가된 key ID·명시적 actor가 있어야 하며, 목록에 없거나 모호한 키는 연결하지 않는다.
`KeyDescription`의 지원하는 before/after 형식만 파싱하므로 모든 생성 이벤트의 귀속을 보장하지 않는다.
원문 변경값·사용자 이름·메일은 이 경로에서 저장하지 않는다. 키 삭제 기록을 현재 폐기로 승격하지 않는다.
발급 목록의 `federated_credentials`·`public_certificates`, 금고의 `keys`·`certificates`·`versions`·`deleted`·
`public_certificates`도 기존 수집기에 연결한다. 공개 인증서 옵션은 인증서 목록을 포함하고 GET 권한을
별도 점검한다. 공개 DER 대조는 개인키 보관을 입증하지 않는다. 값 읽기는 기존 별도 승인 계약이다.
구현·제약·검증은 [재검토 기록](../docs/INVENTORY_METADATA_REVIEW_2026-10-05.md)을 따른다.

Azure Key Vault·Microsoft Entra ID·Azure Resource Manager의 인벤토리와 Azure Blob Storage·Azure DevOps Repos
콘텐츠 수집을 소유한다. Python 구현과 전용 테스트는 `backend/cremore_azure_provider/`에 있다. 이 폴더에는 UI가 없고 연결 화면은 onboarding descriptor로 콘솔이 그린다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

## Microsoft 연결: 앱 등록 하나

공급자 연결 `azure`(콘솔 이름 "Microsoft")는 앱 등록 하나로 Entra ID(앱 비밀·인증서 목록, 사람 목록), Azure(구독·스토리지
키·Key Vault·Blob), 테넌트에 연결된 Azure DevOps 조직(저장소 검사, PAT 목록)을 함께 연결한다. 따로 있던 Entra ID(사람)
연결(`entra_id`)은 새로 만들지 않으며 기존 연결은 계속 수집한다. 개인 액세스 토큰의 `azure_devops` 공급자는 Azure DevOps
Server와 테넌트에 연결되지 않은 조직을 위해 남는다.

- **인증서**(`certificate`, 워커가 관리 ID나 워크로드 신원 연합을 쓸 수 없을 때): Microsoft는 관리 ID, 연합 자격 증명,
  인증서 순으로 권한다([앱 등록 보안 모범 사례](https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration)).
  CreMore가 RSA 키와 자체 서명 인증서(180일)를 만들어 봉인하고, 관리자는 공개 인증서만
  앱 등록에 올린다(`app_certificate.py`). CA가 발급한 인증서만 받는 테넌트 정책은 이 인증서를 거절한다(`AZURE_ADD_KEY_REFUSED`). Microsoft 문서의
  [인증서 자격 증명](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) 형식(PS256,
  `x5t#S256`)으로 client credentials 토큰을 받는다(동시에 읽는 스캔 스레드들도 범위마다 한 번만 요청). 만료 60일 전부터 worker가
  [addKey](https://learn.microsoft.com/en-us/graph/api/application-addkey?view=graph-rest-1.0)로 새 인증서를 더하고
  ([소유 증명](https://learn.microsoft.com/en-us/graph/application-rollkey-prooftoken): 현재 키로 서명, `aud`
  `00000002-0000-0000-c000-000000000000`, `iss` 애플리케이션 객체 ID, 10분), 하루 뒤 이전 인증서를
  [removeKey](https://learn.microsoft.com/en-us/graph/api/application-removekey?view=graph-rest-1.0)로 지운다. 자기 키 교체에는
  권한이 필요 없고, 자기 애플리케이션 객체를 찾는 데 Application.Read.All이 필요하다. 만료된 인증서는 스스로 교체하지 못한다.
- **워커 신원**(`workload_identity`): 워크로드·관리 ID 또는 회사 IdP 연합 자격 증명(`DefaultAzureCredential`). 저장하는 비밀이 없다.
  환경 변수의 서비스 주체, 워크로드 ID, 관리 ID만 쓰고 호스트의 사람 로그인(Azure CLI·PowerShell·azd·VS Code·공유 토큰 캐시·
  브라우저·Windows 계정 브로커)은 쓰지 않는다(`metadata/transport.py`의 `ambient_credential`, 2026-10-08). 마지막으로
  로그인한 사람의 신원으로 수집되는 일을 막는다. 환경 변수의 사용자 암호 로그인(`AZURE_USERNAME`·`AZURE_PASSWORD`)도
  사람 계정이므로 설정하지 않는다.
  관리 ID에는 포털의 API 권한 화면이 없어, 설정 도우미가 Graph 앱 역할을 서비스 주체에 할당하는 `az rest`
  (`servicePrincipals/{id}/appRoleAssignments`)와 개체 ID로 Azure 역할을 주는 명령을 준다
  ([관리 ID에 앱 역할 할당](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-assign-app-role-managed-identity)).
- 수집은 schema 2 `auth_type: private_key_jwt`와 세 역할(`client_id`·`private_key`·`tenant_id`, 봉투 하나)로 Graph·ARM·Key
  Vault·사람 목록·Azure DevOps PAT 목록을 읽는다. Blob·Azure DevOps 콘텐츠 검사는 같은 봉투를 `secret_ref`로 받아 서비스별
  토큰(`https://storage.azure.com/.default`, Azure DevOps `499b84ac-1321-427f-aa17-267ca6975798/.default`)을 Bearer로 보낸다.
  인증서 로그인은 공용 클라우드(`login.microsoftonline.com`)만 지원한다.
- 필요한 권한: Microsoft Graph 애플리케이션 권한 Application.Read.All(인증서 교체·앱 목록),
  Organization.Read.All(앱 목록의 테넌트 확인·사람 목록의 불투명 토큰 확인), User.Read.All(사람 목록),
  AuditLog.Read.All(로그인·디렉터리 감사 옵션)과 관리자 동의(최소 권한은 권한 있는 역할 관리자).
  Azure 역할 Reader(구독), Storage Blob Data Reader(스토리지 계정), 키 지문을 읽을 스토리지 계정의
  Reader and Data Access(listKeys, 그 키로 계정의 모든 데이터에 접근 가능), Key Vault Reader(값 대조는 Key Vault Secrets User).
  Key Vault 역할은 Azure RBAC 권한 모델에만 적용되며, 예전 액세스 정책 모델은 비밀 List(값 대조는 Get)를 준다.
  Azure DevOps는 조직에 서비스 주체를 Basic 액세스로 추가하고
  ([서비스 주체](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity?view=azure-devops)),
  PAT 목록은 Project Collection Administrators 그룹이 읽는다
  ([Token Admin](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/admin-revoke-user-pats?view=azure-devops)).
  그 그룹은 조직 전체 관리자이고, `vso.tokenadministration`에는 읽기 전용이 없어 모든 사용자의 PAT를 조회·폐기할 수 있다.
  마법사의 설정 도우미가 값이 채워진 `az` 명령을 준다.
- 개인 액세스 토큰 연결(`azure_devops`)은 그 조직 범위의 PAT를 필요한 범위만, 가장 짧은 만료로 쓴다. 모든 조직용(전역) PAT는
  2026년 12월 1일부터 동작하지 않는다
  ([PAT](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops)).
- 서비스 주체로 Token Admin PAT 목록을 읽는 것은 문서가 명시하지 않아 실제 조직에서 확인하지 않았다. 권한 점검이 그 호출을
  실제로 해 보고 `GRANTED`·`MISSING`으로 알린다.

루트에서 `python -m pip install -e ".[dev,gcp,azure]"`로 개발 설치 후
`python -m pytest azure/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

## Azure Blob Storage 콘텐츠 수집

콘텐츠 소스 `azure_blob`(`blob_source.py`·`blob_content.py`)은 승인한 스토리지 계정의 컨테이너 하나
(`account/container`) 또는 계정의 컨테이너 목록을 기존 승인 범위·worker·catalog 경로로 스캔한다.
worker 자신의 Azure 신원(`ambient_credential`: 환경 변수의 서비스 주체·workload·managed identity, 사람 로그인 제외)으로
`https://storage.azure.com/.default` 토큰을 받으며 연결에 비밀을 저장하지 않는다. 계정·컨테이너에
Storage Blob Data Reader가 필요하다. 공유 키·SAS 인증, 스냅샷·이전 버전 목록, Archive 계층 읽기는 하지 않는다.

목록은 List Containers·List Blobs(XML, `NextMarker`)를 끝까지 따르며, 같은 marker 반복·잘못된 XML·이름은
실패로 남기고 빈 목록으로 보지 않는다. marker 하나는 UTF-8 8 KiB, 같은 수집기의 목록들에서 총 10,000개로
제한하며 중복 이력은 메모리의 고정 길이 지문만 남긴다. 각 Blob은 목록의 ETag를 `If-Match`로 고정해 읽으므로 수집 중
바뀐 Blob은 다른 내용을 읽지 않고 실패로 센다. 크기 한도를 넘는 Blob은 읽지 않고 실패로 센다.
노출 위치는 `계정/컨테이너`와 Blob 이름, 버전은 ETag다. 요청 헤더 `x-ms-version`은 `2023-11-03`이다.
발견 상세의 원본 링크는 아직 만들지 않으며 `SOURCE_LINK_NOT_SUPPORTED`로 알린다(위치 정보는 기록됨).
연결 카드의 인증 방식은 "Worker Azure 신원"으로 표시한다.

## Azure DevOps Repos 콘텐츠 수집

콘텐츠 소스 `azure_devops`(`devops_source.py`·`devops_content.py`)는 Azure DevOps Services
(`https://dev.azure.com/{organization}`) 또는 Azure DevOps Server(`base_url`의 HTTPS 주소와 조직 자리의
프로젝트 컬렉션 이름)의 승인한 Git 저장소 하나(`조직/프로젝트/저장소`) 또는 프로젝트의 저장소 목록을 스캔한다.
Services 주소는 고정이며 `dev.azure.com`·`*.visualstudio.com`을 서버 주소로 받지 않는다. REST API 버전은
Services `7.1`, Server `5.0`(Server 2019 이상)이다. 서버의 같은 이름 컬렉션이 섞이지 않도록 노출 위치에
인스턴스 주소(`source_instance`)를 포함한다. Code (Read) 권한의 개인 액세스 토큰을 기존 연결 토큰처럼 암호화해 저장하고
Basic(빈 사용자 이름 + PAT)으로 보낸다. 기본 브랜치(또는 설정한 `ref` 브랜치)를 refs의 **정확한 이름**으로
커밋에 고정하고(refs filter는 접두사 일치), 그 커밋의 전체 트리에서 blob을 objectId로 읽는다. 범위 선택의
`refs/heads/이름`은 해당 브랜치를 정확히 가리키며 `HEAD`·빈 선택은 저장소의 기본 브랜치를 따른다.
콘텐츠 수집과 변경분 조회는 같은 해석을 사용하며 태그 등 다른 ref namespace는 브랜치로 바꾸어 읽지 않는다. 노출 버전은
커밋 SHA다. `ref`로 기본 브랜치 대신 다른 브랜치 하나를 지정할 수 있다(여러 브랜치는 브랜치별 연결). 비활성
저장소는 목록에서 제외하고 명시 선택 시 실패로 남긴다. Git 이력은 수집하지 않는다.

발견 상세의 원본 링크는 Git 저장소의 경우 탐지한 커밋에 고정한 파일 보기
(`{인스턴스}/{조직}/{프로젝트}/_git/{저장소}?path=/{경로}&version=GC{커밋}&_a=contents`)로 만든다. Microsoft 문서가
명시하는 것은 같은 쿼리의 브랜치 표기 `version=GB<브랜치>`와 커밋 페이지(`…/_git/{저장소}/commit/{커밋}`)이며,
커밋 표기 `GC`는 이 쿼리 체계에서 널리 쓰이는 형식이지만 공식 문서나 실제 조직에서 확인하지 않았다.
줄 번호 파라미터는 문서화된 근거가 없어 넣지 않는다(행 번호는 화면에 따로 표시). 웹은 이 모양의 링크만 연다.
TFVC는 문서화된 파일 링크 형식이 없어 링크를 만들지 않고 `SOURCE_LINK_NOT_SUPPORTED`로 알린다.

`version_control="tfvc"`는 프로젝트의 TFVC 트리(`$/{project}`)를 자원 `AZURE_DEVOPS_TFVC`(`조직/프로젝트/$`,
Git 저장소 이름에 쓸 수 없는 `$`로 구분)로 스캔한다. 최신 변경집합 번호를 먼저 정하고 목록과 파일 읽기
(`Accept: application/octet-stream`)를 모두 그 번호로 고정하며, 노출 버전은 변경집합 번호다. 폴더·심볼릭 링크·
삭제된 항목은 건너뛰고, 크기 한도를 넘는 파일은 읽지 않고 실패로 센다. 프로젝트 루트 밖 경로가 목록에 있으면
실패로 남긴다(TFVC 경로는 대소문자를 구분하지 않고 비교). TFVC 범위에는 저장소·브랜치 지정이 없다.
Git·TFVC 모두 전체 트리 응답이 JSON 상한(8MiB)을 넘으면 같은 커밋·변경집합으로 그 폴더의 직속 항목(`OneLevel`)을
읽고 하위 폴더마다 같은 방식으로 나눠 목록을 만든다. 나눈 목록도 루트 밖 경로는 요청하지 않고 실패로 남긴다.
한 폴더의 직속 항목만으로 상한을 넘거나 요청 예산이 부족하면 `SOURCE_RESPONSE_TOO_LARGE`·예산 오류로
부분 실패하며, 이는 빈 저장소의 근거가 아니다.

TFVC 항목의 캐시 리비전은 그 항목을 마지막으로 바꾼 변경집합 번호(`version`)에 대소문자를 바꾸지 않은 경로의 SHA-256을
합친 값이다(이 소스의 탐지 캐시는 리비전만으로 찾으므로 한
변경집합의 두 항목이 같은 값을 갖지 않게 한다). 바뀌지 않은 항목은 다시 읽지 않고, 번호가 없거나 최신 변경집합보다
크면 매번 읽는다. 변경 감지는 TFVC 루트에도 있다. 커서는 `$/{project}` 아래 최신 변경집합 번호이고, 그 뒤의 변경집합
(최신순 30개까지)과 변경집합마다의 변경 목록(쪽당 100개, 합계 2,000개까지)에서 루트 안 파일 경로를 모은다. 이름 변경은
원래 경로를 함께 넣고, 삭제·이름 변경은 Git처럼 루트 전체를 다시 읽는다. 한도를 넘거나, 폴더의 이름 변경·삭제·분기처럼
파일이 하나씩 나오지 않는 변경, 대소문자 때문에 승인 범위 판정이 달라질 수 있는 경로가 있으면 루트 전체를 다시 읽는다.
새 변경집합이 없으면 요청 한 번으로 끝난다.

### 노출 파일의 마지막 작성자

`devops_context.py`의 `exposure_context`는 연결한 조직·프로젝트 안에서 스캔한 버전 기준으로 노출 파일을 마지막으로
바꾼 항목 하나를 읽는다(GET만, `vso.code`). 플랫폼의 `finding-context` 작업이 호출한다.
Git은 `commits?searchCriteria.itemPath=&searchCriteria.itemVersion.version=<commit>&searchCriteria.$top=1`의 작성자
이름·이메일·시각, TFVC는 `tfvc/changesets?searchCriteria.itemPath=&searchCriteria.toId=<changeset>&$top=1`의 작성자
표시 이름·고유 이름이다. Azure DevOps에는 CODEOWNERS 파일이 없고 저장소 읽기 권한자는 보안 namespace 질의라 읽지 않는다.

## Azure DevOps PAT 발급 목록

schema 2 공급자 `azure_devops`(`devops_tokens/`)는 Azure DevOps Services 조직의 개인 액세스 토큰 메타데이터를
발급 목록으로 모은다. [Graph 사용자 목록](https://learn.microsoft.com/en-us/rest/api/azure/devops/graph/users/list?view=azure-devops-rest-7.1)을
`X-MS-ContinuationToken`으로 끝까지 따르고, 사용자마다
[Token Admin PAT 목록](https://learn.microsoft.com/en-us/rest/api/azure/devops/tokenadmin/personal-access-tokens/list?view=azure-devops-rest-7.1)
(`isPublic=false`)을 본문의 `continuationToken`으로 읽는다. 인증은 연결의 비밀 참조(`token` 슬롯)에 둔 조직 관리자
PAT(Token Administration·Graph 읽기)를 Basic으로 보낸다. 체크포인트에는 현재 사용자 페이지의 descriptor·이름·메일과
커서만 남는다.

항목마다 authorization ID(`pat:{조직}:{id}`), 표시 이름, scope 목록, 생성·만료 시각, 소유자 이름·메일, `isValid`를 남긴다.
목록의 사용자는 소유자이며 API가 별도 생성자를 주지 않으므로 생성자는 미지원으로 표시한다.
`isValid=false`는 `INACTIVE`, 만료 시각이 지난 유효 토큰은 `EXPIRED`다. API는 토큰 값과 해시를 주지 않으므로
노출 토큰과는 후보로만 연결되고 "발급했는데 금고에 없음" 판정은 할 수 없다. 응답에 값 필드가 있으면 저장하지 않고
누락 사유와 부분 수집으로 남긴다. 목록에서 빠진 사용자(404)·권한 거절·예산 초과는 빈 목록이 아니라 부분 수집이다.
Azure DevOps Server의 Token Admin은 이번 범위에 없다. 소유자의 subject descriptor(`owner.subject`)도 남긴다:
승인된 폐기가 토큰을 그 목록에서 다시 읽는다.

목록의 PAT는 승인된 조치 계획으로 폐기한다(`devops_tokens/remediation.py`,
[Revocations](https://learn.microsoft.com/en-us/rest/api/azure/devops/tokenadmin/revocations/revoke-authorizations?view=azure-devops-rest-7.1),
[공급자 자격증명 조치](../docs/PROVIDER_ACTIONS.md)). 조치는 Azure DevOps 연결의 전용 용도(`remediation`)로 하며,
프로젝트 컬렉션 관리자의 PAT(`vso.tokenadministration`: 목록과 폐기를 함께 허용)를 쓴다. 폐기는 되돌릴 수 없고
반영까지 최대 1시간이 걸려, 쓰기 직후 아직 유효로 읽히면 결과를 나중에 다시 확인한다. 이 연결은 실행 계정에 묶이지 않는다.

노출 탐지기 `azure-devops-pat-v1`(`AZURE_DEVOPS_PAT`)은 2024년부터 발급된 84자 PAT를 찾는다.
[Purview 정의](https://learn.microsoft.com/en-us/purview/sit-defn-azure-devops-personal-access-token)대로
영숫자 76자 뒤 고정 서명 `AZDO`와 영숫자 4자이며, 앞뒤가 토큰 문자로 이어지면 매칭하지 않는다.
이전 52자 PAT는 최대 유효기간(1년)이 지나 모두 만료되었고 모양만으로 구별할 수 없어 찾지 않는다.

## Key Vault: `azure_key_vault`

기본 Azure 인증은 검증된 vault origin에 맞춰 Public·China·US Government·Germany의
토큰 scope와 authority를 선택한다. 외부에서 주입한 토큰은 그대로 사용하며,
단일 vault와 읽기 전용 요청 경계는 유지한다.

`metadata/`가 Key Vault data-plane API `2025-07-01`을 사용한다. 기본은 한 vault의
`secrets` 메타데이터이며 `sources`에 `versions`·`deleted_secrets`를 추가할 수 있다.
`versions`는 `secrets` 목록이 필요하다. `maxresults`는 서비스 한도인 25 이하로 제한한다.
`updated`는 속성 변경 시각이며 비밀 회전 시각으로 표시하지 않는다.

`capabilities=["vault_metadata", "vault_value"]`와 `options.include_values=true`를
함께 설정하면 `secrets/get` 권한으로 현재 버전의 값을 읽어 공통 탐지 엔진의 HMAC 지문으로 변환한다.
`versions`도 선택했으면 조회한 과거 버전을 추가로 지문화한다. `CURRENT`는 실제 현재 비밀 GET의
응답에만 부여한다. 버전 목록은 현재성을 증명하지 않아 개별 버전 읽기는 `UNKNOWN`으로 표시한다.
기본 메타데이터 모드는 값을 읽지 않으며 `store_values`는 지원하지 않는다.
원문은 DB·checkpoint·일반 기록·오류·export에 저장하지 않는다. 수집기의 등록된 관리 신원으로만 읽으며
발견 자격증명으로 로그인하거나 서비스 권한을 시험하지 않는다.

값 접근 권한 부족·잘못된 응답·인식 불가/크기 초과·부분 목록은 `PARTIAL` 및 미해결 이유로 남는다.
값을 읽지 못한 기록은 목록이 보고한 상태·날짜를 그대로 두고 미해결 이유만 더한다(마지막 목록을 지우지 않는다).
목록이 비활성(`enabled: false`)으로 보고한 비밀·버전은 Key Vault가 GET을 403으로 거절하므로 요청하지 않고
`SECRET_DISABLED`로 남긴다. 값을 비교하지 못했으므로 이 경우도 `PARTIAL`이다.
성공한 일부 값만 보고 전체 금고에 없다고 판정하지 않는다. 지문 비교에는 동일한 키·엔진·정책 계약이 필요하다.
비밀별 값 읽기도 페이지 저장과 함께 cursor가 전진해 재시작 시 이미 처리한 값을 건너뛴다.
삭제된 비밀은 메타데이터만 수집하며 복원 요청은 하지 않는다. 기존 형식 export(`cloud_secret_metadata_inventory`)에는
`secrets` 목록의 현재 비밀만 넣고 삭제된 비밀·값 읽기 기록은 넣지 않는다.

`keys`·`key_versions`·`deleted_keys`, `certificates`·`certificate_versions`·`deleted_certificates`도
명시적으로 선택할 수 있다. 버전 목록에는 대응하는 `keys` 또는 `certificates` 발견이 필요하며, 그 목록이
완료되지 않으면 버전 목록도 `PARTIAL`(`PARENT_LISTING_INCOMPLETE`)이고 비교에서 빠진 버전을 삭제로 보지 않는다.
`keys/list`·`certificates/list` 권한으로 ID·버전·생성/만료/활성 속성·공급자가 제공한 인증서 thumbprint를
수집한다. 키 재료·인증서 비밀·개인키는 읽지 않으며 인증서의 기저 Secret도 자동으로 읽지 않는다.
삭제된 인증서 목록은 공식 API의 `certificates/get/list` 권한 계약도 확인한다.
ARM에서 금고를 발견해도 이 단일 vault 연결이 자동 생성되거나 권한이 확대되지는 않는다.

`public_keys` capability와 `public_certificates` source를 함께 선택하면 `certificates/get` 권한으로
목록에서 발견한 인증서의 **공개 X.509 DER**만 읽어 SHA-256을 계산한다. `certificates` source가
필수이며 `certificate_versions`를 선택하면 발견한 버전도 처리한다. `max_targets`·요청·페이지·레코드
예산을 지키며 저장 후 cursor를 전진한다. 응답은 요청한 vault·이름·버전에 결합한다.
버전 없는 GET으로 반환된 버전에는 현재 버전 관측 표시를 남기고, 버전 지정 GET만으로 현재성을 추정하지 않는다.
`cer` 원문·`sid`·개인키는 저장하지 않고, 응답의 기저 Secret/Key URL을 따라가지 않는다.

## Entra ID: `azure_entra`

`entra/`는 Graph `v1.0`의 `applications`·`servicePrincipals`에서 앱·서비스 주체와
`passwordCredentials`·`keyCredentials` 메타데이터를 수집한다. 기본 `sources`는
`["applications", "service_principals"]`다. `policy` capability와
`federated_identity_credentials` source를 선택하면 각 앱의 페더레이션 신뢰 설정도 수집한다.
이때 `applications` source가 함께 필요하다. 앱별 페더레이션 조회는 `options.max_targets`로 제한하며
한도 도달은 부분 수집으로 표시한다. 이는 발급된 임시 토큰 목록이 아니다.
자격증명의 `startDateTime`은 유효 시작 시각(인증서의 NotBefore 또는 호출자가 정한 시작)이라 생성일이 아닌
`not_before`로 남긴다. Graph는 자격증명을 추가한 시각을 주지 않으므로 발급 목록의 생성일은 미지원으로 표시한다.

연결은 `auth_type="workload_identity"`, `tenant=<소문자 tenant GUID>`,
`tenant_confirmed=true`, `scopes=[{"kind":"organization","id":<같은 tenant GUID>}]`를 사용한다.
지원 origin은 `https://graph.microsoft.com`, `https://graph.microsoft.us`,
`https://dod-graph.microsoft.us`, `https://microsoftgraph.chinacloudapi.cn`이다.
등록된 worker Azure 신원을 쓰고 비밀 참조·원문 bearer 저장·임의 origin을 허용하지 않는다.

### 앱 자격증명이 할 수 있는 일: `app_permissions`·`app_azure_roles` (2026-10-07)

`policy` capability와 두 옵션(source) 중 하나를 켜면, 비밀이나 인증서가 있는 앱마다 그 자격증명이 로그인하는 서비스
주체가 가진 것을 읽어 각 자격증명의 권한으로 붙인다(`entra/permissions.py`의 `app_access` 단계, 서비스 주체 최대
`options.max_targets`=50개). 앱 등록의 자격증명은 `appId`가 같은 서비스 주체로 연결하고, 목록에 그 서비스 주체가
없으면 추측하지 않고 보고서에 개수만 남긴다. 토큰 서명용 키(`use`=`Sign`)는 로그인 자격증명이 아니어서 제외한다.

| 옵션 | 종류 | 읽는 곳 | 권한 이름 |
| --- | --- | --- | --- |
| `app_permissions` | 애플리케이션 권한 | `GET /v1.0/servicePrincipals/{id}/appRoleAssignments`와 리소스 서비스 주체의 `appRoles`(Application.Read.All) | `Microsoft Graph: Directory.ReadWrite.All` |
| `app_permissions` | Entra 역할 | `GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{id}'`와 역할 정의(RoleManagement.Read.Directory) | `Global Administrator`(관리 단위·앱 범위면 `· 범위`) |
| `app_azure_roles` | Azure 역할 | `GET /providers/Microsoft.Management/managementGroups/{tenant}/providers/Microsoft.Authorization/roleAssignments?$filter=assignedTo('{id}')`와 역할 정의 | `Owner · /subscriptions/…` |

Azure 역할은 역할 할당·정의 읽기(`Microsoft.Authorization/roleAssignments/read`·`roleDefinitions/read`)만 담은 사용자
지정 역할을 테넌트 루트 관리 그룹(ID가 테넌트 ID)에 주고 읽는다. 연결 안내가 역할 정의와 할당 명령을 만든다. 루트 관리
그룹은 테넌트에서 관리 그룹을 처음 쓸 때 만들어지므로, 없으면 연결 점검이 `AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND`로
알린다. 역할 정의는 루트 관리 그룹에서 먼저 읽고, 없으면 할당이 가리키는 곳에서 읽는다.

읽은 것은 모두 존재하는 부여(`ALLOW`)이며 콘솔의 권한 표에 나온다. Azure 역할은 그룹으로 받은 할당
(`membership_resolution=group_member`)까지 포함하고, 할당의 조건은 있음(`condition_present`)만 남기며 원문은
저장하지 않는다. 읽지 못한 종류는 `UNKNOWN` 항목 하나와 `error_code`로 남기고, 모든 서비스 주체에서 되풀이될 실패
(권한 거절·인증 실패·연결 실패, Azure 역할의 루트 관리 그룹 없음)는 다시 묻지 않는다. 한 자격증명의 권한이 250개를
넘으면 `UNKNOWN` 항목을 남기고 잘렸다는 `permissions_truncated` 항목을 붙인다. 이 단계의 보고서는 끝까지 돌면
`COMPLETE`이고 읽은 범위(`selection`)와 실패 개수(`error_counts`)를 사실로 남기므로, 자격증명 목록과 실행의 수집
상태를 바꾸지 않는다. 역할 정의를 읽지 못한 Azure 할당은 역할 ID로 보여 준다. 공개 인증서 옵션과 함께 쓰면 인증서의
마지막 관측이 권한과 공개 인증서 근거를 함께 가진다.

남는 미확인 영역: 거부 할당(deny assignment)은 읽지 않는다(`deny_policies=not_evaluated`). 역할 할당 가능 그룹으로
받은 Entra 역할과 PIM의 eligible 할당은 목록에 없다. 워크로드 ID의 조건부 액세스, Exchange의 애플리케이션 RBAC와
SharePoint `Sites.Selected`처럼 애플리케이션 권한을 좁히는 설정은 판정에 없다. 다중 테넌트 앱이 다른 테넌트에서 받은
권한과 Azure Lighthouse 위임은 보지 않는다. 루트 관리 그룹에서 `assignedTo`가 하위 구독·리소스 그룹·리소스의 할당까지
돌려준다는 점은 실제 테넌트에서 확인하지 않았다. Azure 역할은 Azure 글로벌 클라우드(`https://graph.microsoft.com`)에서만
켤 수 있다. 오래된 체크포인트(버전 1)는 같은 단계 위치로 이어 간다.

앱 권한은 관리자 동의된 `Application.Read.All`과 `Organization.Read.All`이 필요하다.
후자는 재시작을 포함한 각 시도에서 `/organization?$select=id`로 응답 tenant를 검사하기 위한 것이다.
SDK에 tenant를 지정하는 것만으로 모든 managed identity가 해당 tenant에서 실행됐다고 단정하지 않는다.
tenant 불일치·확인 실패는 앱 목록을 요청하기 전에 실패한다. 이 검사는 collector principal의 ID나
발견한 비밀의 유효성 검증이 아니다. `principal_pin`은 지원하지 않는다.

사람 목록(`entra_id`, Microsoft 연결의 `identity` 기능 포함)은 Graph 요청 전에 액세스 토큰의 `tid`를 읽어
연결의 tenant와 다르면 `ENTRA_ID_TENANT_MISMATCH`로 실패한다(관리 ID는 요청한 tenant를 무시한다).
`tid`가 읽히고 일치하는 기존 연결은 추가 권한 없이 계속 수집하며 `/organization`을 요청하지 않는다.
`tid`를 읽을 수 없는 토큰(암호화 액세스 토큰 포함)은 사용자 페이지를 요청하기 전에 같은 토큰으로
`/v1.0/organization?$select=id`를 읽어 조직이 정확히 하나이고 연결의 tenant와 일치하는지 확인한다.
이때는 관리자 동의된 애플리케이션 권한 `Organization.Read.All`이 필요하다(그런 토큰을 쓰는 연결만).
조직 불일치·복수 조직·후속 페이지는 `ENTRA_ID_TENANT_MISMATCH`, 403 등 조회·응답 해석 실패는
`ENTRA_ID_TENANT_UNVERIFIED`로 실패하고 사용자 목록을 읽지 않는다. 확인 요청도 요청 예산·응답 크기 제한을 따른다.
두 온보딩 descriptor(`azure`·`entra_id`)는 이 권한을 선택 권한(`required: false`)으로 안내하고 연결 권한 점검에서 조직 읽기를
따로 보여 주지만, 없어도 활성화를 막지 않는다(tid가 읽히는 연결에는 필요 없고, 읽히지 않으면 수집이 위 코드로 멈춘다).

Graph `keyId`는 공급자 식별자 근거다. client secret의 `secretText`·hint와 응답의 임의 필드는 저장하지 않는다.
비밀값은 생성 후 재조회할 수 없어 메타데이터만으로 금고 값과 동일하다고 확정하지 않는다.
평문 노출은 공통 탐지기 `azure-entra-client-secret-v1`(`AZURE_ENTRA_CLIENT_SECRET`)이 찾는다.
[Microsoft 정의](https://learn.microsoft.com/en-us/purview/sit-defn-azure-ad-client-secret)는 문자 범위와 최대 40자만
명시하므로, 탐지는 현행 secret에서 관측되는 형식(세 글자·숫자·`Q~`·31–34자)에 기대며 공식 형식 보장이 아니다. 비교할 값이나 해시가 없으므로 발견한 secret은 이 발급 목록의
후보로만 연결되며, 발급 secret의 금고 미보관은 판정하지 않는다. `Q~`가 없는 이전 형식은 모양으로 구별할 수 없어
`AZURE_CLIENT_SECRET`·`ARM_CLIENT_SECRET` 같은 Azure client-secret 설정 이름 바로 옆의 32–44자 값만
`azure-entra-client-secret-labeled-v1`이 중간 신뢰도로 탐지한다. 이름 없는 이전 형식 secret은 탐지하지 않는다.
공개키의 `customKeyIdentifier`는 공급자가 제공한 식별자로 보존하며 항상 인증서 thumbprint라고 가정하지 않는다.
만료일·비활성 상태를 기록하지만 만료 전이라는 이유로 현재 인증 가능 상태를 부여하지 않는다.
Managed identity와 페더레이션은 고객 금고에 장기 비밀이 없다는 경고를 일괄 적용할 대상이 아니다.

`public_keys` capability와 `public_certificates` source를 선택하면 앞선 앱/서비스 주체 목록에서
발견한 X.509 자격증명에 한해 `/applications/{id}` 또는 `/servicePrincipals/{id}`를
`$select=id,appId,keyCredentials`로 조회한다. 목록 API의 `key`는 null일 수 있어 이 singleton 조회가 필요하다.
응답의 object ID·app ID·key ID를 목록과 대조하고 실제 DER 인증서를 파싱한 뒤 SHA-256만 보존한다.
`applications` 또는 `service_principals` source가 함께 필요하며 `max_targets`는 singleton 대상 개수 한도다.
중복/변경된 ID·잘못된 인증서·403·한도 초과는 부분 수집, 429는 기존 checkpoint 대기로 남긴다.

두 수집기의 공개 인증서 근거는 `sha256_fingerprint`와 `evidence_class=X509_DER_SHA256` facts다.
공통 대조는 `cremore_azure_provider.public_certificates.certificate_evidence(record)`를 import한다.
이 순수 helper는 명시적 공개 인증서 조회 operation만 인정하며 `customKeyIdentifier`·`x5t`는 비교에 쓰지 않는다.
동일 DER은 **공개 인증서 연결 근거**이며 비밀값 일치, 금고의 개인키 보관, 현재 인증 가능성 또는 권한 증거가 아니다.
`value_match`를 만들지 않으며 기존 P06/P08 메타데이터는 유지한다.
공통 보관 대조 화면에서는 발급 인벤토리 행(`origin=ISSUANCE`, `credential_type=AZURE_CERTIFICATE`)으로
표시한다. 최신 금고 버전의 공개 DER이 일치하면 `PUBLIC_CERTIFICATE_MATCH`와
`PUBLIC_CERTIFICATE_SHA256` 근거를 사용하고, 이전 버전·오래된/변경된/비활성 금고 연결의 근거는 이력으로 남긴다.
없으면 `UNKNOWN`이다. 대조 범위가 확인되고 선택한 모든 Key Vault 인증서 연결의 최신 수집이 완료·유효하며
발급 관측도 최신일 때만 `PUBLIC_CERTIFICATE_NOT_OBSERVED`(그 범위에서 공개 인증서 미관측)로 표시한다.
이것도 공개 인증서 목록에 관한 판정이며 개인키/비밀의 금고 부재를 뜻하지 않는다.
발급 전용 항목 수(`issuance_only`)에는 인증서가 포함되지만 평문 노출 수·비밀값 일치율 분모/분자는 늘리지 않는다.
공개 인증서 전용 연결은 비밀값 비교 scope에 포함되지 않으며, 전체 조회/표시 한도에 걸리면 부분 결과임을 표시한다.

목록은 승인된 origin/path에 고정되며 nextLink의 cursor만 복사한다. 요청·재시도·페이지·레코드 한도,
응답 바이트 제한, 취소, 재시작, 429 대기, 실패/빈 결과 구분을 유지한다. Graph 기본 목록은 최대 25개
객체씩 요청한다. keyCredentials 선택은 tenant별 150 requests/min 한도가 있으므로 여러 worker가
같은 tenant를 읽는 경우 서버의 429/Retry-After 응답을 따른다.

## Entra 앱 목록으로 연동 제안

Microsoft 연결의 Entra 발급 목록은 수집한 앱 등록·서비스 주체를 표시 이름과 함께 저장한다. 연동 화면은 사용 중인 앱의 그 이름에 CreMore가 연결하는
서비스(GitHub·GitLab·Atlassian·Slack·Notion·AWS·Google Cloud·Okta 등)가 보이고 아직 그 연결이 없으면 연동을 제안한다
(`cremore/onboarding/suggestions.py`). 저장된 목록만 읽고 Microsoft에 따로 묻지 않는다.

## 지원 범위와 검증

`arm/`의 `azure_resource_manager`는 Public Azure `https://management.azure.com`에 고정된다.
`tenant`·`tenant_confirmed`·`workload_identity`는 Entra와 동일한 승인 경계를 사용하지만 Graph 권한은
요구하지 않는다. ARM 발견과 Key Vault data-plane 권한은 별개다.

- `mode="discovery"`, 단일 `organization` scope(tenant GUID), `sources=["subscriptions"]`:
  `/tenants`로 해당 tenant에 대한 접근을 확인한 뒤 `/subscriptions`에서 그 tenant에 속하고 수집 신원에
  보이는 구독 메타데이터만 반환한다. 다른 tenant의 구독은 포함하지 않는다. 전사 전체를 볼 권한을
  증명하는 기능은 아니며 발견 결과가 구독 승인이나 비밀 접근 목록을 자동으로 채우지 않는다.
- `mode="inventory"`, 명시한 `subscription` scope 목록:
  각 구독의 GET 응답 tenant/subscription ID를 확인한 뒤 선택된 `vaults`·`storage_accounts`를 수집한다.
  이 두 source가 기본이다. `subscriptions`를 선택하면 승인된 구독 자체의 메타데이터도 남긴다.
  금고 목록의 `/resources` 후속 페이지 등에서 `properties.tenantId`·`vaultUri`가 누락되면, 승인 구독의 유효한
  `Microsoft.KeyVault/vaults` ID에 한해 같은 `Microsoft.KeyVault/vaults/read` 권한과 금고 API 버전으로
  `GET {vault ID}`를 추가 호출한다. 완전한 속성이 있으면 추가 호출하지 않으며, 추가 조회도 기존 요청 예산을 쓴다.
  응답 ID·구독 범위·tenant·vault URI를 다시 검사하고, 권한 거절·범위 불일치는 해당 금고를 기록하지 않은 채
  이유가 있는 `PARTIAL`로 남긴다. 조회 실패를 금고 부재의 증거로 바꾸지 않는다.
- Storage 키 지문화는 `sources`의 `storage_keys`, `include_values=true`, `issuer_value` capability,
  `options.azure_storage_accounts`의 정확한 계정 ARM ID 목록이 모두 있어야 한다.
  계정 ID는 `/subscriptions/<GUID>/resourceGroups/<이름>/providers/Microsoft.Storage/storageAccounts/<계정명>`이며
  해당 구독도 명시적으로 승인되어 있어야 한다. 목록 발견 결과로 이 설정을 자동 확대하지 않는다.

Storage `listKeys`는 읽기 작업이지만 HTTP `POST`이며 응답에 키값이 포함된다. 메타데이터 모드에서는
호출하지 않는다. 승인된 계정의 `key1`·`key2` 값만 메모리에서 기존 `AZURE_STORAGE_KEY` 탐지기의
`AccountKey=<값>` 정규화로 지문화하고 원문을 저장하지 않는다. 반환되지 않은 키 슬롯·새로운/중복 키 이름·
잘못된 값·권한 거절은 부분 수집으로 남긴다. 이 조회는 키 재생성, SAS 생성 또는 발견 키로 서비스에
접속하는 검증이 아니다. 키 슬롯 이름은 발급된 모든 과거 키 버전을 식별하는 ID가 아니다.

ARM 최소 권한은 `Microsoft.Resources/subscriptions/read`, 발견 모드의 tenant 조회 접근,
선택한 리소스의 `Microsoft.KeyVault/vaults/read`·`Microsoft.Storage/storageAccounts/read`다.
Storage 값을 읽는 승인된 계정에만 `Microsoft.Storage/storageAccounts/listKeys/action`을 별도로 부여한다.
Reader만으로는 이 값 접근 권한이 생기지 않는다. Key Vault 비밀·키·인증서의 data-plane 권한은 이 권한과 별개다.

Azure가 발급 목록을 추적하지 않는 SAS와 모든 활성 OAuth 세션의 전수 목록은 주장하지 않는다.
노출된 SAS는 공통 탐지기 `azure-sas-token-v1`(`AZURE_SAS_TOKEN`)이 `sv=` 날짜와 `sig=`가 함께 있는 쿼리로 찾는다.
서명(`sig`)은 지문으로만 남고, [`sas.py`](backend/cremore_azure_provider/sas.py)가 같은 쿼리의 서명된 필드
(권한·만료·리소스·저장된 접근 정책·암호화 범위·응답 헤더 재정의·사용자 위임 주체 `skoid`/`sktid`),
URL 또는 연결 문자열의 계정 이름, 서비스 SAS가 서명하는 URL 경로만 `azure_sas`로 남긴다.
이 필드는 토큰에 적힌 내용이며 현재 유효성이 아니다. 계정 이름이 같은 Storage 키 항목과는 식별자 수준으로 연결한다.

`storage_keys` 수집은 발견된 SAS 중 승인된 계정 이름을 가진 것(최대 1,000개 발견 항목)의 자격증명 지문과
서명된 필드를 워커에서 받는다. 메모리에 있는 `key1`·`key2`로 Microsoft가 문서화한 string-to-sign
([계정 SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas),
[서비스 SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas))을 HMAC-SHA256으로
재계산하고, Base64·퍼센트 인코딩 표기의 지문이 발견 SAS 지문과 같으면 그 키의 비공개
`value_match.signed_fingerprints`에 남긴다. 외부 호출·발견 SAS 사용·서명 원문 저장은 없으며 공개 응답에서
이 필드를 제거한다. 발견 조회는 그 키를 `VALUE`/`SAS_SIGNATURE`로, 다른 키는 계정 이름 연결로 표시한다.
서명 일치는 그 키가 이 SAS에 서명했다는 뜻이며, 이 SAS를 무효화하려면 저장된 접근 정책이 없을 때 해당 키를
재생성해야 한다. 현재 유효성·만료·권한 검증은 아니다.

지원 범위는 계정 키로 서명한 계정 SAS(`sv=2015-04-05` 이상)와 서비스 SAS다. 서비스 SAS는 Blob(`dfs` 포함,
2012-02-12 이상), Queue·Table(2013-08-15 이상), Files(2015-02-21 이상)이며, 버전마다 문서의 형식(2015-02-21 전에는
정규화 리소스에 서비스 이름이 없고, 2015-04-05 전에는 IP·프로토콜 필드가 없음)을 따른다. Table은 `tn`의 소문자
테이블 이름과 파티션·행 키 범위를 서명 대상에 넣는다. 사용자 위임 SAS(Entra 위임 키로 서명)와 경로가 없는
Blob·Files·Queue 서비스 SAS(연결 문자열)는 확인하지 않는다. 일치하지 않거나 확인하지 못한 SAS는 부재나 다른 키의 근거로 쓰지 않는다. 형식은 공식 문서의
버전별 정의를 테스트에 고정했으나 Azure가 실제로 발급한 SAS나 공식 SDK의 결과로는 검증하지 않았다.
경로·신규 필드는 이 변경 이후 스캔한 노출에만 있으므로, 이전 서비스 SAS는 해당 위치를 다시 스캔해야 확인된다.
SAS를 새로 발견하면 다음 `storage_keys` 수집 때 확인한다.
ARM 관리 인벤토리와 애플리케이션 자격증명·KV 저장 객체도 구분한다. 원문 88자 키만 저장한 금고 항목은
타입을 안전하게 추정할 수 없어 일반 탐지기에서 미인식일 수 있다. `AccountKey=` 문맥 또는 별도의
신뢰 가능한 발급/보관 근거가 없는 값을 일치한다고 표시하지 않는다.

로컬 합성 테스트는 tenant/origin 경계, 페이지·checkpoint·budget, 값 생략, 지문 동일성,
권한 오류·부분 목록·취소를 검사한다. 실제 Entra 관리자 동의/managed identity 로그인, Azure 권한 설정,
고객 Key Vault API 실행은 별도로 승인된 테스트 tenant/vault에서 검증해야 한다.

공식 계약(2026-09-25 확인):

- [Graph applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0),
  [servicePrincipals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0),
  [organization](https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0)
- [passwordCredential](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0),
  [keyCredential](https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0),
  [federated identity](https://learn.microsoft.com/en-us/graph/api/federatedidentitycredential-list?view=graph-rest-1.0)
- [Application singleton GET](https://learn.microsoft.com/en-us/graph/api/application-get?view=graph-rest-1.0),
  [Service principal singleton GET](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0),
  [Public certificate GET](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate?view=rest-keyvault-certificates-2025-07-01)
- [Key Vault secrets listing](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secrets/get-secrets?view=rest-keyvault-secrets-2025-07-01),
  [secret value](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01)
- [Key Vault keys](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys?view=rest-keyvault-keys-2025-07-01),
  [key versions](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key-versions/get-key-versions?view=rest-keyvault-keys-2025-07-01),
  [certificates](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates/get-certificates?view=rest-keyvault-certificates-2025-07-01),
  [certificate versions](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate-versions/get-certificate-versions?view=rest-keyvault-certificates-2025-07-01)
- [Tenants](https://learn.microsoft.com/en-us/rest/api/resources/tenants/list?view=rest-resources-2022-12-01),
  [Subscriptions](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list?view=rest-resources-2022-12-01),
  [Subscription GET](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/get?view=rest-resources-2022-12-01)
- [Vault discovery](https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription?view=rest-keyvault-keyvault-2024-11-01),
  [Storage discovery](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list?view=rest-storagerp-2025-01-01),
  [Storage listKeys](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list-keys?view=rest-storagerp-2025-01-01),
  [Storage key permissions](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.
