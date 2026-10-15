# 노출 위치의 접근 관련 근거

자격증명이 발견된 저장소·페이지의 접근 관련 정보는 기존 `finding-context` 작업으로 읽는다.
이 결과는 **수집 시점에 공급자가 보고한 협업자·프로젝트 멤버·명시적 권한 설정**이다. 실제로 파일을 읽은 사람의 이력,
노출 당시의 독자 목록, 모든 정책을 평가한 실효 접근 권한, 자격증명의 발급자·소유자를 뜻하지 않는다.
GitLab 프로젝트 멤버와 저장소 코드를 읽을 수 있는 사람을 동일하게 취급하지 않는다.

## 공급자별 현재 범위

| 공급자 | 현재 제공하는 근거 | 제한 및 추가 구현에 필요한 정보 |
| --- | --- | --- |
| GitHub | 저장소 collaborators, 공급자가 반환한 역할, 공개 범위, CODEOWNERS, 마지막 커밋 작성자 | `affiliation=all`로 보고된 협업자를 읽는다. 공개·internal 저장소의 비회원 독자, 공개 링크, 앱·토큰 전체, 실제 열람 이력은 열거하지 않는다. |
| GitLab | 상속을 포함한 프로젝트 members, 역할, 공개 범위, CODEOWNERS, 마지막 커밋 작성자 | 프로젝트 구성원이라는 사실만으로 저장소 읽기를 확정하지 않는다. repository access 설정을 확인하고 Reporter·Developer·Maintainer·Owner인 경우에만 역할에 따른 읽기 근거를 표시한다. Guest·Planner·Security Manager·알 수 없는 역할은 읽기 여부 미확인이다. 공개/internal 비회원 독자는 열거하지 않는다. |
| Notion | 마지막 편집자 | 공개 API가 페이지 ACL 목록을 제공하지 않는다. 워크스페이스 사용자 목록을 페이지 독자로 대체하지 않는다. |
| Confluence | 마지막 편집자, 페이지의 직접 read restriction에 지정된 사용자·그룹 | 같은 사이트의 v1 restriction API를 읽는다. 제한 대상이라는 사실이 읽기권한 부여는 아니다. 상위 페이지·space/global 권한·그룹 구성원은 평가하지 않는다. 첫 사용자·그룹 확장을 넘으면 부분 수집이다. |
| Bitbucket | 마지막 커밋 작성자, 저장소 사용자·그룹별 명시적 permission | Cloud `permissions-config/users,groups`, Data Center `permissions/users,groups`를 읽는다. 관리자/권한 조회 권한이 별도로 필요할 수 있다. workspace/project 상속·그룹 구성원·실효 독자는 평가하지 않는다. |
| Azure DevOps | 마지막 작성자, Git repository namespace의 직접 Read allow/deny ACE | 저장소 GUID와 project를 먼저 확인하고 정확한 repository token의 ACL만 읽는다. ACL 조회 권한이 추가로 필요하다. 상속·브랜치·그룹·최종 deny 평가는 하지 않는다. TFVC는 작성자만 지원하며 경로 ACL은 미지원이다. |
| AWS S3 | 객체에 해당하는 bucket policy의 명시적 GetObject grant/deny, bucket/object ACL, bucket 공개 접근 차단 설정 | 승인된 account scanner로 `GetBucketPolicy`, `GetBucketAcl`, `GetObjectAcl`(버전은 `GetObjectVersionAcl` 권한), `GetBucketPublicAccessBlock`을 읽는다. Bucket ACL READ는 객체 읽기권한이 아니다. IAM·SCP·boundary·session·조건·VPC·KMS·서명 URL의 실효 접근 평가는 하지 않는다. |
| GCP Cloud Storage | bucket IAM binding, 수집 generation에 고정한 object ACL | `storage.buckets.get/getIamPolicy`, `storage.objects.getIamPolicy`가 필요하다. UBLA면 object ACL을 요청하지 않는다. 상위 IAM·조건·그룹·공개 접근 방지·서명 URL은 평가하지 않는다. IAM 역할 자체가 객체 읽기권한이라는 뜻은 아니다. |
| Azure Blob | container의 공개 접근 설정과 저장된 access policy ID/permission | 기존 Entra 인증으로 Get Container ACL을 읽으며 `Microsoft.Storage/storageAccounts/blobServices/containers/getAcl/action`이 필요하다. 정책은 POLICY 타입이며 사용자나 SAS 자체가 아니다. 정책 시간·계정·네트워크·RBAC/ABAC·ADLS ACL·shared key·실제 발급 SAS는 평가/열거하지 않는다. |
| Vault/OpenBao | 이 콘텐츠 접근 목록의 대상 아님 | schema 1 금고 대조 연결이다. 정책·그룹·entity alias·namespace의 권한 평가는 별도 기능이다. |
| 웹사이트 | 접근자 목록 미지원 | 수집 시점 인증 없는 공개 요청의 성공은 근거가 될 수 있으나, 방문자·접근 가능한 사람의 목록 API는 없다. |

각 미지원 위치도 결과에 남는다. 미지원·권한 거절·조회 실패를 독자가 없는 빈 목록으로 해석하지 않는다.
접근 목록 읽기 권한이 없어도 기존 작성자 근거와 이미 읽은 부분 목록을 함께 유지한다.
새 권한 설정 수집기는 모든 행의 `read_access=UNKNOWN`을 유지한다. 그룹·서비스 주체·공개 대상과
개별 사용자를 `principal_kind`로 구분하고, grant/deny/restriction을 사람의 실효 권한으로 바꾸지 않는다.

## 연결과 승인 범위

- Worker만 해당 콘텐츠 연결의 인증 자격증명을 사용한다. 공급자 연결·콘텐츠 기능이 활성이고,
  현재 인증에 대해 승인한 READY 검사 범위에 위치가 포함되어 있어야 조회한다.
- 리소스·경로 제외, Notion 하위 페이지 승인은 기존 `scope.rescan_target` 계약을 재사용한다.
  요청마다 활성 상태·승인 범위·인증 및 연결 설정을 다시 확인한다. 도중 변경되면 추가 요청을 중단하고
  이전 인증으로 읽던 결과를 저장 대상에서 제외한다.
- `access_key`는 공급자·연결 ID·리소스에 묶인다. 이름이 같은 서로 다른 연결의 저장소를 합치지 않는다.
  S3·GCS 객체 ACL은 여기에 객체 경로까지 묶어 같은 bucket의 다른 객체 ACL을 재사용하지 않는다.
  위치와 접근 근거는 이 키로 연결하고 표시 이름만으로 매칭하지 않는다. 목록의 작성자도 연결 ID에 묶는다.
  이전 형식에 연결 정보가 없으면 새 조회 전까지 모호한 작성자·접근 근거를 연결하지 않는다.
- 외부에는 읽기 요청만 한다. CODEOWNERS 원문과 외부 응답 본문을 저장하지 않고 파싱된 담당자,
  작성자, 협업자·멤버의 제한된 메타데이터만 저장한다. 수집한 자격증명 원문은 이 기능에 저장하지 않는다.
  정책 원문·조건값·SAS도 보관하지 않는다. S3는 요청마다 scanner 승인 revision·계정·현재 scope를
  재확인하고 `ExpectedBucketOwner`를 지정한다. 계정 미지정이나 승인 변경 시 ambient AWS 신원으로 우회하지 않는다.

## 한도와 API 표현

`GET /api/v1/findings/{finding_id}/context`는 analyst 이상이 읽는다. 같은 경로의 POST는 다시 조회하는
작업을 예약한다. 대표 finding이 속한 자격증명의 현재 노출 위치들을 사용한다.

- 한 번에 외부 컨텍스트 조회는 최대 5개 위치, 응답에 남기는 위치는 최대 100개다.
  같은 저장소의 멤버 목록은 연결별로 재사용하지만 파일 작성자 조회도 위치 예산에 포함한다.
- GitHub 협업자와 GitLab 프로젝트 멤버는 worker가 3페이지마다
  결과와 다음 페이지를 같은 리스 트랜잭션에 저장하고 큐로 돌려준다. 새 worker에서 이어 읽으며
  저장소당 100페이지/10,000명, 전체 작업 700요청/1시간 상한을 지킨다.
  현재 연결·승인 범위를 요청마다/저장 직전에 확인하고 다른 인증으로 바뀌면 이전 목록에 이어 붙이지 않는다.
  페이지 조회 중 구성원 변경 가능성은 `PAGED_LIST_NOT_ATOMIC`으로 표시한다.
  콘솔 검색은 수집된 전체 목록에 적용하고 공통 페이지 컨트롤로 최대 100행씩 표시한다.
  GitLab의 `X-Next-Page`가 있으면 짧은 페이지도 이어 읽고 빈 헤더는 목록의 끝으로 해석한다.
  역행·도약·잘못된 페이지 정보는 부분 근거를 보존하고 `MEMBER_PAGINATION_INVALID`로 멈춘다.
  재개는 worker 작업의 동작이며 직접 호출하는 동기 수집은 한 번의 3페이지 예산만 사용한다.
- Confluence는 사용자·그룹 확장을 각각 최대 100개 읽는다. Bitbucket은 사용자·그룹 각각 최대 3페이지×50개다.
  Azure Git은 직접 ACL 1개에서 ACE 최대 300개, GCS는 bucket 메타데이터·IAM·object ACL 최대 5회 요청 예산,
  S3는 읽기 작업 4종, Blob은 GET 1종(재시도 포함 3회 예산)에서 저장 정책 최대 5개를 읽는다. 결과 principal은 공통 최대 300개다.
- `location_count`는 현재의 중복 제거 위치 수, `queried_locations`는 조회 시도 위치 수,
  `unqueried_locations`는 조회하지 않은 위치 수, `omitted_locations`는 100개 표시 예산 밖의 위치 수다.
  조회 시도 수는 성공 수가 아니다.
- `repositories`의 `status`, `basis`, `evidence_kind`, `visibility`, `observed_at`, `completeness`,
  `limitations`를 함께 해석한다. `people[].read_access`는 `REPORTED` 또는 `UNKNOWN`이다.
  `principal_id`, `principal_kind`, `permission`, `effect`는 제한된 설정 근거이며 사람 검색의 IdP 신원을 대신하지 않는다.
  GitHub의 `type=User/Bot`, GitLab 멤버의 bot 표시를 사용해 사용자와 서비스 주체를 구분한다.
  GitHub가 유형을 주지 않거나 알 수 없는 유형을 반환하면 `UNKNOWN`으로 유지한다.
  `completeness=COMPLETE`도 **그 공급자 목록 조회의 완료**이며 모든 실효 독자의 완전한 목록이 아니다.
- 후속 페이지가 실패하면 앞서 수집된 사람을 보존하며 실패 status와 `completeness=PARTIAL`을 유지한다.
  페이지·사람·위치 한도, 비정상 행은 부분 수집으로 표시한다. 알려지지 않은 공개 범위는 `UNKNOWN`이다.
- `BLOCKED`, `UNSUPPORTED`, `LIMIT_REACHED`, `FORBIDDEN`, `UNAVAILABLE` 등은 사람 0명과 구별한다.
  관측 시각은 성공한 전체 또는 부분 목록에만 붙인다. 과거 저장 결과는 현재 권한 보장이 아니다.
  페이지 재개 뒤의 관측 시각은 마지막 성공한 묶음의 조회 시각이며, 앞 페이지의 계정을 다시 확인한 시각은 아니다.
  콘솔은 저장된 관측 이후 권한 변경 가능성과 실행 중 저장된 행 수를 표시한다.

## 검증 범위

기본 검증은 fake HTTP와 격리된 SQLite/PostgreSQL로 수행한다. 연결별 동일 이름 격리, 승인·제외·중지,
조회 도중 인증/호스트 변경, 부분 결과 보존, 예산·미지원 위치 표시, 새 필드 저장과 과거 응답 호환을 검사한다.
실제 공급자 계정의 관리자 권한·대규모 멤버 목록·기업별 커스텀 역할은 별도 실환경 검증 대상이다.

추가 권한 근거의 구현 검증은 fake API로 수행했다. 실제 공급자별 ACL 권한과 응답은 이번 작업에서
실계정으로 조회하지 않았다. 배포만으로 기존 연결에 위 추가 조회 권한이 자동 부여되지 않는다.

공식 API 근거:

- [Confluence content restrictions](https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content-restrictions/)
- [GitHub repository collaborators](https://docs.github.com/en/rest/collaborators/collaborators#list-repository-collaborators)
- [GitLab members](https://docs.gitlab.com/api/members/), [REST pagination](https://docs.gitlab.com/api/rest/#pagination)
- [Bitbucket Cloud repositories](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/)
- [Azure DevOps ACL query](https://learn.microsoft.com/en-us/rest/api/azure/devops/security/access-control-lists/query?view=azure-devops-rest-7.1)
- [Azure Blob container ACL과 필요한 RBAC action](https://learn.microsoft.com/en-us/rest/api/storageservices/get-container-acl)
- [GCS bucket IAM](https://cloud.google.com/storage/docs/json_api/v1/buckets/getIamPolicy), [object ACL](https://cloud.google.com/storage/docs/json_api/v1/objectAccessControls/list)
- [S3 GetObjectAcl](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html)

2026-10-03 실행 결과:

- 추가 공급자 구현: ownership·AWS/GCS/Blob/Confluence/Bitbucket/Azure Git context·AWS read-only·공급자 경계·source 계약 묶음 **169 passed**. 격리 PostgreSQL 17을 포함했고 추가/변경 Python Ruff와 공백 검사도 통과했다. 객체별 ACL 격리·S3 승인 취소·정책 조건 비보관·일부 거절·타입 구분을 검사했다.
- 격리 PostgreSQL 17 포함 ownership·credential records·GitHub/GitLab context 묶음 86 passed.
- 기능 중지 guard 추가 뒤 ownership 28 passed. 독립 검토의 PostgreSQL 포함 core/provider 묶음 44 passed와 마지막 상태 처리 집중 5 passed.
- GitHub/GitLab 공급자 fake HTTP 15 passed. GitLab Security Manager는 읽기권한 미확인으로 검사한다.
- 웹 전체 Node 259 passed, tsc 통과. KO/light 1440px·EN/dark 360px의 검색·연결 격리·부분/미지원·CSV·overlay·Escape 초점 복귀와 기존 대응 티켓 브라우저 검사 통과.
- 변경 Python Ruff·공백 검사 통과. 위 검사 수는 중복되며, 실제 외부 계정 조회·티켓 발송은 실행하지 않았다.

2026-10-06 후속 검증:

- GitLab 재개·페이지 헤더, GitHub/GitLab 사용자·봇 구분, 소스 계약과 기존 공급자 ACL 회귀 묶음 **109 passed**.
  fake HTTP·격리 SQLite를 사용했고 PostgreSQL은 실행하지 않았다. 새 worker에서 735명까지 재개,
  권한 거절·취소·자격증명 실패·재승인된 인증 교체·요청/시간 예산 중단 및 부분 근거의 관측 시각 보존을 검사했다.
- KO/light 1440px·EN/dark 360px 브라우저 검사는 235행의 검색·페이지 이동, 연결 격리,
  부분/미지원/과거 근거·CSV·초점 복귀와 저장된 관측의 시각 한계·실행 중 저장 행 수를 검사한다.
- 실제 외부 계정 조회·발견 자격증명 사용·열람 이력 수집은 실행하지 않았다. 과거 대규모 실계정 검증 결과로 해석하지 않는다.
