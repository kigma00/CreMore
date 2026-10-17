# AWS 기계 신원

사람의 브라우저 로그인과 별도로, AWS 수집 프로세스가 회사 IdP에서 토큰을 받아 IAM 역할을 맡는 방식이다. 연동 서비스 화면의 **기계 신원 (회사 IdP)**에서 관리한다.

관리자는 IdP의 client credentials 앱 정보(HTTPS 토큰 URL, 클라이언트 ID, 클라이언트 비밀)와 이 IdP를 신뢰하는 AWS IAM 역할 ARN을 입력한다. 비밀은 봉인 저장하고 다시 표시하지 않는다. API와 워커는 각자 토큰을 갱신하며 `AWS_WEB_IDENTITY_TOKEN_FILE`을 통해 AWS SDK에 제공한다. 첫 토큰을 받지 못해도 호스트의 다른 AWS 신원으로 대체하지 않는다.

AWS 역할의 신뢰 정책은 IdP의 OIDC 발급자와 `aud`·`sub` 조건을 제한해야 한다. 설정 화면의 **토큰 받아 보기**와 **명령 복사**로 클레임과 IAM 설정 명령을 확인할 수 있다. AWS 연동의 연결 확인 단계에서 실제 사용할 신원을 승인한다.

Helm에서는 `serviceAccounts.api.annotations` 및 `serviceAccounts.worker.annotations`의 EKS 역할 ARN 또는 EKS Pod Identity를 사용할 수 있다. Docker Compose에서는 EC2 인스턴스 프로필이나 `deploy/compose/identity/refresher.yml`과 `deploy/compose/identity/aws-web-identity.yml`을 함께 사용할 수 있다.

현재 기계 신원 대상은 AWS 하나다. 기존 DB에 남아 있는 다른 대상 설정은 토큰 갱신과 연결 대상으로 사용하지 않는다.
