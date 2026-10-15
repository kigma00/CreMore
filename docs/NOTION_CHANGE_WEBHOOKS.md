# Notion 페이지 변경 알림

페이지 수정·생성·이동·삭제 알림으로 승인된 범위의 스캔을 깨운다. Enterprise 감사 로그 수집과
별개다. 일반 콘텐츠 연결에서 Notion이 제공하는 webhook을 이용하며, 사용 중인 연결 유형과
읽기 권한에서 webhook 설정이 가능해야 한다. 없는 권한이나 선택하지 않은 페이지를 승인하지 않는다.

## 운영자 설정

1. 기존 콘텐츠 온보딩에서 페이지/하위 페이지를 선택하고 검사 대상의 ‘변경되면 검사’를 켠다.
2. 설정 → 검사 트리거 → Notion 변경 알림에서 해당 승인 범위를 선택하고 수신 주소를 만든다.
3. Notion 연결 관리 화면의 Webhooks에 HTTPS 주소를 등록하고 필요한 page/data source 이벤트를 선택한다.
4. CreMore에서 ‘검증 토큰 복사’를 누르고 Notion의 Verify subscription에 붙여넣는다. 토큰을 채팅·로그에 적지 않는다.
5. 선택한 페이지를 수정해 서명된 첫 알림을 보낸다. CreMore에서 구독 검증 완료를 확인하고 활성화한다.
   생성부터 30분 안에 끝내지 못하면 연결을 해제하고 새 주소를 만든다.

페이지 삭제나 새 페이지 이벤트가 와도 범위를 자동 확장하지 않는다. 고정 선택한 페이지 및 승인된
하위 페이지에 해당하는 알림만 처리한다. 이벤트 본문의 변경 내용·사람·페이지 제목은 저장하지 않는다.
읽기 권한을 잃어 API가 실패하면 삭제 확인으로 간주하지 않는다. 주기적 전체 검사를 함께 쓰면
공급자 알림의 누락을 보완할 수 있다.

## 배포와 인증

공개 수신 경로는 `POST /api/v1/hooks/notion/{UUID}` 하나다. Next 경유 시 원래 바이트를 보존하고
쿠키·사용자 bearer·API 관리자 토큰을 붙이지 않는다. API는 64 KiB 상한, HMAC-SHA256
`X-Notion-Signature`, 구독/워크스페이스/앱 일치, 시각, 현재 승인과 범위를 검사한다.
최초 unsigned 검증 토큰은 임시 봉인 후보일 뿐 작업을 실행하지 않는다. Notion 포털 검증과
서명된 알림을 관리자가 확인한 뒤에만 활성화된다. 설정 변경·해제는 admin이며 감사 이력을 남긴다.

표준 공개 Compose·격리 Compose·Helm oauth2-proxy에 이 POST 경로만 로그인 예외로 넣었다.
일반 API·설정 경로는 로그인 예외가 아니다. 별도 WAF/Cloudflare Access를 운영하면 같은 정확한
경로와 POST 메서드만 기계 수신을 허용해야 한다. TLS·요청 시간/속도 제한을 운영 경계에서 적용한다.
격리 배포도 기존 gateway→OIDC proxy→web→API 네트워크를 유지하며 API 포트를 외부에 열지 않는다.
검증 토큰은 API의 `CONTROL_SEALING_KEY`로 봉인한다. 이 키는 수집기 연결 비밀용 private key와 다르다.

이벤트 ID별 receipt와 작업을 같은 DB 트랜잭션에 저장한 뒤 성공을 반환한다. 응답이 유실돼 같은
알림이 재전송되어도 같은 작업을 다시 만들지 않는다. 작업 저장 실패에는 성공 ACK를 주지 않는다.
새 이벤트가 실행 중 도착하면 대기하며 동일 연결을 동시에 쓰지 않는다. 연결 해제는 수신 설정만
없애고 탐지·감사·작업 이력은 유지한다.

## 공식 근거와 검증 범위

2026-10-06 확인한 [webhook 설정](https://developers.notion.com/reference/webhooks),
[이벤트와 전달](https://developers.notion.com/reference/webhooks-events-delivery),
[Markdown 본문](https://developers.notion.com/reference/retrieve-page-markdown),
[요청 제한](https://developers.notion.com/reference/request-limits)을 기준으로 구현했다.
메모리·SQLite·격리 PostgreSQL, 정확 바이트 Next 전달 및 합성 이벤트로 검사한다.
실제 Notion 구독 활성화·회사 방화벽·외부 TLS까지 이 테스트가 증명하지는 않는다.
