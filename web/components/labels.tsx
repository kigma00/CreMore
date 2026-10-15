/* The words for the codes the API returns.
 *
 * A status, a reason or a failure arrives as a stable code so the API stays a
 * contract; these turn one into a sentence a person reads, in both languages.
 * They live together because the same code appears on several screens and has
 * to read the same way on each -- and because keeping them out of the screens
 * is what lets a screen be moved into its own module.
 *
 * Every function here is pure: given a code and a locale it returns text. None
 * fetches, decides or stores. An unknown code falls back to itself rather than
 * to "Unknown", so an untranslated value is visible as the thing it is.
 */

import { type Locale, enumLabel, localize } from "@/components/locale";

// A credential type a custom rule produces: CUSTOM_RULE_ and the SHA-256 of the rule's name (cremore/detection/custom.py).
const customRuleType = (value: unknown) => typeof value === "string" && /^CUSTOM_RULE_[0-9A-F]{64}$/.test(value);

const auditActions: Record<string, [string, string, string, string]> = {
  RESPONSE_REVIEW_STARTED: ["Review started", "검토 시작", "An analyst explicitly started review.", "담당자가 명시적으로 검토를 시작했습니다."],
  RESPONSE_REPORT_RECORDED: ["Action report recorded", "조치 보고 기록", "A versioned action report was recorded without authorizing provider writes.", "조치 보고를 버전별로 기록했습니다. 공급자 조치 실행 승인은 아닙니다."],
  RESPONSE_EVIDENCE_UPDATED: ["Remediation evidence updated", "조치 검증 근거 갱신", "Saved scan, issuer and vault evidence was reevaluated.", "저장된 스캔·발급자·금고 근거를 다시 평가했습니다."],
  RESPONSE_COMPLETED: ["Remediation completed", "조치 완료", "The response cycle satisfied all applicable completion checks.", "해당 대응 회차의 필수 완료 근거를 모두 확인했습니다."],
  RESPONSE_ASSIGNED: ["Responder assigned", "대응 담당자 지정", "A current IdP person was explicitly assigned as responder.", "현재 IdP 사람을 대응 담당자로 명시적으로 지정했습니다."],
  RESPONSE_UNASSIGNED: ["Responder unassigned", "대응 담당자 지정 해제", "The explicit responder assignment was cleared.", "명시적 대응 담당자 지정을 해제했습니다."],
  RESPONSE_RESPONSIBILITY_CHANGED: ["Responsibility rule changed", "책임 규칙 변경", "An explicit location or account responsibility rule changed.", "위치 또는 발급 계정의 명시적 책임 규칙을 변경했습니다."],
  RESPONSE_REQUESTED: ["Cleanup requested", "노출 제거 대응 요청", "A responder was asked to clean up exposed locations.", "담당자에게 노출 위치 제거를 요청했습니다."],
  RESPONSE_TICKET_OPENED: ["External response ticket opened", "외부 대응 티켓 생성", "The external ticket system confirmed creation of the request.", "외부 티켓 시스템이 요청 생성을 확인했습니다."],
  RESPONSE_LINK_SENT: ["Response link sent", "대응 링크 발송", "The CreMore link went out to the responder: by Slack DM or mail, in a team channel, or both (the note names the targets).", "담당자에게 CreMore 링크를 보냈습니다. Slack DM·메일, 팀 채널 또는 둘 다로 보냈으며 메모에 보낸 곳이 있습니다."],
  RESPONSE_NOT_SENT: ["Response request not sent", "대응 요청 발송 실패", "The request did not go out, so its link was voided; a new request can be sent.", "요청이 나가지 않아 링크를 무효로 했습니다. 새 요청을 보낼 수 있습니다."],
  RESPONSE_LATE_TICKET_OPENED: ["Delayed ticket creation confirmed", "지연된 티켓 생성 확인", "A delayed result confirmed that the external ticket was created.", "늦게 도착한 응답으로 외부 티켓 생성을 확인했습니다."],
  RESPONSE_SEND_UNKNOWN: ["Delivery result uncertain", "대응 요청 발송 결과 불확실", "The send result is uncertain; duplicate sending is blocked.", "발송 결과가 불확실하여 중복 발송을 차단했습니다."],
  RESPONSE_TICKET_CHECKED: ["Response ticket checked", "대응 티켓 회신 확인", "CreMore checked the external request's response.", "외부 대응 요청의 회신 상태를 확인했습니다."],
  RESPONSE_ANSWER_REFUSED: ["Responder not confirmed", "지정한 담당자 회신 확인 실패", "The answer was not accepted as the designated responder's.", "지정한 담당자의 회신으로 인정하지 않았습니다."],
  RESPONSE_CLEANUP_DECLARED: ["Cleanup reported; awaiting scan", "제거 완료 회신 · 재검사 대기", "The responder reports cleanup. A later scan must verify removal.", "담당자가 제거 완료를 회신했습니다. 이후 검사로 제거를 확인해야 합니다."],
  RESPONSE_DECLINED: ["Response request declined", "대응 요청 거절", "The responder declined the cleanup request.", "담당자가 노출 제거 요청을 거절했습니다."],
  RESPONSE_SEND_RELEASED: ["Admin cleared uncertain delivery", "관리자 확인 후 재요청 허용", "An admin recorded that no external duplicate request remains pending. This is an operator assertion.", "관리자가 외부에 진행 중인 중복 요청이 없다고 확인했습니다. 관리자 확인 진술입니다."],
  RESPONSE_REMOVAL_VERIFIED: ["Removal verified by scan", "검사로 노출 제거 확인", "An authoritative scan confirmed removal at all tracked locations.", "완전한 검사로 추적 중인 모든 위치의 제거를 확인했습니다."],
  RESPONSE_REAPPEARED: ["Exposure reappeared", "노출 재발견", "A scan found the same credential again after confirmed removal.", "제거 확인 후 같은 자격증명 노출을 다시 발견했습니다."],
  RESPONSE_STILL_EXPOSED: ["Exposure remains", "노출 잔존 확인", "The verification scan still found exposed locations; more action is needed.", "확인 검사에서 노출이 남아 있어 추가 대응이 필요합니다."],
  AUTH_SESSION_OBSERVED: ["Sign-in session observed", "로그인 세션 확인", "CreMore first observed this verified IdP session. A token refresh may be a new observation when the IdP supplies no session evidence.", "CreMore가 검증된 IdP 세션의 접근을 처음 확인했습니다. IdP가 세션 근거를 주지 않으면 토큰 갱신도 새 관측으로 남을 수 있습니다."],
  API_REQUEST_STARTED: ["Request started", "요청 시작", "A verified user began this request. A missing result means its outcome is unknown.", "검증된 사용자의 요청을 실행 전에 기록했습니다. 같은 요청 ID의 결과가 없으면 완료 여부는 미확인입니다."],
  API_REQUEST_SUCCEEDED: ["Request succeeded", "요청 성공", "The API returned a successful HTTP response. Background work has its own result records.", "API가 성공 HTTP 응답을 반환했습니다. 백그라운드 작업의 최종 결과는 별도 기록으로 확인합니다."],
  API_REQUEST_ACCEPTED: ["Request accepted", "요청 접수", "The API accepted background work (HTTP 202); this is not proof that the work finished.", "API가 백그라운드 작업을 접수했습니다(HTTP 202). 작업 완료를 의미하지 않습니다."],
  API_REQUEST_DENIED: ["Access denied", "접근 거절", "Authentication or authorization refused the request. Unverified callers are not attributed to a user.", "인증 또는 권한 검사에서 거절했습니다. 검증되지 않은 요청자는 사용자로 특정하지 않습니다."],
  API_REQUEST_FAILED: ["Request failed", "요청 실패", "The API rejected an invalid request or returned an error. Request bodies and exception contents are not retained.", "잘못된 요청이나 처리 오류로 실패했습니다. 요청 본문과 예외 원문은 저장하지 않습니다."],
  ROLLUP_UPDATED: ["Finding summary updated", "탐지 결과 집계 갱신", "The scanner recalculated the representative exposure, severity and workflow status from the recorded exposure locations.", "스캐너가 기록된 노출 위치를 바탕으로 대표 노출 위치·심각도·처리 상태를 다시 계산한 기록입니다."],
  ACKNOWLEDGED: ["Finding acknowledged", "탐지 결과 확인", "The finding was marked as acknowledged.", "탐지 결과를 확인한 상태로 변경했습니다."],
  RESOLVED: ["Finding resolved", "탐지 결과 해결 처리", "The finding was marked as resolved with the recorded resolution.", "기록된 해결 근거에 따라 탐지 결과를 해결 처리했습니다."],
  REOPENED: ["Finding reopened", "탐지 결과 다시 열기", "The finding was reopened for review.", "탐지 결과를 다시 검토할 수 있도록 열린 상태로 변경했습니다."],
  FALSE_POSITIVE: ["Marked as false positive", "오탐 처리", "The finding was marked as a false positive.", "탐지 결과를 오탐으로 분류했습니다."],
  AUTO_FALSE_POSITIVE: ["Automatically marked as false positive", "자동 오탐 처리", "The finding matched a saved false-positive policy and was automatically classified.", "저장된 오탐 판정 기준에 따라 탐지 결과를 자동으로 오탐 분류했습니다."],
  IGNORED: ["Finding excluded", "탐지 결과 제외", "The finding was excluded from active review with the recorded reason.", "기록된 사유로 탐지 결과를 검토 대상에서 제외했습니다."],
  ASSIGNED: ["Finding assignee changed", "탐지 담당자 변경", "The finding's assignee was changed. The saved note records the assignment.", "탐지 결과의 담당자를 변경했습니다. 지정 내용은 아래 사유·메모에서 확인하세요."],
  RISK_REEVALUATED: ["Risk reevaluated", "위험도 재평가", "Risk was reevaluated using stored detection evidence.", "저장된 탐지 근거를 사용해 위험도를 재평가했습니다."],
  TICKET_CREATED: ["Response ticket created", "대응 티켓 생성", "A response ticket was created for this finding.", "이 탐지 결과에 대한 대응 티켓을 생성했습니다."],
  TICKET_UPDATED: ["Response ticket updated", "대응 티켓 변경", "The linked response ticket was updated.", "연결된 대응 티켓의 내용을 변경했습니다."],
  TICKET_APPROVED: ["Response ticket approved", "대응 티켓 승인", "An administrator approved the recorded version of the response ticket.", "관리자가 기록된 버전의 대응 티켓을 승인했습니다."],
  OWNERSHIP_REVIEW_UPDATED: ["Ownership review updated", "소유자 조사 변경", "The ownership review record was updated.", "자격증명 소유자 조사 기록을 변경했습니다."],
  CONNECTION_STOPPED: ["Connection stopped", "연결 사용 중단", "CreMore stopped using this connection. This does not revoke the credential at its provider.", "CreMore에서 이 연결의 사용을 중단했습니다. 공급자 측 자격증명 자체가 폐기되는 것은 아닙니다."],
  // Every other event the backend writes (the list of 2026-09-30), by area.
  AUTO_FALSE_POSITIVE_REOPENED: ["Auto-triage reversed", "자동 오탐 처리 되돌림", "A finding the false-positive policy had closed was opened again: its exposures no longer qualify.", "오탐 판정 기준으로 닫혔던 탐지 결과를 다시 열었습니다. 노출 위치가 기준에 더 맞지 않습니다."],
  COMMENT: ["Comment", "코멘트", "A comment was added to the finding.", "탐지 결과에 코멘트를 남겼습니다."],
  TAGS_CHANGED: ["Tags changed", "태그 변경", "Tags were added to or removed from the finding.", "탐지 결과의 태그를 더하거나 뺐습니다."],
  STAGE_CHANGED: ["Stage changed", "처리 단계 변경", "The review or remediation stage of the finding was set.", "탐지 결과의 검토·조치 단계를 정했습니다."],
  REMEDIATION_STEP: ["Remediation step changed", "조치 단계 변경", "A remediation step's status or comment changed.", "조치 단계의 상태나 코멘트를 바꿨습니다."],
  OWNER_CONTACTED: ["Owner contacted", "담당자에게 연락", "Someone recorded that the owner was asked; CreMore sent nothing itself.", "담당자에게 연락했다고 기록했습니다. CreMore가 직접 보낸 것은 아닙니다."],
  OWNER_CONTACT_SENT: ["Sent to the owner", "담당자에게 보냄", "CreMore sent the owner a message; the note has the channel and digests of the recipients and text.", "CreMore가 담당자에게 메시지를 보냈습니다. 메모에 채널과 받는 곳·내용의 digest가 있습니다."],
  OWNER_CONTACT_FAILED: ["Owner contact not sent", "담당자 연락 발송 실패", "The message to the owner did not go out.", "담당자에게 보낼 메시지가 나가지 않았습니다."],
  CONTACT_DELIVERY_SAVED: ["Contact delivery saved", "연락 발송 설정 저장", "An Admin saved the mail relay and Slack delivery setup.", "관리자가 메일 서버·Slack 발송 설정을 저장했습니다."],
  RESPONSE_CHANNELS_SAVED: ["Response channels saved", "대응 알림 채널 저장", "An Admin saved the Slack channels response requests may also be posted in; the note has the channel ids and the public ones allowed.", "관리자가 대응 요청을 함께 올릴 Slack 채널을 저장했습니다. 메모에 채널 ID와 허용한 공개 채널이 있습니다."],
  CONTACT_DELIVERY_TESTED: ["Contact delivery tested", "연락 발송 시험", "An Admin sent a test message; the note has how many were delivered.", "관리자가 시험 메시지를 보냈습니다. 메모에 전달된 수가 있습니다."],
  DETECTION_ALERTS_TESTED: ["Slack detection alerts tested", "Slack 탐지 알림 시험", "An Admin sent a test message to the alert channel; the note says it was delivered or gives the failure code.", "관리자가 알림 채널로 시험 메시지를 보냈습니다. 메모에 전달 여부나 실패 코드가 있습니다."],
  TICKET_SYSTEM_SAVED: ["Ticket system saved", "티켓 시스템 설정 저장", "The company ticket system was set up or turned off.", "회사 티켓 시스템을 설정하거나 껐습니다."],
  TICKET_SYSTEM_CHECKED: ["Ticket system checked", "티켓 시스템 확인", "An Admin tried signing in to the ticket system.", "관리자가 티켓 시스템 로그인을 시험했습니다."],
  MANAGEMENT_ACTION_REQUESTED: ["Management action requested", "관리 조치 요청", "A management action was requested for this finding.", "이 탐지 결과에 관리 조치를 요청했습니다."],
  MANAGEMENT_ACTION_CONFIRMED: ["Management action confirmed", "관리 조치 확인", "A pending management action was confirmed.", "대기 중인 관리 조치를 확인했습니다."],
  MANAGEMENT_ACTION_REFUSED: ["Management action refused", "관리 조치 확인 거절", "A confirmation was refused: another operator must confirm, or it was no longer pending.", "확인이 거절됐습니다. 다른 담당자가 확인해야 하거나 이미 대기 상태가 아닙니다."],
  ROTATION_LEGACY_WRITE_REFUSED: ["Legacy rotation refused", "이전 키 교체 실행 거절", "The old rotation path is read-only. Use an approved action plan after reconciling any unfinished job.", "이전 키 교체 경로는 읽기 전용입니다. 미완료 작업의 상태를 대조한 뒤 승인된 조치 계획을 사용해야 합니다."],
  ACTION_PLAN_REQUESTED: ["Action plan requested", "조치 계획 요청", "A key action plan was created and waits for approval.", "키 조치 계획을 만들었고 승인을 기다립니다."],
  ACTION_PLAN_APPROVED: ["Action plan approved", "조치 계획 승인", "The action plan was approved.", "조치 계획을 승인했습니다."],
  ACTION_PLAN_CANCELLED: ["Action plan cancelled", "조치 계획 취소", "The action plan was cancelled.", "조치 계획을 취소했습니다."],
  ACTION_PLAN_QUEUED: ["Action plan queued", "조치 계획 실행 대기", "The approved plan was handed to the worker.", "승인된 계획을 작업자에게 넘겼습니다."],
  ACTION_PLAN_EXECUTION_STARTED: ["Action plan started", "조치 계획 실행 시작", "The change at the provider started.", "공급자에서 변경을 시작했습니다."],
  ACTION_PLAN_VERIFIED: ["Action plan verified", "조치 결과 확인", "The provider showed the outcome.", "공급자에서 결과를 확인했습니다."],
  ACTION_PLAN_FAILED: ["Action plan failed", "조치 계획 실패", "The plan failed; the note has the code.", "계획이 실패했습니다. 메모에 코드가 있습니다."],
  ACTION_PLAN_OUTCOME_UNKNOWN: ["Action outcome unknown", "조치 결과 모름", "The change may have happened at the provider, but it was not confirmed.", "공급자에서 변경이 일어났을 수 있지만 확인되지 않았습니다."],
  ACTION_PLAN_RECHECKED: ["Action plan rechecked", "조치 상태 다시 확인", "A recheck ran and the plan's state did not change.", "다시 확인했고 계획 상태는 그대로입니다."],
  ACTION_PLAN_RECHECK_REQUESTED: ["Action recheck requested", "조치 상태 확인 요청", "A recheck of the plan was queued to the worker.", "계획 상태 확인을 작업자에게 요청했습니다."],
  ACTION_PLAN_REFUSED: ["Action refused", "조치 거절", "An attempt on a plan was refused; the note has the step and the code.", "계획에 대한 시도가 거절됐습니다. 메모에 단계와 코드가 있습니다."],
  ACTION_PLAN_EMERGENCY: ["Emergency containment", "긴급 차단", "An Admin contained a publicly exposed key before its owner approved.", "관리자가 공개 노출된 키를 소유자 승인 전에 차단했습니다."],
  OWNER_APPROVAL_REQUESTED: ["Owner approval asked", "소유자 승인 요청", "The key's owner was asked to approve the plan.", "키 소유자에게 계획 승인을 요청했습니다."],
  OWNER_APPROVAL_NOT_SENT: ["Owner approval not sent", "소유자 승인 요청 실패", "The request to the owner did not go out.", "소유자에게 보낼 요청이 나가지 않았습니다."],
  OWNER_APPROVAL_TICKET_OPENED: ["Owner approval ticket opened", "소유자 승인 티켓 생성", "A ticket and its approval were opened in the ticket system.", "티켓 시스템에 티켓과 승인 요청을 열었습니다."],
  OWNER_APPROVAL_TICKET_REFUSED: ["Owner approval ticket refused", "소유자 승인 응답 거부", "An answer in the ticket system was not accepted: someone else answered, or not independently.", "티켓 시스템의 응답을 받아들이지 않았습니다. 다른 사람이 답했거나 독립된 응답이 아닙니다."],
  OWNER_APPROVAL_GRANTED: ["Owner approved", "소유자 승인", "The key's owner approved the plan.", "키 소유자가 계획을 승인했습니다."],
  OWNER_APPROVAL_DECLINED: ["Owner declined", "소유자 거절", "The key's owner declined the plan.", "키 소유자가 계획을 거절했습니다."],
  OWNER_APPROVAL_RECORDED: ["Owner decision recorded", "소유자 결정 기록", "The local operator recorded a decision the owner gave elsewhere, with evidence.", "로컬 운영자가 소유자가 다른 곳에서 한 결정을 근거와 함께 기록했습니다."],
  OWNER_NOTIFIED_AFTER: ["Owner told afterwards", "소유자에게 사후 안내", "The owner was told after an emergency containment.", "긴급 차단 뒤 소유자에게 알렸습니다."],
  OWNER_NOTICE_NOT_SENT: ["Owner notice not sent", "사후 안내 실패", "The notice after an emergency containment did not go out.", "긴급 차단 뒤 안내가 나가지 않았습니다."],
  OWNER_APPROVAL_POLICY_CHANGED: ["Owner approval policy changed", "소유자 승인 정책 변경", "An Admin turned the owner's approval requirement on or off.", "관리자가 소유자 승인 필요 여부를 바꿨습니다."],
  PROVIDER_CONNECTION_CREATED: ["Integration created", "연동 생성", "A provider integration was created.", "공급자 연동을 만들었습니다."],
  PROVIDER_CONNECTION_CHECK_REQUESTED: ["Access check requested", "권한 확인 요청", "The integration's access check was queued.", "연동의 권한 확인을 요청했습니다."],
  PROVIDER_CONNECTION_ACTIVATED: ["Integration started", "연동 시작", "The integration's features started and their records were made.", "연동 기능을 시작하고 그 기록을 만들었습니다."],
  PROVIDER_CONNECTION_PLAN_CHANGED: ["Integration plan changed", "연동 수집 설정 변경", "What a running feature collects was changed.", "시작한 기능의 수집 설정을 바꿨습니다."],
  PROVIDER_CONNECTION_CREDENTIAL_CHANGED: ["Integration credential changed", "연동 자격증명 변경", "The integration's credential was replaced.", "연동의 자격증명을 바꿨습니다."],
  PROVIDER_CONNECTION_ENABLED: ["Integration resumed", "연동 다시 시작", "The integration and its records started again.", "연동과 그 기록을 다시 시작했습니다."],
  PROVIDER_CONNECTION_DISABLED: ["Integration stopped", "연동 중지", "The integration and its records stopped.", "연동과 그 기록을 멈췄습니다."],
  PROVIDER_CONNECTION_DELETED: ["Integration deleted", "연동 삭제", "The integration was deleted.", "연동을 삭제했습니다."],
  PROVIDER_CONNECTION_CREDENTIAL_RENEWED: ["Credential renewed", "자격증명 교체", "The worker renewed the integration's credential.", "작업자가 연동의 자격증명을 교체했습니다."],
  PROVIDER_CONNECTION_CREDENTIAL_RENEWAL_FAILED: ["Credential renewal failed", "자격증명 교체 실패", "A renewal or retirement attempt failed; the note has the code.", "교체나 폐기 시도가 실패했습니다. 메모에 코드가 있습니다."],
  PROVIDER_CONNECTION_CREDENTIAL_RETIRED: ["Old credential retired", "이전 자격증명 폐기", "The worker retired the credential a renewal replaced.", "작업자가 교체된 이전 자격증명을 폐기했습니다."],
  PROVIDER_CONNECTION_RECORD_TAKEN_OVER: ["Record taken over", "기록 인계", "The integration took over a record a stopped integration owned.", "멈춘 연동의 기록을 이 연동이 넘겨받았습니다."],
  PROVIDER_CONNECTION_RECORD_ADOPTED: ["Discovered record adopted", "발견한 기록 편입", "A discovered record, such as an AWS account, was taken into the integration.", "AWS 계정 같은 발견한 기록을 연동에 넣었습니다."],
  GITHUB_ENTERPRISE_INSTALL_REQUESTED: ["Organizations queued for install", "조직 설치 요청", "Organizations were queued for the GitHub App install.", "GitHub App을 설치할 조직을 대기열에 넣었습니다."],
  GITHUB_ENTERPRISE_INSTALL_CANCELLED: ["Organization installs cancelled", "조직 설치 취소", "Organizations were taken off the install queue and left out.", "조직을 설치 대기열에서 빼고 제외했습니다."],
  GITHUB_ENTERPRISE_AUTO_INSTALL_ON: ["Auto-install turned on", "자동 설치 켬", "New organizations of the enterprise are installed on automatically.", "엔터프라이즈의 새 조직에 자동으로 설치합니다."],
  GITHUB_ENTERPRISE_AUTO_INSTALL_OFF: ["Auto-install turned off", "자동 설치 끔", "New organizations are no longer installed on automatically.", "새 조직에 더는 자동으로 설치하지 않습니다."],
  GITHUB_ENTERPRISE_AUTO_QUEUED: ["New organizations queued", "새 조직 자동 대기", "Auto-install queued organizations seen for the first time.", "자동 설치가 처음 본 조직을 대기열에 넣었습니다."],
  GITHUB_ENTERPRISE_ORG_INSTALLED: ["App installed on an organization", "조직에 앱 설치", "The worker installed the GitHub App on an organization.", "작업자가 조직에 GitHub App을 설치했습니다."],
  GITHUB_ENTERPRISE_ORG_CONNECTED: ["Organization integration made", "조직 연동 생성", "The worker made the organization's integration.", "작업자가 조직의 연동을 만들었습니다."],
  GITHUB_ENTERPRISE_ORG_ACTIVATED: ["Organization integration started", "조직 연동 시작", "The organization's integration started once every permission was granted.", "모든 권한이 확인된 뒤 조직 연동을 시작했습니다."],
  GITHUB_ENTERPRISE_ORG_INSTALL_FAILED: ["Organization install failed", "조직 설치 실패", "Installing on or connecting an organization failed.", "조직 설치나 연결이 실패했습니다."],
  GITHUB_ENTERPRISE_KEY_PROPAGATED: ["App key passed on", "앱 키 전달", "The App's new key was copied into the organization integrations it made.", "앱의 새 키를 만든 조직 연동들에 옮겼습니다."],
  GITHUB_ENTERPRISE_STOPPED_WITH_SOURCE: ["Stopped with its source", "원본과 함께 중지", "The source integration stopped, so its install queue and auto-install stopped.", "원본 연동이 멈춰 설치 대기열과 자동 설치도 멈췄습니다."],
  GITHUB_APP_MANIFEST_STARTED: ["GitHub App setup started", "GitHub App 만들기 시작", "Making a GitHub App from its manifest started.", "매니페스트로 GitHub App 만들기를 시작했습니다."],
  GITHUB_APP_MANIFEST_CREATED: ["GitHub App created", "GitHub App 생성", "GitHub created the App.", "GitHub가 앱을 만들었습니다."],
  GITHUB_APP_MANIFEST_COMPLETED: ["GitHub App setup completed", "GitHub App 연동 완료", "The App was installed and its integration made or updated.", "앱을 설치하고 연동을 만들거나 바꿨습니다."],
  GCP_OAUTH_CLIENT_SAVED: ["Google OAuth client saved", "Google OAuth 앱 저장", "An Admin saved the Google OAuth client.", "관리자가 Google OAuth 앱을 저장했습니다."],
  GCP_OAUTH_STARTED: ["Google sign-in started", "Google 로그인 시작", "A Google sign-in for an integration started.", "연동의 Google 로그인을 시작했습니다."],
  GCP_OAUTH_AUTHORIZED: ["Google sign-in authorized", "Google 로그인 승인", "Google authorized the sign-in.", "Google이 로그인을 승인했습니다."],
  GCP_OAUTH_CONNECTED: ["Google sign-in attached", "Google 로그인 연결", "The sign-in was attached to its integration and the check asked again.", "로그인을 연동에 연결하고 권한 확인을 다시 요청했습니다."],
  METADATA_CONNECTION_CREATED: ["Collection created", "수집 생성", "An integration made an inventory or vault collection.", "연동이 발급 목록·금고 수집을 만들었습니다."],
  COVERAGE_CONNECTION_CREATED: ["Collection created", "수집 생성", "An integration made a vault or inventory collection.", "연동이 금고·발급 목록 수집을 만들었습니다."],
  COLLECTION_PLAN_CHANGED: ["Collection plan changed", "수집 설정 변경", "A plan change was applied to a collection.", "수집에 바뀐 설정을 적용했습니다."],
  COLLECTION_TURNED_OFF_BY_PLAN: ["Collection turned off", "수집 끔", "A collection the new plan no longer describes was turned off, not deleted.", "새 설정에 없는 수집을 지우지 않고 껐습니다."],
  METADATA_CONNECTION_CHANGED: ["Collection changed", "수집 변경", "A collection's settings, switch or token changed.", "수집의 설정·켜기·토큰을 바꿨습니다."],
  METADATA_COLLECTION_REQUESTED: ["Collection run requested", "수집 실행 요청", "A collection run was queued by hand.", "수집 실행을 직접 요청했습니다."],
  METADATA_COLLECTION_PAUSED: ["Collection paused", "수집 일시 정지", "A running collection was paused.", "진행 중인 수집을 잠시 멈췄습니다."],
  METADATA_COLLECTION_RESUMED: ["Collection resumed", "수집 재개", "A paused collection went on.", "멈춘 수집을 이어서 합니다."],
  METADATA_COLLECTION_STOP_REQUESTED: ["Collection stop requested", "수집 중지 요청", "Stopping a collection run was requested.", "수집 실행 중지를 요청했습니다."],
  METADATA_COLLECTION_SCHEDULED: ["Scheduled collection queued", "예약 수집 실행", "The scheduler queued a collection run.", "예약에 따라 수집 실행을 넣었습니다."],
  GCP_VALUES_READ: ["Stored GCP values read", "저장된 GCP 값 조회", "An Admin read stored Google Cloud secret values.", "관리자가 저장된 Google Cloud 비밀값을 읽었습니다."],
  FORWARDED_TO_SIEM: ["Sent to the SIEM", "SIEM으로 보냄", "The finding was sent to the SIEM and webhook destinations.", "탐지 결과를 SIEM·웹훅 목적지로 보냈습니다."],
  SIEM_TEST_EVENT_QUEUED: ["SIEM test event sent", "SIEM 테스트 이벤트", "An Admin queued a test event for every destination.", "관리자가 모든 목적지에 테스트 이벤트를 보냈습니다."],
  SIEM_HELD_RELEASED: ["Held SIEM deliveries released", "보류한 SIEM 전송 재시도", "An Admin gave a destination's held deliveries another round.", "관리자가 목적지의 보류한 전송을 다시 보내게 했습니다."],
  NOTION_WEBHOOK_CREATED: ["Notion receiving URL created", "Notion 알림 주소 생성", "An Admin created a receiving URL for an approved scan scope.", "관리자가 승인된 검사 범위의 알림 주소를 만들었습니다."],
  NOTION_WEBHOOK_CONFIRMED: ["Notion change notifications enabled", "Notion 변경 알림 활성화", "An Admin confirmed the verified subscription and its signed event.", "관리자가 검증된 구독과 서명된 확인 알림을 확인했습니다."],
  NOTION_WEBHOOK_DISABLED: ["Notion change notifications disabled", "Notion 변경 알림 해제", "An Admin removed the notification binding; scan history is retained.", "관리자가 알림 연결을 해제했습니다. 검사 이력은 유지됩니다."],
  DOMAIN_ADDED: ["Domain added", "도메인 추가", "A company domain was added and waits for its record.", "회사 도메인을 추가했고 레코드 확인을 기다립니다."],
  DOMAIN_INTERNAL_CHANGED: ["Internal sites changed", "사내 주소 허용 변경", "Whether the exposure scan reaches the domain's internal sites was changed.", "외부 노출 검사가 이 도메인의 사내 사이트를 읽을지 바꿨습니다."],
  DOMAIN_CHALLENGE_RENEWED: ["Domain value renewed", "도메인 값 재발급", "A new value was made; the domain waits for its new record.", "새 값을 만들었고 도메인은 새 레코드를 기다립니다."],
  DOMAIN_REMOVED: ["Domain removed", "도메인 삭제", "The domain was removed.", "도메인을 지웠습니다."],
  DOMAIN_VERIFIED: ["Domain verified", "도메인 확인", "The DNS answered with this installation's record.", "DNS에서 이 설치의 레코드를 확인했습니다."],
  DOMAIN_VERIFICATION_FAILED: ["Domain not verified", "도메인 확인 실패", "The DNS check did not verify the domain; the note has the result.", "DNS 확인에서 도메인을 확인하지 못했습니다. 메모에 결과가 있습니다."],
  DOMAIN_LAPSED: ["Domain verification lapsed", "도메인 확인 끊김", "A verified domain lost its record; a new value was made and internal sites turned off.", "확인된 도메인의 레코드가 없어졌습니다. 새 값을 만들고 사내 주소 허용을 껐습니다."],
  MACHINE_IDENTITY_CHANGED: ["Machine identity changed", "기계 신원 변경", "An Admin saved the company IdP machine identity.", "관리자가 회사 IdP 기계 신원을 저장했습니다."],
  LEAVER_LINK_CONFIRMED: ["Account link confirmed", "계정 연결 확인", "An Admin confirmed an account belongs to a person.", "관리자가 계정과 사람의 연결을 확인했습니다."],
  LEAVER_LINK_REJECTED: ["Account link rejected", "계정 연결 거절", "An Admin rejected an account-to-person link.", "관리자가 계정과 사람의 연결을 거절했습니다."],
  LEAVER_LINK_CLEARED: ["Account link decision cleared", "계정 연결 결정 지움", "An Admin removed their decision about a link.", "관리자가 연결에 대한 결정을 지웠습니다."],
  LEAVER_EVALUATED: ["Departed-owner check run", "퇴사자 점검 실행", "An Admin ran the departed-owner check.", "관리자가 퇴사자 점검을 실행했습니다."],
  AWS_SSO_LOGIN_STARTED: ["AWS sign-in started", "AWS 로그인 시작", "An Admin started CreMore's AWS Identity Center sign-in.", "관리자가 CreMore의 AWS Identity Center 로그인을 시작했습니다."],
  AWS_SSO_LOGIN_DONE: ["AWS sign-in completed", "AWS 로그인 완료", "The sign-in was approved; the note names the identity CreMore now runs as.", "로그인이 승인됐습니다. 메모에 CreMore가 이제 쓰는 신원이 있습니다."],
  AWS_SSO_LOGIN_EXPIRED: ["AWS sign-in expired", "AWS 로그인 만료", "The code expired before anyone approved it.", "승인 전에 코드가 만료됐습니다."],
  AWS_SSO_LOGIN_DENIED: ["AWS sign-in denied", "AWS 로그인 거절", "The sign-in was denied.", "로그인이 거절됐습니다."],
  AWS_SSO_LOGIN_FAILED: ["AWS sign-in failed", "AWS 로그인 실패", "The sign-in failed; the note has the code.", "로그인이 실패했습니다. 메모에 코드가 있습니다."],
  AUDIT_CHAIN_STARTED: ["Audit chain started", "감사 체인 시작", "The hash chain started over the records that existed before it.", "그전까지의 기록 위에서 해시 체인을 시작했습니다."],
  AUDIT_CHAIN_ANCHORED: ["Audit chain anchored", "감사 체인 앵커", "The hourly anchor of the verified chain head.", "확인된 체인 머리를 매시간 남기는 앵커입니다."],
  AUDIT_CHAIN_REWOUND: ["Audit chain rewound", "감사 체인 되감김", "The head the worker sealed last lost its place.", "작업자가 마지막으로 봉인한 체인 머리가 자리를 잃었습니다."],
  AUDIT_CHAIN_ACKNOWLEDGED: ["Chain problems accepted", "체인 문제 확인 처리", "An Admin accepted the chain problems they examined, with a reason.", "관리자가 확인한 체인 문제를 사유와 함께 받아들였습니다."],
  CONNECTION_EXPIRY_DECLARED: ["Expiry entered", "만료일 입력", "An Admin entered an expiry the provider does not report.", "관리자가 공급자가 알려 주지 않는 만료일을 입력했습니다."],
  CONNECTION_EXPIRY_CLEARED: ["Expiry cleared", "만료일 지움", "An Admin cleared the expiry they had entered.", "관리자가 입력했던 만료일을 지웠습니다."],
  INSTALLATION_SETTING_CHANGED: ["Setting changed", "환경 설정 변경", "An Admin changed an installation setting; the note names the setting and what changed, never an address or identifier.", "관리자가 설치 설정을 바꿨습니다. 메모에 바꾼 설정과 항목이 있고 주소나 식별자 값은 남기지 않습니다."],
  LEARNED_FP_PROFILE_STOPPED: ["Auto-triage profile stopped", "자동 오탐 프로필 멈춤", "An Admin stopped a learned profile from closing findings; its samples are kept.", "관리자가 학습한 프로필의 자동 처리를 멈췄습니다. 표본은 남아 있습니다."],
  LEARNED_FP_PROFILE_RESET: ["Auto-triage samples cleared", "자동 오탐 표본 비움", "An Admin cleared a learned profile's samples; it learns again from the next confirmation.", "관리자가 학습한 프로필의 표본을 지웠습니다. 다음 확정부터 다시 배웁니다."],
};

const auditTargets: Record<string, [string, string]> = {
  notion_webhook: ["Notion change notification", "Notion 변경 알림"],
  api_request: ["API request", "사용자 요청"], sign_in: ["Sign-in session", "로그인 세션"],
  finding: ["Finding", "탐지 결과"], connection: ["Content source", "노출 검사 연결"], provider_connection: ["Integration", "연동"],
  coverage_connection: ["Collection", "수집"], action_plan: ["Action plan", "조치 계획"], credential: ["Credential", "Credential"],
  orphan: ["Unlinked credential", "연결 없는 자격증명"], coverage_entity: ["Inventory item", "발급 목록 항목"],
  contact_delivery: ["Contact delivery", "연락 발송"], detection_alerts: ["Slack detection alerts", "Slack 탐지 알림"],
  ticket_system: ["Ticket system", "티켓 시스템"], response_channels: ["Response channels", "대응 알림 채널"],
  owner_approval_policy: ["Owner approval policy", "소유자 승인 정책"], github_app_manifest: ["GitHub App setup", "GitHub App 만들기"],
  gcp_oauth: ["Google sign-in", "Google 로그인"], siem_event: ["SIEM event", "SIEM 이벤트"], siem_destination: ["SIEM destination", "SIEM 목적지"],
  domain: ["Domain", "도메인"], machine_identity: ["Machine identity", "기계 신원"], identity_person: ["Person", "사람"],
  installation_setting: ["Installation setting", "환경 설정"], learned_fp_profile: ["Learned false-positive profile", "학습한 오탐 프로필"],
  identity_check: ["Departed-owner check", "퇴사자 점검"], aws_sso_login: ["AWS sign-in", "AWS 로그인"], audit_chain: ["Audit chain", "감사 체인"],
  connection_health: ["Connection health", "연결 상태"],
};

export function auditActionText(action: string, locale: Locale) {
  const copy = auditActions[action.replace(/^FINDING_/, "")];
  return { label: copy ? copy[locale === "ko" ? 1 : 0] : action.replaceAll("_", " "), description: copy ? copy[locale === "ko" ? 3 : 2] : localize(locale, "No explanation is registered for this action. Review its original code and saved evidence below.", "설명이 등록되지 않은 작업입니다. 아래 원본 작업 코드와 저장된 기록을 확인하세요.") };
}

export function auditActorLabel(actor: string, locale: Locale) {
  const labels: Record<string, [string, string]> = { scanner: ["Automatic scanner", "자동 스캐너"], "system:rescore": ["System · risk reevaluation", "시스템 · 위험도 재평가"], "system:learned-fp": ["System · false-positive policy", "시스템 · 오탐 판정"],
    "system:audit-chain": ["System · audit chain", "시스템 · 감사 체인"], "system:domains": ["System · domain re-check", "시스템 · 도메인 재확인"],
    "system:owner-approval": ["System · owner approval", "시스템 · 소유자 승인"], "system:ticketing": ["System · ticket system", "시스템 · 티켓 시스템"], "system:response": ["System · exposure response", "시스템 · 노출 대응"],
    "system:onboarding": ["System · integration check", "시스템 · 연동 점검"], "system:github-enterprise": ["System · GitHub Enterprise", "시스템 · GitHub Enterprise"],
    "system:contact": ["System · contact delivery", "시스템 · 연락 발송"], "system:identity-leavers": ["System · departed-owner check", "시스템 · 퇴사자 점검"],
    "system:principals": ["System · sign-in accounts", "시스템 · 로그인 계정"], "system:machine-identity": ["System · machine identity", "시스템 · 기계 신원"],
    "metadata-schedule": ["Collection schedule", "수집 예약"], UNKNOWN: ["Unknown", "미상"] };
  return labels[actor]?.[locale === "ko" ? 1 : 0] || actor;
}

export function auditTargetLabel(target: string, locale: Locale) {
  const copy = auditTargets[target];
  return copy ? localize(locale, copy[0], copy[1]) : target;
}

export function scanDurationText(seconds: number | null | undefined, locale: Locale) {
  if (seconds == null) return "—";
  if (seconds < 1) return localize(locale, "< 1s", "1초 미만");
  if (seconds < 60) return `${Math.round(seconds)}${localize(locale, "s", "초")}`;
  const m = Math.floor(seconds / 60), s = Math.round(seconds % 60);
  return `${m}${localize(locale, "m", "분")} ${s}${localize(locale, "s", "초")}`;
}
// Plain-language reason for a run parked mid-scan, so an operator knows what to do.

export function holdText(code: string, locale: Locale): { title: string; action: string } {
  const map: Record<string, [string, string, string, string]> = {
    AWS_LOGIN_REQUIRED: ["AWS sign-in expired", "AWS 로그인 만료", "Follow the guidance next to Test connection in the AWS integration; the scan resumes automatically.", "AWS 연동의 연결 확인 옆 안내를 따르세요. 스캔은 자동으로 이어집니다."],
    METADATA_COLLECTION_PAUSED: ["Paused by an operator", "운영자가 일시 정지함", "Resuming continues the same run from its last saved page.", "재개하면 마지막으로 저장한 페이지부터 같은 실행을 이어갑니다."],
    AWS_IDENTITY_CHANGED: ["AWS identity changed", "AWS 신원 변경됨", "The signed-in AWS identity differs from the approved one. Sign in as the approved identity or re-approve it.", "로그인된 AWS 신원이 승인된 것과 다릅니다. 승인된 신원으로 로그인하거나 다시 승인하세요."],
    REVALIDATION_REQUIRED: ["Account needs revalidation", "계정 재검증 필요", "Re-validate this account's access in Accounts & providers.", "'계정·공급자'에서 이 계정의 접근을 다시 검증하세요."],
    ACCOUNT_NOT_CONNECTED: ["Account not connected", "계정 미연결", "Connect this AWS account (deploy the member role) before scanning it.", "이 AWS 계정을 연결(멤버 역할 배포)한 뒤 스캔하세요."],
    ACCOUNT_OWNER_UNKNOWN: ["Owner account unknown", "소유 계정 미확인", "The key's owner account is not established; verification must run first.", "키의 소유 계정이 확인되지 않았습니다. 먼저 검증이 필요합니다."],
  };
  const e = map[code];
  if (e) return { title: localize(locale, e[0], e[1]), action: localize(locale, e[2], e[3]) };
  if (code.startsWith("BUDGET")) return { title: localize(locale, "Waiting for scan budget", "스캔 예산 대기"), action: localize(locale, "A sibling scope is using the shared request budget; this resumes when budget frees up.", "다른 범위가 공유 요청 예산을 쓰는 중입니다. 예산이 나면 이어집니다.") };
  return { title: code, action: localize(locale, "The scan is waiting on an external condition and will retry automatically.", "외부 조건을 기다리는 중이며 자동으로 다시 시도합니다.") };
}

export function failureCodeLabel(code: string, locale: Locale) {
  const map: Record<string, [string, string]> = {
    GITHUB_TREE_UNAVAILABLE: ["Repository tree could not be read", "저장소 트리를 읽지 못함"],
    GITHUB_REPOSITORY_UNAVAILABLE: ["Repository unavailable", "저장소 접근 불가"],
    GITHUB_ORG_LIST_FAILED: ["Organization listing failed", "조직 목록 조회 실패"],
    S3_LIST_FAILED: ["Bucket listing failed", "버킷 목록 조회 실패"],
    S3_OBJECT_UNREADABLE: ["Object could not be read", "객체를 읽지 못함"],
    NOTION_SEARCH_FAILED: ["Notion search failed", "Notion 검색 실패"],
    BUDGET_REQUESTS: ["Reached its request budget; the next run resumes here", "요청 예산 도달 · 다음 실행이 여기서 이어감"],
    BUDGET_BYTES: ["Ran out of byte budget", "바이트 예산 소진"],
    OBJECTS_INCOMPLETE: ["Some objects failed or were not fully scanned", "검사 실패·미완료 객체 있음"],
    ENCRYPTED_DOCUMENT: ["Encrypted or protected document", "암호화·보호된 문서"],
    MALFORMED_DOCUMENT: ["Damaged document", "손상된 문서"],
    NO_EXTRACTABLE_TEXT: ["No extractable text; image review needed", "추출 가능한 텍스트 없음 · 이미지 확인 필요"],
    PDF_GRAPHICS_CONTENT: ["PDF graphics were not read", "PDF 그래픽 내용은 읽지 못함"],
    EMBEDDED_CONTENT: ["Embedded objects were not fully read", "삽입 개체 일부를 읽지 못함"],
    MEDIA_FORMAT: ["Image, audio, video or font file; not read for text", "이미지·오디오·영상·글꼴 파일이라 글자를 읽지 않음"],
    UNSUPPORTED_FORMAT: ["Unsupported document format", "지원하지 않는 문서 형식"],
    UNSUPPORTED_ENCODING: ["Unsupported text encoding", "지원하지 않는 텍스트 인코딩"],
    BINARY_CONTENT: ["Unrecognized binary content", "해석할 수 없는 바이너리 내용"],
    UNSUPPORTED_HWP_VERSION: ["Unsupported HWP version", "지원하지 않는 HWP 버전"],
    UNSUPPORTED_DOC_VERSION: ["Unsupported Word version", "지원하지 않는 Word 버전"],
    UNSUPPORTED_OLE_FORMAT: ["Unsupported legacy Office format", "지원하지 않는 구형 Office 형식"],
    INPUT_LIMIT: ["File size limit", "파일 크기 한도"],
    TEXT_LIMIT: ["Extracted text size limit", "추출 텍스트 크기 한도"],
    EXPANSION_LIMIT: ["Archive expansion limit", "압축 해제 크기 한도"],
    MEMBER_SIZE_LIMIT: ["Archive member size limit", "압축 내부 파일 크기 한도"],
    MEMBER_LIMIT: ["Archive member count limit", "압축 내부 파일 수 한도"],
    PAGE_LIMIT: ["PDF page limit", "PDF 페이지 수 한도"],
    DEPTH_LIMIT: ["Nested archive depth limit", "중첩 압축 깊이 한도"],
    PARSE_TIMEOUT: ["Document reading timed out", "문서 읽기 시간 초과"],
    PARSER_RESOURCE_LIMIT: ["Document reader memory limit", "문서 읽기 메모리 한도"],
    PARSER_FAILURE: ["Document reader failed", "문서 읽기 실패"],
    PARSER_UNAVAILABLE: ["Document reader is unavailable", "문서 읽기 도구를 사용할 수 없음"],
    MISSING_DOCUMENT_BODY: ["Document body is missing", "문서 본문 누락"],
    MISSING_PACKAGE_MEMBER: ["Referenced document member is missing", "문서에서 참조하는 구성요소 누락"],
    ARCHIVE_SPECIAL_MEMBER: ["Special archive member skipped", "압축 내부 특수 항목 제외"],
    DUPLICATE_MEMBERS: ["Duplicate archive member names", "압축 내부 파일명 중복"],
    TRAILING_COMPRESSED_DATA: ["Additional compressed stream not read", "연결된 추가 압축 스트림 미검사"],
    RTF_EXTENSION_CONTENT: ["RTF extension content not fully read", "RTF 확장 내용 일부 미검사"],
    OBJECTS_NOT_SCANNED: ["Failed, incomplete or unsupported-format objects (counted together)", "검사 실패·미완료 또는 미지원 형식 (분리 전 집계)"],
    CHILD_TASK_FAILED: ["A scope task failed", "범위 태스크 실패"],
    INSUFFICIENT_PERMISSION: ["Insufficient permission", "권한 부족"],
    ATLASSIAN_OAUTH_TOKEN_REFUSED: ["Atlassian refused the service account's client", "Atlassian이 서비스 계정 클라이언트를 거절함"],
    ATLASSIAN_OAUTH_UNAVAILABLE: ["Atlassian sign-in did not answer", "Atlassian 로그인이 응답하지 않음"],
    ATLASSIAN_OAUTH_NOT_FOR_THIS_SOURCE: ["A Confluence service account credential is set on another source", "다른 소스에 Confluence 서비스 계정 자격증명이 지정됨"],
    CONFLUENCE_GATEWAY_ADDRESS_INVALID: ["Not a Confluence gateway address", "Confluence 게이트웨이 주소가 아님"],
    CONFLUENCE_CLOUD_ID_UNAVAILABLE: ["The Confluence site's cloud ID could not be read", "Confluence 사이트의 Cloud ID를 읽지 못함"],
    // The only codes the SIEM outbox keeps for a failed delivery (cremore/siem/outbox.py SAFE_CODES).
    DELIVERY_FAILED: ["Delivery failed", "전송 실패"], DELIVERY_TIMEOUT: ["Delivery timed out", "전송 시간 초과"],
    DELIVERY_REJECTED: ["The destination refused it", "목적지가 거절함"], DELIVERY_RATE_LIMITED: ["The destination's rate limit", "목적지 요청 한도"],
    AUTH_FAILED: ["The destination refused the sign-in", "목적지가 인증을 거절함"], INVALID_RESPONSE: ["The destination's answer could not be read", "목적지 응답을 읽지 못함"],
    SINK_UNAVAILABLE: ["The output is not available", "출력을 쓸 수 없음"], HTTP_STATUS_REJECTED: ["The destination answered with an error status", "목적지가 오류 상태로 응답함"],
    HEC_RESPONSE_REJECTED: ["Splunk HEC refused the event", "Splunk HEC가 이벤트를 거절함"], RESPONSE_TOO_LARGE: ["The destination's answer was too large", "목적지 응답이 너무 큼"],
    HTTP_DELIVERY_FAILED: ["The HTTP delivery failed", "HTTP 전송 실패"], STDOUT_DELIVERY_FAILED: ["Writing to standard output failed", "표준 출력에 쓰지 못함"],
    INVALID_EVENT: ["The event could not be formatted", "이벤트 형식을 만들지 못함"], INVALID_EVENT_TIME: ["The event time could not be formatted", "이벤트 시각 형식 오류"],
    OAUTH_TOKEN_FAILED: ["The destination's sign-in token was refused", "목적지 로그인 토큰을 받지 못함"], SYSLOG_CONNECT_FAILED: ["Could not reach the syslog server", "syslog 서버에 연결하지 못함"],
    SYSLOG_TLS_FAILED: ["The syslog TLS handshake failed", "syslog TLS 연결 실패"], SYSLOG_DELIVERY_FAILED: ["The syslog delivery failed", "syslog 전송 실패"],
  };
  // A collection's reason reads the same here as on its metadata screens.
  const e = map[code] ?? metadataReasonLabels[code];
  return e ? localize(locale, e[0], e[1]) : enumLabel(code, locale);
}

export function credentialTypeLabel(type: string, locale: Locale = "en") {
  if (customRuleType(type)) return localize(locale, "Custom rule match · unconfirmed", "사용자 규칙 일치 · 미확정");
  const labels: Record<string, string> = locale === "ko" ? {
    AWS_ACCESS_KEY: "AWS 액세스 키",
    AWS_ACCESS_KEY_ID: "AWS 액세스 키 ID · 식별자만 노출",
    AWS_SECRET_ACCESS_KEY: "AWS 시크릿 키 · ID 미확정",
    AWS_SESSION_TOKEN: "AWS 세션 토큰 · 일부 구성요소",
    GITHUB: "GitHub 토큰",
    GITHUB_TOKEN: "GitHub 토큰",
    NOTION_TOKEN: "Notion 통합 토큰",
    GENERIC_PASSWORD: "하드코딩된 비밀번호",
    GENERIC_API_KEY: "일반 API 키",
    BASIC_AUTH_URL: "URL에 포함된 인증 정보",
    DB_CONNECTION_STRING: "DB 연결 문자열",
    GITLAB: "GitLab 토큰",
    SLACK: "Slack 토큰",
    PRIVATE_KEY: "개인 키",
    GENERIC_SECRET: "일반 비밀정보",
    AZURE_DEVOPS_PAT: "Azure DevOps 개인 액세스 토큰",
    AZURE_SAS_TOKEN: "Azure Storage SAS 토큰",
    AZURE_ENTRA_CLIENT_SECRET: "Microsoft Entra 클라이언트 시크릿",
  } : {
    AWS_ACCESS_KEY: "AWS access key",
    AWS_ACCESS_KEY_ID: "AWS access key ID · identifier only",
    AWS_SECRET_ACCESS_KEY: "AWS secret key · ID unconfirmed",
    AWS_SESSION_TOKEN: "AWS session token · partial material",
    GITHUB: "GitHub token",
    GITHUB_TOKEN: "GitHub token",
    NOTION_TOKEN: "Notion integration token",
    GENERIC_PASSWORD: "Hardcoded password",
    GENERIC_API_KEY: "Generic API key",
    BASIC_AUTH_URL: "Credentials in URL",
    DB_CONNECTION_STRING: "Database connection string",
    GITLAB: "GitLab token",
    SLACK: "Slack token",
    PRIVATE_KEY: "Private key",
    GENERIC_SECRET: "Generic secret",
    AZURE_DEVOPS_PAT: "Azure DevOps personal access token",
    AZURE_SAS_TOKEN: "Azure Storage SAS token",
    AZURE_ENTRA_CLIENT_SECRET: "Microsoft Entra client secret",
  };
  return (
    labels[type] ||
    type
      .split("_")
      .filter(Boolean)
      .map((word) => word.charAt(0) + word.slice(1).toLowerCase())
      .join(" ") ||
    localize(locale, "Credential", "자격증명")
  );
}

/* A metadata collection's reasons: a run's, a source report's or a worker job's code.
 * The platform's and GitHub's codes are here; other provider codes show as themselves. */
export const metadataReasonLabels: Record<string, [string, string]> = {
  METADATA_COLLECTION_PAUSED: ["Paused by an operator; resuming continues the same run", "운영자가 일시중지함 · 재개하면 같은 실행을 이어감"],
  METADATA_COLLECTION_PAUSE_EXPIRED: ["The pause reached the run's 6-hour lifetime; closed with what it read", "일시중지가 실행 수명(6시간)에 닿아 읽은 결과까지로 닫음"],
  METADATA_COLLECTION_STOPPED: ["Stopped by an operator; what it saved stays readable", "운영자가 중지함 · 저장한 결과는 그대로 조회 가능"],
  METADATA_COLLECTION_FAILED: ["The collection failed", "수집 실패"],
  METADATA_SECRET_UNAVAILABLE: ["A required secret reference could not be resolved", "필수 비밀 참조를 해석하지 못함"],
  METADATA_RETRY_LATER: ["Waiting to retry", "잠시 뒤 다시 시도함"],
  SOURCE_COVERAGE_NOT_REPORTED: ["The collection did not report what it read, so it counts as partial", "수집이 읽은 범위를 보고하지 않아 일부로 봄"],
  SOURCE_COLLECTION_INCOMPLETE: ["Some of what it reads was not read to the end", "읽을 곳 가운데 끝까지 읽지 못한 곳이 있음"],
  UNRESOLVED_ITEMS: ["Some items' values could not be read for matching", "대조할 값을 읽지 못한 항목이 있음"],
  METADATA_FACT_LIMIT: ["Too many fields; the rest were not kept", "필드가 너무 많아 나머지는 저장하지 않음"],
  INVALID_METADATA_VALUE: ["A value in a form that cannot be kept", "저장할 수 없는 형식의 값"],
  UNAPPROVED_METADATA_FIELD: ["Not on the list of fields that may be kept", "저장할 수 있는 필드 목록에 없음"],
  INVALID_METADATA_TIME: ["A time in a form that cannot be kept", "저장할 수 없는 형식의 시각"],
  CONNECTION_REVISION_CONFLICT: ["The connection was changed or disabled during the collection", "수집 중 연결 설정이 바뀌었거나 비활성화됨"],
  COLLECTOR_PRINCIPAL_MISMATCH: ["The collecting identity changed between pages", "페이지 사이에 수집 주체가 바뀜"],
  PROVIDER_AUTH_VALUE_IN_METADATA: ["A page carried an authentication value and was refused", "인증 값이 담긴 페이지를 거부함"],
  LEASE_RETRY_LIMIT: ["The task did not finish within its retries", "작업이 재시도 한도 안에 끝나지 않음"],
  RUN_EXPIRED: ["The run passed its 6-hour lifetime", "실행이 6시간 수명을 넘김"],
  RUN_CLOSED_OR_EXPIRED: ["The run was already closed or past its lifetime", "실행이 이미 닫혔거나 수명을 넘김"],
  REQUEST_BUDGET_EXCEEDED: ["Reached the run's request limit; what was not read is not empty", "실행 요청 한도 도달 · 읽지 못한 부분은 빈 결과가 아님"],
  PAGE_BUDGET_EXCEEDED: ["Reached the run's page limit; what was not read is not empty", "실행 페이지 한도 도달 · 읽지 못한 부분은 빈 결과가 아님"],
  RECORD_BUDGET_EXCEEDED: ["Reached the run's record limit; what was not read is not empty", "실행 레코드 한도 도달 · 읽지 못한 부분은 빈 결과가 아님"],
  TIME_BUDGET_EXCEEDED: ["Reached the run's time limit; what was not read is not empty", "실행 시간 한도 도달 · 읽지 못한 부분은 빈 결과가 아님"],
  TASK_BUDGET_EXCEEDED: ["Reached the run's task limit; what was not read is not empty", "실행 작업 수 한도 도달 · 읽지 못한 부분은 빈 결과가 아님"],
  COLLECTION_STOPPED: ["Stopped early after a failure the next reads would repeat", "다음 읽기도 같은 실패가 날 오류로 일찍 멈춤"],
  INVALID_PAGE_DATA: ["A page did not have the expected shape", "페이지 형식이 예상과 다름"],
  GITHUB_APP_IDENTITY_MISMATCH: ["The private key belongs to a different GitHub App", "개인 키가 설정과 다른 GitHub App의 것임"],
  GITHUB_APP_PRIVATE_KEY_INVALID: ["The GitHub App private key cannot sign", "GitHub App 개인 키로 서명할 수 없음"],
  GITHUB_APP_ID_INVALID: ["The GitHub App ID or Client ID is not valid", "GitHub App ID 또는 Client ID가 올바르지 않음"],
  GITHUB_HTTP_401: ["GitHub rejected the credential (401)", "GitHub가 자격증명을 거부함(401)"],
  GITHUB_HTTP_403: ["GitHub refused access (403)", "GitHub가 접근을 거부함(403)"],
  GITHUB_HTTP_404: ["Not found, or not visible to the App (404)", "없거나 App에 보이지 않음(404)"],
  GITHUB_RATE_LIMITED: ["GitHub's rate limit; the run waits and resumes", "GitHub 요청 한도 · 기다렸다가 이어감"],
  GITHUB_UNAVAILABLE: ["GitHub did not answer; the run waits and resumes", "GitHub 응답 없음 · 기다렸다가 이어감"],
  GITHUB_ENTERPRISE_AUDIT_TOKEN_REQUIRED: ["No classic PAT is set for the Enterprise audit log", "Enterprise 감사 로그용 classic PAT가 없음"],
  GITHUB_ENTERPRISE_AUDIT_TOKEN_UNAVAILABLE: ["The Enterprise audit PAT could not be resolved", "Enterprise 감사 PAT를 해석하지 못함"],
  GITHUB_ENTERPRISE_AUDIT_TOKEN_REJECTED: ["GitHub rejected the Enterprise audit PAT", "GitHub가 Enterprise 감사 PAT를 거부함"],
  GITHUB_ENTERPRISE_AUDIT_TOKEN_INVALID: ["The Enterprise audit token is not a classic PAT", "Enterprise 감사 토큰이 classic PAT가 아님"],
  ORGANIZATION_INSTALLATION_SUSPENDED: ["The App's installation on this organization is suspended", "이 조직의 App 설치가 정지됨"],
  ORGANIZATION_INSTALLATION_GITHUB_HTTP_403: ["The installation lookup was refused (403)", "설치 조회가 거부됨(403)"],
  ORGANIZATION_INSTALLATION_GITHUB_HTTP_404: ["This App's installation was not found (404); not proof it is uninstalled", "이 App의 설치를 찾지 못함(404) · 설치가 없다는 뜻은 아님"],
  SLACK_MISSING_SCOPE: ["The Slack token lacks a scope this read needs", "Slack 토큰에 이 읽기에 필요한 범위가 없음"],
  SLACK_TEAMS_READ_REQUIRED: ["Workspace discovery requires admin.teams:read on an organization-installed admin app", "워크스페이스 목록 조회에는 조직에 설치한 관리자 앱의 admin.teams:read 권한이 필요함"],
  SLACK_WORKSPACES_NOT_CONFIRMED: ["Workspace membership could not be confirmed; check access and retry", "워크스페이스 소속을 확인하지 못함 · 권한 확인 후 다시 조회"],
  SLACK_NO_PERMISSION: ["The Slack token lacks a scope this read needs", "Slack 토큰에 이 읽기에 필요한 범위가 없음"],
  SLACK_NOT_AN_ADMIN: ["The token's user is not an organization admin", "토큰 사용자가 조직 관리자가 아님"],
  SLACK_NOT_ALLOWED_TOKEN_TYPE: ["An organization admin's user token is required", "조직 관리자의 사용자 토큰이 필요함"],
  SLACK_FEATURE_NOT_ENABLED: ["The admin API or audit log is not on for this organization (Enterprise Grid)", "이 조직에 관리 API·감사 로그가 켜져 있지 않음(Enterprise Grid)"],
  SLACK_APP_MANAGEMENT_APP_NOT_INSTALLED_ON_ORG: ["The app must be installed on the organization, not a workspace", "앱을 워크스페이스가 아니라 조직에 설치해야 함"],
  SLACK_TEAM_NOT_FOUND: ["The workspace is not visible to this token", "이 토큰으로 워크스페이스가 보이지 않음"],
  SLACK_TEAM_ACCESS_NOT_GRANTED: ["The workspace is not visible to this token", "이 토큰으로 워크스페이스가 보이지 않음"],
  SLACK_INVALID_AUTH: ["Slack rejected the token", "Slack이 토큰을 거부함"],
  SLACK_TOKEN_REVOKED: ["The Slack token was revoked", "Slack 토큰이 폐기됨"],
  SLACK_TOKEN_EXPIRED: ["The Slack token expired", "Slack 토큰이 만료됨"],
  SLACK_ACCOUNT_INACTIVE: ["The token's user or workspace is deactivated", "토큰 사용자나 워크스페이스가 비활성화됨"],
  SLACK_RATE_LIMITED: ["Slack's rate limit; the run waits and resumes", "Slack 요청 한도 · 기다렸다가 이어감"],
  SLACK_UNAVAILABLE: ["Slack did not answer; the run waits and resumes", "Slack 응답 없음 · 기다렸다가 이어감"],
  SLACK_RETRY_LIMIT: ["Slack kept failing past the retry limit", "재시도 한도를 넘도록 Slack 응답이 실패함"],
  SLACK_AUDIT_APP_LIMIT: ["More than 5,000 apps in the audit log window; the rest were not taken", "감사 로그 기간의 앱이 5,000개를 넘어 나머지는 반영하지 않음"],
  SLACK_INVALID_RECORD: ["An entry did not have the expected shape and was left out", "형식이 맞지 않는 항목을 뺌"],
  SLACK_METADATA_OMITTED: ["A value could not be kept and was left out", "보관할 수 없는 값을 뺌"],
  SLACK_DUPLICATE_RECORD: ["An app was listed twice; the second was left out", "같은 앱이 두 번 나와 두 번째를 뺌"],
  SLACK_CURSOR_CYCLE: ["Slack returned a page it had already given", "Slack이 이미 준 페이지를 다시 줌"],
  SLACK_INVALID_RESPONSE: ["A Slack answer did not have the expected shape", "Slack 응답 형식이 예상과 다름"],
  SLACK_RESPONSE_LIMIT: ["A Slack answer was larger than allowed", "Slack 응답이 허용 크기를 넘음"],
  TOKEN_VALUES_AND_WEBHOOK_URLS_NOT_RETURNED: ["Slack never returns token values or webhook URLs", "Slack은 토큰 값·웹훅 URL을 주지 않음"],
};

/** A code in words with the code kept, for support and search; an unknown code stays itself. */
export function metadataReasonText(code: string, locale: Locale) {
  const e = metadataReasonLabels[code];
  return e ? `${localize(locale, e[0], e[1])} (${code})` : code;
}

export function metadataReasonsText(codes: readonly string[], locale: Locale) {
  return codes.map((code) => metadataReasonText(code, locale)).join(" · ");
}
