"""The exposure responder's link page (cremore.governance.response): a Slack DM or mail carried a CreMore link, and the
person it went to answers here signed in with the company IdP. No platform role is needed; the bearer is verified as
for an owner approval link (governance.link_holder) and only the request's own recipient reads or answers.
"""

from __future__ import annotations

from fastapi import Header
from pydantic import BaseModel, ConfigDict, Field

from cremore.api.http_support import http_error
from cremore.api.http_support import utc_now as _now
from cremore.api.routes.credentials import ResponseReportFields, _credentials_in
from cremore.api.routes.governance import link_holder
from cremore.governance import response

CODES = ("RESPONSE_LINK_NEEDS_SIGN_IN", "RESPONSE_LINK_SIGN_IN_REQUIRED", "RESPONSE_LINK_EMAIL_UNVERIFIED")


class ResponseLinkBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(max_length=64)


class ResponseLinkOptionsBody(ResponseLinkBody):
    q: str = Field(default="", max_length=200)


class ResponseLinkAnswerBody(ResponseReportFields):
    token: str = Field(max_length=64)


def register(ctx) -> None:
    app, repo, settings = ctx.app, ctx.repo, ctx.settings

    def holder(authorization: str) -> dict:
        return link_holder(app, repo, settings, authorization, CODES)

    @app.post("/api/v1/response-links/view")
    def view_response_link(body: ResponseLinkBody, authorization: str = Header(default="")) -> dict:
        """The request as the person it went to sees it; reading changes nothing."""
        who = holder(authorization)
        try:
            return response.link_view(repo, settings, body.token, who, now=_now())
        except response.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.post("/api/v1/response-links/answer")
    def answer_response_link(body: ResponseLinkAnswerBody, authorization: str = Header(default="")) -> dict:
        """The person's report, which is their answer: DONE declares cleanup, anything else declines it."""
        who = holder(authorization)
        try:
            return response.link_answer(repo, settings, body.token, who, report_id=body.report_id,
                data=body.model_dump(mode="json", exclude={"token", "report_id"}), now=_now(),
                contains_credentials=lambda text: bool(_credentials_in(app.state.orchestrator, text)))
        except response.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.post("/api/v1/response-links/evidence-options")
    def response_link_evidence_options(body: ResponseLinkOptionsBody, authorization: str = Header(default="")) -> dict:
        """The replacement references the report may name, for the link's own finding only, while it takes an answer."""
        from cremore.coverage import response_evidence

        who = holder(authorization)
        now = _now()
        try:
            finding = response.link_finding(repo, settings, body.token, who, now=now)
        except response.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None
        return response_evidence.options(repo, finding, now=now, q=body.q)
