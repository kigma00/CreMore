"""Owner contact sent by CreMore, through the API: an admin sets the relay and the bot up (their secrets never come
back), an analyst sends from a finding to allowed domains, and each send or failure is in the finding's history
without its text or its recipients' addresses."""

import datetime as dt
import json

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import Credential, Exposure
from cremore.governance.contact_test import MAIL, PASSWORD, TOKEN, Relay, Slack

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


def bearer(issuer, sub, group):
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,))}


def setup(issuer):
    repo = InMemoryRepository()
    cred = repo.upsert_credential(Credential(fingerprint="fp", credential_type="GITHUB_TOKEN", provider="github"))
    exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="synthetic", location="a"))
    finding = repo.upsert_finding(cred.id, exposure.id, "HIGH")
    client = TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))
    relay, slack = Relay(), Slack()
    client.app.state.contact_transports = {"smtp": relay, "smtp_ssl": relay, "http_client_factory": slack.client}
    return repo, client, finding, relay, slack


def history(repo, finding, prefix="OWNER_CONTACT"):
    return [(event.event_type, event.note) for event in repo.list_finding_events(finding.id) if event.event_type.startswith(prefix)]


def test_an_admin_sets_up_the_channels_and_never_sees_the_secrets_again(issuer):
    _repo, client, _finding, relay, _slack = setup(issuer)
    admin, analyst = bearer(issuer, "ada", "g-admins"), bearer(issuer, "ann", "g-analysts")
    body = {"mail": MAIL, "slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]}, "allowed_domains": ["example.com"]}
    assert client.put("/api/v1/settings/contact-delivery", headers=analyst, json=body).status_code == 403
    saved = client.put("/api/v1/settings/contact-delivery", headers=admin, json=body)
    assert saved.status_code == 200 and saved.headers["cache-control"] == "no-store"
    shown = client.get("/api/v1/settings/contact-delivery", headers=admin).text
    assert PASSWORD not in saved.text + shown and TOKEN not in saved.text + shown
    assert json.loads(shown)["mail"]["password_saved"] is True
    assert json.loads(shown)["slack"] == {"token_saved": True, "allowed_channels": ["#security-alerts"]}
    # The analysts' view says only which channels are ready and where they send.
    assert client.get("/api/v1/contact-delivery", headers=analyst).json() == {
        "mail": True, "slack": True, "allowed_domains": ["example.com"], "allowed_channels": ["#security-alerts"],
        "console_url": None}
    refused = client.put("/api/v1/settings/contact-delivery", headers=admin, json={**body, "allowed_domains": []})
    assert refused.status_code == 422 and refused.json()["detail"] == "CONTACT_DOMAINS_REQUIRED"
    # A test message on one channel; both the save and the test are audited, without secrets or addresses.
    tested = client.post("/api/v1/settings/contact-delivery/test", headers=admin, json={"channel": "mail", "to": "ada@example.com"})
    assert tested.status_code == 200 and tested.json()["delivered"] == ["ada@example.com"] and relay.sent
    audit = [(row["action"], row["note"]) for row in client.get("/api/v1/audit", headers=admin).json()
             if row["action"].startswith("CONTACT_DELIVERY")]
    assert ("CONTACT_DELIVERY_TESTED", "mail delivered=1") in audit
    saved_note = ("mail=smtp.example.com:587/starttls from=security@example.com slack=on mail_secret=replaced"
                  " slack_secret=replaced console=off +example.com +#security-alerts")
    assert ("CONTACT_DELIVERY_SAVED", saved_note) in audit
    assert PASSWORD not in json.dumps(audit) and "ada@example.com" not in json.dumps(audit)


def test_an_analyst_sends_from_a_finding_and_the_history_keeps_what_was_done(issuer):
    repo, client, finding, relay, _slack = setup(issuer)
    admin, analyst = bearer(issuer, "ada", "g-admins"), bearer(issuer, "ann", "g-analysts")
    client.put("/api/v1/settings/contact-delivery", headers=admin,
               json={"mail": MAIL, "slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]}, "allowed_domains": ["example.com"]})
    path = f"/api/v1/findings/{finding.id}/contacts/send"
    due = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=3)).isoformat()
    message = {"revision": 0, "channel": "mail", "template": "revoke", "due_at": due, "to": ["kim@example.com"],
               "subject": "[조치 요청] 노출된 토큰을 폐기해 주세요", "body": "안녕하세요.\n가린 식별자: ghp_••••"}
    sent = client.post(path, headers=analyst, json=message)
    assert sent.status_code == 200 and sent.json()["delivered"] == ["kim@example.com"]
    assert sent.json()["annotations"]["contact"]["sent"] is True and sent.json()["annotations"]["contact"]["recipients"] == 1
    assert relay.sent[-1]["Subject"] == message["subject"]
    # Slack: a person by address and a channel; the history counts them, and never names them.
    revision = sent.json()["annotations"]["revision"]
    sent = client.post(path, headers=analyst, json={**message, "revision": revision, "channel": "slack", "subject": "",
                                                    "to": ["kim@example.com", "#security-alerts"]})
    assert sent.status_code == 200 and sent.json()["delivered"] == ["kim@example.com", "#security-alerts"]
    notes = [note.split(" · ") for _kind, note in history(repo, finding)]
    assert [parts[:4] for parts in notes] == [["mail", "revoke", "1", due], ["slack", "revoke", "2", due]]
    # Keyed digests of the recipients and the text, so a message someone holds can be matched to its send.
    assert all(parts[4].startswith("to=") and parts[5].startswith("text=") and len(parts[5]) == 21 for parts in notes)
    assert "kim@example.com" not in json.dumps([event.model_dump(mode="json") for event in repo.list_finding_events(finding.id)])
    # Nothing goes out to another domain or an unlisted channel, with a secret in it, or on a stale read.
    revision = sent.json()["annotations"]["revision"]
    posted = len(relay.sent)
    for change, status, code in (({"to": ["kim@other.test"]}, 422, "CONTACT_RECIPIENT_NOT_ALLOWED"),
                                 ({"channel": "slack", "subject": "", "to": ["#general"]}, 422, "CONTACT_RECIPIENT_NOT_ALLOWED"),
                                 ({"body": f"값은 {GH} 입니다"}, 422, "TEXT_CONTAINS_CREDENTIAL"),
                                 ({"revision": revision - 1}, 409, "ANNOTATIONS_CHANGED"),
                                 ({"due_at": "2020-01-01"}, 422, "DUE_DATE_OUT_OF_RANGE")):
        refused = client.post(path, headers=analyst, json={**message, "revision": revision, **change})
        assert (refused.status_code, refused.json()["detail"]) == (status, code), change
        assert GH not in refused.text
    assert len(relay.sent) == posted and len(history(repo, finding)) == 2
    viewer = bearer(issuer, "vic", "g-viewers")
    assert client.post(path, headers=viewer, json={**message, "revision": revision}).status_code == 403
    assert client.get("/api/v1/contact-delivery", headers=viewer).status_code == 403


def test_a_person_sends_a_bounded_number_an_hour_and_a_sent_message_is_never_lost_from_the_history(issuer, monkeypatch):
    from cremore.db.annotation_store import AnnotationStore
    from cremore.governance import contact

    repo, client, finding, relay, _slack = setup(issuer)
    admin, analyst = bearer(issuer, "ada", "g-admins"), bearer(issuer, "ann", "g-analysts")
    client.put("/api/v1/settings/contact-delivery", headers=admin, json={"mail": MAIL, "allowed_domains": ["example.com"]})
    path = f"/api/v1/findings/{finding.id}/contacts/send"
    due = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=3)).isoformat()
    message = {"revision": 0, "channel": "mail", "template": "info", "due_at": due, "subject": "확인 요청", "body": "확인 부탁드립니다."}
    monkeypatch.setattr(contact, "HOURLY_RECIPIENTS", 2)
    limited = client.post(path, headers=analyst, json={**message, "to": ["a@example.com", "b@example.com", "c@example.com"]})
    assert (limited.status_code, limited.json()["detail"]) == (429, "CONTACT_RATE_LIMITED") and not relay.sent
    # The annotations cannot be written after the message went out: the send and its audit row stand.
    monkeypatch.setattr(AnnotationStore, "change", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("db down")))
    sent = client.post(path, headers=analyst, json={**message, "to": ["kim@example.com"]})
    assert sent.status_code == 200 and sent.json()["annotations"] is None and len(relay.sent) == 1
    # The refusal is in the history too, so a person pressing on the limit shows.
    assert [(kind, note.rsplit(" · ", 1)[-1] if kind.endswith("FAILED") else "") for kind, note in history(repo, finding)] == [
        ("OWNER_CONTACT_FAILED", "CONTACT_RATE_LIMITED"), ("OWNER_CONTACT_SENT", "")]


def test_a_send_that_does_not_go_out_is_in_the_history_as_a_failure(issuer):
    repo, client, finding, _relay, _slack = setup(issuer)
    admin, analyst = bearer(issuer, "ada", "g-admins"), bearer(issuer, "ann", "g-analysts")
    path = f"/api/v1/findings/{finding.id}/contacts/send"
    due = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=3)).isoformat()
    message = {"revision": 0, "channel": "mail", "template": "info", "due_at": due, "to": ["kim@example.com"],
               "subject": "확인 요청", "body": "사용 여부를 알려 주세요."}
    # Not set up: nothing to send with, nothing recorded.
    refused = client.post(path, headers=analyst, json=message)
    assert (refused.status_code, refused.json()["detail"]) == (409, "CONTACT_CHANNEL_NOT_SET_UP") and history(repo, finding) == []
    client.put("/api/v1/settings/contact-delivery", headers=admin, json={"mail": MAIL, "allowed_domains": ["example.com"]})
    client.app.state.contact_transports = {"smtp": Relay(fail="auth")}
    failed = client.post(path, headers=analyst, json=message)
    assert (failed.status_code, failed.json()["detail"]) == (502, "SMTP_AUTH_FAILED")
    assert history(repo, finding) == [("OWNER_CONTACT_FAILED", "mail · info · SMTP_AUTH_FAILED")]
    annotations = client.get(f"/api/v1/findings/{finding.id}/annotations", headers=analyst).json()
    assert not annotations["contact"] and annotations["revision"] == 0
