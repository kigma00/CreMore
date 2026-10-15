"""The people directory over synthetic IdP collections (cremore.identity.people)."""

from cremore_azure_provider.entra_id import entra_id_test
from cremore_okta_provider.tests import test_identity as okta

from cremore.coverage.metadata_job_test import (
    repo as repo,  # noqa: PLC0414 -- memory and sqlite repositories
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.identity import idp, people
from cremore.identity.leavers_test import save


def okta_row(ident, status, email, first, last, department=None):
    row = okta.row(ident, status, email=email)
    row["profile"].update(firstName=first, lastName=last, **({"department": department} if department else {}))
    return row


def okta_records(spec, *rows):
    records, final = okta.run(spec, okta.Org({"": okta.users_page(*rows)}))
    assert final.status == "COMPLETE"
    return records


def seed(repo, *, profiles=True):
    store = MetadataStore(repo)
    options = {"page_size": 200, **({"keep_profiles": True} if profiles else {})}
    kept = okta.spec(options=options)
    save(store, kept, okta_records(kept, okta_row("00uada000001", "ACTIVE", "a@acme.test", "Ada", "Lovelace", "Platform"),
                                   okta_row("00ueve000001", "DEPROVISIONED", "eve@acme.test", "Eve", "Stone")))
    entra = entra_id_test.spec(options={"page_size": 2, **({"keep_profiles": True} if profiles else {})})
    records, _final = entra_id_test.run(entra)
    save(store, entra, records)
    return store


def test_people_come_from_opt_in_profiles_and_email_never_merges_idp_accounts(repo, monkeypatch):
    monkeypatch.setattr(entra_id_test.identity, "token_for_spec", lambda _spec: (lambda: "graph-token"))
    seed(repo)
    found = people.directory(repo)
    assert found["total"] == 5
    ada = next(person for person in found["items"] if person["name"] == "Ada Lovelace" and person["sources"][0]["provider"] == "okta")
    assert (ada["email"], ada["department"], ada["title"]) == ("a@acme.test", "Platform", None)
    same_email = [person for person in found["items"] if person["email"] == "a@acme.test"]
    assert len(same_email) == 2 and len({person["person_ref"] for person in same_email}) == 2
    assert ada["refs"] == [ada["id"]] and ada["id"] == ada["person_ref"]
    assert {person["sources"][0]["provider"] for person in people.directory(repo, query="  PLATFORM ")["items"]} == {"okta", "entra_id"}
    first = people.directory(repo, limit=1)
    assert first["items"] == found["items"][:1] and first["total"] == 5 and first["next_cursor"]


def test_collections_that_keep_digests_only_name_nobody(repo, monkeypatch):
    monkeypatch.setattr(entra_id_test.identity, "token_for_spec", lambda _spec: (lambda: "graph-token"))
    seed(repo, profiles=False)
    found = people.directory(repo)
    assert found["items"] == [] and found["total"] == 0 and found["directory"]["status"] == "PROFILES_DISABLED"


def test_a_profile_value_shaped_like_a_credential_is_not_kept():
    token = "gh" + "p_" + "A" * 36
    facts = idp.profile_facts((("display_name", "  Ada\n  Lovelace "), ("email", token), ("department", "Platform"),
                               ("display_name", "second"), ("nickname", "x")))
    assert [(fact.name, fact.value) for fact in facts] == [("display_name", "Ada Lovelace"), ("department", "Platform")]
