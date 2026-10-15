"""aws bounded read-only inventory functions."""
from __future__ import annotations

from cremore.coverage.collection import Collection, CollectionLimit
from cremore.coverage.models import Observation, in_scope
from cremore_aws_provider.iam_inventory import (
    collect_iam,  # noqa: F401 -- preserve this public collection import.
)
from cremore_aws_provider.secret_inventory import collect_region
from cremore_aws_provider.usage_inventory import (
    collect_usage,  # noqa: F401 -- preserve this public collection import.
)


def collect_aws_vault(spec, client_factory, engine, *, checkpoint=None):
    out = Collection(spec, checkpoint=checkpoint)
    service = "secretsmanager" if spec.provider == "aws_secrets_manager" else "ssm"
    for region in spec.regions:
        try:
            client = client_factory(service, region)
            if service == "secretsmanager":
                collect_region(spec, client, engine, out, region)
            else:
                seen = set()
                for prefix in spec.prefixes:
                    for param in out.pages(client.get_parameters_by_path, "Parameters", token_in="NextToken", token_out="NextToken",
                                           Path="/" + prefix, Recursive=True, WithDecryption=True, MaxResults=10):
                        if param["ARN"] in seen:
                            continue
                        seen.add(param["ARN"])
                        location = {"reference": param["ARN"], "account_id": spec.account_id, "region": region, "version": str(param["Version"])}
                        if not in_scope(spec, Observation(**location, evidence="UNRESOLVED", reason="CHECKING_SCOPE")):
                            out.reasons.add("PROVIDER_SCOPE_MISMATCH")
                            continue
                        out.value(engine, param["Value"], location)
        except CollectionLimit as exc:
            out.reasons.add(str(exc))
            break
        except Exception:  # noqa: BLE001 -- SDK/secret parsing failures must produce fixed incomplete-collection reason codes.
            out.reasons.add("VAULT_REGION_COLLECTION_FAILED")
    return out
