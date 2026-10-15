"""AWS IAM key actions for a verified remediation session."""

from datetime import UTC, datetime

from cremore.remediation.action_plans import (
    _KEY_STATUS_ABSENT,
    ActionPlanError,
    KeyActionAdapter,
)
from cremore_aws_provider.aws_pagination import iam_pages


class Boto3KeyActionAdapter(KeyActionAdapter):
    def __init__(self, iam) -> None:
        self.iam = iam

    def key_status(self, user_name: str, key_id: str) -> str:
        for page in iam_pages(self.iam.list_access_keys, UserName=user_name):
            if not isinstance(page, dict) or not isinstance(page.get("AccessKeyMetadata"), list):
                raise ActionPlanError("KEY_LIST_INCOMPLETE")
            for meta in page["AccessKeyMetadata"]:
                if not isinstance(meta, dict) or not meta.get("AccessKeyId"):
                    raise ActionPlanError("KEY_LIST_INCOMPLETE")
                if meta.get("AccessKeyId") == key_id:
                    status = meta.get("Status")
                    if status not in ("Active", "Inactive"):
                        raise ActionPlanError("KEY_STATE_UNKNOWN")
                    return status
        return _KEY_STATUS_ABSENT

    def has_newer_key(self, user_name: str, key_id: str, since: datetime) -> bool:
        for page in iam_pages(self.iam.list_access_keys, UserName=user_name):
            if not isinstance(page, dict) or not isinstance(page.get("AccessKeyMetadata"), list):
                raise ActionPlanError("KEY_LIST_INCOMPLETE")
            for meta in page["AccessKeyMetadata"]:
                if not isinstance(meta, dict) or not isinstance(meta.get("AccessKeyId"), str) or not meta["AccessKeyId"]:
                    raise ActionPlanError("KEY_LIST_INCOMPLETE")
                if meta["AccessKeyId"] == key_id:
                    continue
                created = meta.get("CreateDate")
                if not isinstance(created, datetime) or created.tzinfo is None:
                    raise ActionPlanError("KEY_LIST_INCOMPLETE")
                if created.astimezone(UTC) >= since:
                    return True
        return False

    def disable_key(self, user_name: str, key_id: str) -> None:
        self.iam.update_access_key(UserName=user_name, AccessKeyId=key_id, Status="Inactive")

    def delete_key(self, user_name: str, key_id: str) -> None:
        self.iam.delete_access_key(UserName=user_name, AccessKeyId=key_id)


def build_key_action_adapter_factory(region: str):
    """``factory(session)``: the adapter for the plan account's verified remediation session."""

    def factory(session) -> KeyActionAdapter:
        return Boto3KeyActionAdapter(session.client("iam", region))

    return factory
