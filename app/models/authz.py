from enum import IntFlag
from typing import Optional

from pydantic import BaseModel, model_validator


class Action(IntFlag):
    READ     = 1 << 0   # view/query/get
    WRITE    = 1 << 1   # create/update/modify
    DELETE   = 1 << 2   # remove/purge
    APPROVE  = 1 << 3   # approve/authorize/accept
    REJECT   = 1 << 4   # reject/deny/disallow
    EXECUTE  = 1 << 5   # run/deploy/trigger
    ASSIGN   = 1 << 6   # grant/revoke/attach
    MANAGE   = 1 << 7   # admin-level (settings, ownership)
    EXPORT   = 1 << 8   # download/report/export data
    IMPORT   = 1 << 9   # upload/import data
    ACTIVATE = 1 << 10  # enable/disable/suspend
    ARCHIVE  = 1 << 11  # archive/restore


class Authorize(BaseModel):
    action: str
    resource: Optional[str]
    check_condition: bool = False
    conditions_to_check: Optional[list]
    grant_type: str = "fga"

    @model_validator(mode="after")
    def check_grant_type(cls, values):
        if values.grant_type not in ("fga", "rba"):
            raise ValueError("grant_type must be fga or rba (fine-grained access or role based access)")

        if values.check_condition:
            if values.conditions_to_check is None:
                raise ValueError("conditions_to_check must be specified")

            pass

        return values
