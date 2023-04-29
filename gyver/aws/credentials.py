from typing import Optional

from gyver.config import as_config


@as_config
class Credentials:
    __prefix__ = "aws"

    access_key_id: str
    secret_access_key: str
    region: str
    endpoint_url: Optional[str] = None
