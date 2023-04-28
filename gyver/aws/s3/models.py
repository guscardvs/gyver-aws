from datetime import datetime
from enum import Enum
from typing import TypedDict

from typing_extensions import NotRequired

from gyver.aws.model import AwsModel

UploadParams = TypedDict(
    "UploadParams",
    {
        "Key": str,
        "Content-Type": str,
        "Content-Disposition": NotRequired[str],
        "Policy": str,
        "X-Amz-Algorithm": str,
        "X-Amz-Credential": str,
        "X-Amz-Date": str,
        "X-Amz-Signature": str,
    },
)


class StorageClass(Enum):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    GLACIER = "GLACIER"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"
    UNKNOWN = "UNKNOWN"


class FileInfo(AwsModel):
    key: str
    last_modified: datetime
    size: int
    e_tag: str
    storage_class: StorageClass
