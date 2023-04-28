import base64
import io
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
import mimetypes
import re
from typing import Generator, NamedTuple, Optional, Sequence, cast
from xml.etree import ElementTree as ET

from gyver.attrs import define
from gyver.utils import json
from gyver.aws.auth import AwsAuthV4, amz_dateformat
from gyver.aws.constants import constants
from gyver.aws.credentials import Credentials
from gyver.aws.exc import (
    InvalidParam,
    NotFound,
    RequestFailed,
    UnexpectedResponse,
)
from gyver.aws.http import Opts
from gyver.aws.http.response import ResponseProxy
from gyver.aws.s3.config import S3ObjectConfig
from gyver.aws.s3.models import FileInfo, UploadParams
from gyver.aws.typedef import GET, HEAD, POST, PUT, Methods, Services
from gyver.url import URL, Path
from gyver.utils import lazyfield

HOST_TEMPLATE = "https://{bucket}.s3.{region}.amazonaws.com"

DAY = 86400
WEEK = 604800


def response_failed_handler(response_proxy: ResponseProxy):
    if not response_proxy.ok:
        raise RequestFailed(response_proxy)


@define
class S3Core:
    credentials: Credentials
    config: S3ObjectConfig

    @lazyfield
    def base_uri(self) -> URL:
        if self.credentials.host:
            return URL(self.credentials.host)
        return URL(
            HOST_TEMPLATE.format(
                bucket=self.config.bucket_name, region=self.credentials.region
            )
        )

    def get_uri_copy(self) -> URL:
        return self.base_uri.copy()

    @lazyfield
    def aws_auth(self) -> AwsAuthV4:
        return AwsAuthV4(self.credentials, Services.S3)


@define
class Get:
    core: S3Core
    object_name: str
    version: Optional[str] = None

    def new_url(self):
        return self.core.get_uri_copy().add(path=self.object_name)

    def presigned_url(self, expires: int = DAY):
        url = self._append_get_object_params(GET, expires)
        if self.version:
            url.add({"v": self.version})
        return url

    def _download_handler(self, proxy: ResponseProxy):
        response_failed_handler(proxy)
        return proxy.content

    def download(self) -> Opts[bytes]:
        url = self.presigned_url()
        return Opts(self._download_handler, GET, url=url, raw=True)

    def _info_handler(self, proxy: ResponseProxy):
        if not proxy.ok:
            if proxy.status_code == HTTPStatus.NOT_FOUND:
                raise NotFound(self.object_name, Services.S3)
            raise RequestFailed(proxy)
        return FileInfo.parse_obj(
            {
                "key": self.object_name,
                "last_modified": datetime.strptime(
                    proxy.headers["Last-Modified"],
                    "%a, %d %b %Y %H:%M:%S GMT",
                ),
                "size": proxy.headers["Content-Length"],
                "e_tag": proxy.headers["ETag"].strip("\"'"),
                "storage_class": proxy.headers.get(
                    "x-amz-storage-class", "UNKNOWN"
                ),
            }
        )

    def info(self) -> Opts[FileInfo]:
        url = self.new_url()
        return Opts(self._info_handler, HEAD, url)

    def _append_get_object_params(self, method: Methods, expires: int) -> URL:
        if not (1 <= expires <= WEEK):
            raise InvalidParam(
                "expires",
                expires,
                f"Expires must be greater than 1 and lower than a {WEEK=}",
            )
        timestamp = datetime.now(timezone.utc)
        url = self.new_url().add(
            {
                "X-Amz-Algorithm": constants.aws_algorithm,
                "X-Amz-Credential": self.core.aws_auth.make_credential(
                    timestamp
                ),
                "X-Amz-Date": amz_dateformat(timestamp),
                "X-Amz-Expires": str(expires),
                "X-Amz-SignedHeaders": "host",
            }
        )
        _, signature = self.core.aws_auth.make_signature(
            method,
            url,
            "UNSIGNED-PAYLOAD",
            timestamp,
            {"host": url.netloc.encode()},
        )
        url.add({"X-Amz-Signature": signature})
        return url


class ObjectTuple(NamedTuple):
    object_name: str
    version: Optional[str] = None


@define
class DeleteMany:
    core: S3Core
    objects: Sequence[ObjectTuple]

    def delete(self) -> Opts[None]:
        url = self.core.get_uri_copy().add({"delete": ""}, path="/")
        payload = self._build_payload()
        return Opts(
            response_failed_handler,
            POST,
            url,
            data=payload,
            headers={"content-type": "text/xml"},
        )

    def _build_payload(self):
        root = ET.Element("Delete", xmlns=constants.xmlns)
        for item in self.objects:
            object_el = ET.SubElement(root, "Object")
            ET.SubElement(object_el, "Key").text = item.object_name
            if item.version:
                ET.SubElement(object_el, "VersionId").text = item.version
        et = ET.ElementTree(root)
        stream = io.BytesIO()
        et.write(
            stream, encoding=constants.default_encoding, xml_declaration=True
        )
        return stream.getvalue()


@define
class Upload:
    core: S3Core
    object_name: str
    content: bytes
    content_type: Optional[str] = None
    request_timeout_seconds: int = 30 * 60

    @lazyfield
    def mimetype(self):
        return (
            self.content_type
            or mimetypes.guess_type(self.object_name.strip("/"))[0]
            or constants.default_mimetype
        )

    @lazyfield
    def content_size(self):
        return len(self.content)

    def upload(self):
        parts = self._fileparts()
        fields = self._put_object_fields(
            parts[0] if len(parts) > 1 else "",
            parts[-1],
            expires=datetime.now(timezone.utc)
            + timedelta(seconds=self.request_timeout_seconds),
        )
        return Opts(
            self._upload_handler,
            POST,
            self.core.base_uri,
            data=fields,
            files={"file": self.content},
            raw=True,
        )

    def _upload_handler(self, response_proxy: ResponseProxy):
        if response_proxy.status_code is not HTTPStatus.NO_CONTENT:
            raise RequestFailed(response_proxy)

    def _fileparts(self):
        object_name = self.object_name.strip("/")
        return object_name.rsplit("/", 1)

    def _put_object_fields(
        self,
        path: str,
        filename: str,
        content_disp: bool = True,
        expires: Optional[datetime] = None,
    ) -> UploadParams:
        key = "/".join(item.strip("/") for item in (path, filename))
        policy_conditions = [
            {"bucket": self.core.config.bucket_name},
            {"key": key},
            {"content-type": self.mimetype},
            ["content-length-range", self.content_size, self.content_size],
        ]
        content_disposition_fields = {}
        if content_disp:
            policy_conditions.append(
                content_disposition_fields := {
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
        timestamp = datetime.now(timezone.utc)
        policy_conditions.extend(self._upload_additional_conditions(timestamp))

        expiration = expires or timestamp + timedelta(seconds=60)
        policy = {
            "expiration": f"{expiration:%Y-%m-%dT%H:%M:%SZ}",
            "conditions": policy_conditions,
        }
        b64_policy = base64.b64encode(json.dumps(policy).encode()).decode()
        return cast(
            UploadParams,
            {
                "Key": key,
                "Content-Type": self.mimetype,
                **content_disposition_fields,
                "Policy": b64_policy,
                **self._signed_upload_fields(timestamp, b64_policy),
            },
        )

    def _upload_additional_conditions(self, timestamp: datetime):
        return [
            {
                "X-Amz-Credential": self.core.aws_auth.make_credential(
                    timestamp
                )
            },
            {"X-Amz-Algorithm": constants.aws_algorithm},
            {"X-Amz-Date": amz_dateformat(timestamp)},
        ]

    def _signed_upload_fields(self, timestamp: datetime, policy: str):
        return {
            "X-Amz-Algorithm": constants.aws_algorithm,
            "X-Amz-Credential": self.core.aws_auth.make_credential(timestamp),
            "X-Amz-Date": amz_dateformat(timestamp),
            "X-Amz-Signature": self.core.aws_auth.aws4_sign_string(
                policy, timestamp
            ),
        }


class CopyParams(NamedTuple):
    object_name: str
    bucket: str


@define
class Copy:
    core: S3Core
    prevalidate: bool = True

    def copy(
        self, source: CopyParams, target: CopyParams
    ) -> Generator[Opts, None, None]:
        url = URL(
            HOST_TEMPLATE.format(
                bucket=target.bucket, region=self.core.credentials.region
            )
        ).add(path=target.object_name)
        if self.prevalidate:
            yield Get(
                S3Core(
                    self.core.credentials,
                    S3ObjectConfig(bucket_name=source.bucket),
                ),
                source.object_name,
            ).info()
        yield Opts(
            response_failed_handler,
            PUT,
            url,
            headers={
                "x-amz-copy-source": Path(source.bucket)
                .add(source.object_name)
                .encode()
            },
        )

    def copy_from(self, source: CopyParams, target_name: Optional[str] = None):
        target = CopyParams(
            target_name or source.object_name, self.core.config.bucket_name
        )
        return self.copy(source, target)

    def copy_to(self, target: CopyParams, source_name: Optional[str] = None):
        source = CopyParams(
            source_name or target.object_name, self.core.config.bucket_name
        )
        return self.copy(source, target)


@define(frozen=False)
class TokenHolder:
    continuation_token: Optional[str] = None
    should_break: bool = False


xmlns_re = re.compile(f' xmlns="{re.escape(constants.xmlns)}"'.encode())


@define
class List:
    core: S3Core
    prefix: Optional[str] = None
    chunksize: int = constants.max_chunksize

    def __post_init__(self):
        if not (1 <= self.chunksize <= constants.max_chunksize):
            raise InvalidParam(
                "chunksize",
                self.chunksize,
                "Chunksize must be greater "
                f"than 1 and lesser than {constants.max_chunksize}",
            )

    def new_url(self):
        return self.core.get_uri_copy().add(
            {"list-type": "2", "max-keys": str(self.chunksize)}, path="/"
        )

    def fetch(self):
        base_url = self.new_url()
        token_holder = TokenHolder()
        fetch_handler = self._get_fetch_handler(token_holder)
        while True:
            url = self._prepare_url(base_url, token_holder.continuation_token)
            yield Opts(fetch_handler, GET, url)
            if token_holder.should_break:
                break

    def _get_fetch_handler(self, token_holder: TokenHolder):
        def _fetch_handler(response_proxy: ResponseProxy) -> list[FileInfo]:
            response_failed_handler(response_proxy)
            nonlocal token_holder
            xml_content = ET.fromstring(
                xmlns_re.sub(b"", response_proxy.content)
            )
            results = []
            for contents in xml_content.findall("Contents"):
                results.append(
                    FileInfo.parse_obj(
                        {items.tag: items.text for items in contents}
                    )
                )
            if self._list_is_exhausted(xml_content):
                token_holder.should_break = True
            if (t := xml_content.find("NextContinuationToken")) is not None:
                token_holder.continuation_token = t.text
            else:
                raise UnexpectedResponse("unexpected response from S3")
            return results

        return _fetch_handler

    def _prepare_url(
        self,
        base_url: URL,
        continuation_token: Optional[str],
    ):
        url = base_url.copy()
        if self.prefix:
            prefix = self.prefix.removeprefix("/")
            url.add({"prefix": prefix})
        if continuation_token:
            url.add({"continuation-token": continuation_token})
        return url

    def _list_is_exhausted(self, xml_content: ET.Element):
        return (
            t := xml_content.find("IsTruncated")
        ) is not None and t.text == "false"
