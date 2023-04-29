import hashlib
import hmac
from base64 import b64encode
from binascii import hexlify
from datetime import date, datetime, timezone
from functools import reduce
from typing import Mapping, Optional

from gyver.attrs import define
from gyver.url import URL

from .constants import constants
from .credentials import Credentials
from .typedef import Methods, Services


@define(pydantic=False)
class AwsAuthV4:
    credentials: Credentials
    _service: Services
    use_default_headers: bool = True

    @property
    def service(self):
        return self._service.value

    def headers(
        self,
        method: Methods,
        url: URL,
        *,
        headers: Optional[Mapping[str, str]] = None,
        data: Optional[bytes] = None,
        content_type: Optional[str] = None,
        now: Optional[datetime] = None,
    ):
        now = now or datetime.now(timezone.utc)
        data = data or b""
        content_type = content_type or constants.content_type
        payload_hash = self.hash_payload(data)
        headers = self._base_headers(url, headers or {}, data, content_type, now)
        signed_headers, signature = self.make_signature(
            method, url, payload_hash, now, headers
        )
        credential = self.make_credential(now)
        authorization_header = (
            f"{constants.aws_algorithm} Credential={credential}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
        return headers | {
            "authorization": authorization_header,
            "x-amz-content-sha256": payload_hash,
        }

    def hash_payload(self, payload: Optional[bytes] = None) -> str:
        return hashlib.sha256(payload or b"").hexdigest()

    def _base_headers(
        self,
        url: URL,
        headers: Mapping[str, str],
        data: bytes,
        content_type: str,
        now: datetime,
    ):
        base_headers = {
            "host": url.netloc.encode(),
            "x-amz-date": amz_dateformat(now),
        }
        if self.use_default_headers:
            base_headers |= {
                "content-md5": b64encode(hashlib.md5(data).digest()).decode(),
                "content-type": content_type,
            }
        result = base_headers | headers
        return {key: result[key] for key in sorted(result)}

    def make_signature(
        self,
        method: Methods,
        url: URL,
        payload_hash: str,
        now: datetime,
        headers: Optional[Mapping[str, str]] = None,
    ) -> tuple[str, str]:
        now = now
        headers = headers or {}
        signed_headers, canonical_request = self._get_canonical_request(
            method, url, headers, payload_hash
        )
        signed_string = self._create_sign_string(
            now, hashlib.sha256(canonical_request.encode()).hexdigest()
        )
        return signed_headers, self.aws4_sign_string(signed_string, now)

    def _get_canonical_request(
        self,
        method: Methods,
        url: URL,
        headers: Mapping[str, str],
        payload_hash: str,
    ) -> tuple[str, str]:
        header_keys = sorted(headers)
        signed_headers = ";".join(header_keys)
        return signed_headers, "\n".join(
            (
                method,
                url.path.encode(),
                url.query.encode(),
                "\n".join(
                    ":".join((str.lower(key), str.strip(headers[key])))
                    for key in header_keys
                )
                + "\n",
                signed_headers,
                payload_hash,
            )
        )

    def _create_sign_string(self, now: datetime, hashed_canonical: str) -> str:
        return "\n".join(
            (
                constants.aws_algorithm,
                amz_dateformat(now),
                self._credential_scope(now),
                hashed_canonical,
            )
        )

    def _credential_scope(self, now: date):
        return "/".join(
            (
                _make_aws_date(now),
                self.credentials.region,
                self.service,
                constants.aws_request,
            )
        )

    def aws4_sign_string(self, string_to_sign: str, now: datetime) -> str:
        key_parts = (
            b"AWS4" + self.credentials.secret_access_key.encode(),
            _make_aws_date(now),
            self.credentials.region,
            self.service,
            constants.aws_request,
            string_to_sign,
        )
        signature_bytes: bytes = reduce(
            _aws4_reduce_signature, key_parts  # type: ignore
        )
        return hexlify(signature_bytes).decode()

    def make_credential(self, now: date):
        return "/".join((self.credentials.access_key_id, self._credential_scope(now)))


def _aws4_reduce_signature(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _make_aws_date(now: date):
    # make sure to use date, because datetime is a date child
    return "".join(date.isoformat(now).split("-"))


def amz_dateformat(dt: datetime):
    return dt.strftime("%Y%m%dT%H%M%SZ")
