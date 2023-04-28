from http import HTTPStatus
from typing import Mapping

from gyver.attrs import define
from gyver.url import URL


@define
class ResponseProxy:
    url: URL
    headers: Mapping[str, str]
    status_code: HTTPStatus
    content: bytes

    @property
    def ok(self):
        return self.status_code < HTTPStatus.BAD_REQUEST
