from http import HTTPStatus
from typing import Any, Protocol

from gyver.exc import GyverError
from gyver.url import URL


class GyverAwsError(GyverError):
    """Base exception for gyver-aws"""


class InvalidParam(GyverAwsError):
    def __init__(self, name: str, val: Any, message: str) -> None:
        super().__init__(name, val, message)
        self.name = name
        self.val = val
        self.message = message


class ResponseProtocol(Protocol):
    url: URL
    status_code: HTTPStatus


class RequestFailed(GyverAwsError):
    def __init__(self, response: ResponseProtocol) -> None:
        super().__init__(response.status_code, response.url.encode())
        self.response = response


class NotFound(GyverAwsError):
    def __init__(self, object_name: str, service_name: str) -> None:
        super().__init__(object_name, service_name)


class UnexpectedResponse(GyverAwsError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
