from typing import (Any, Callable, Generator, Generic, Mapping, Optional,
                    TypeVar, Union)

from gyver.attrs import define
from gyver.url import URL

from gyver.aws.http.response import ResponseProxy
from gyver.aws.typedef import Methods

T = TypeVar("T")


@define
class Opts(Generic[T]):
    response_handler: Callable[[ResponseProxy], T]
    method: Methods
    url: URL
    data: Union[bytes, Mapping[str, Any]] = b""
    headers: Optional[Mapping[str, str]] = None
    files: Optional[Mapping[str, bytes]] = None
    raw: bool = False

    def kwargs(self):
        dictself = {
            "url": self.url,
            "raw": self.raw,
            "headers": self.headers,
        }
        if self.files is not None:
            dictself["files"] = self.files
        if self.data:
            dictself["data"] = self.data
        return dictself


@define
class OptsGenerator(Generic[T]):
    generator: Generator[T, None, None]
    returns_none: bool
