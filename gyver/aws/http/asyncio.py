from http import HTTPStatus
from typing import (
    Any,
    AsyncGenerator,
    Generator,
    Literal,
    Mapping,
    Optional,
    Sequence,
    TypeVar,
    Union,
    overload,
)

import aiohttp

from gyver.attrs import define
from gyver.aws.auth import AwsAuthV4
from gyver.aws.credentials import Credentials
from gyver.aws.exc import InvalidParam
from gyver.aws.http.opts import Opts
from gyver.aws.http.response import ResponseProxy
from gyver.aws.typedef import GET, HEAD, POST, PUT, Services
from gyver.context import AsyncAdapter
from gyver.url import URL
from gyver.utils import lazyfield

T = TypeVar("T")


@define(pydantic=False)
class AsyncAuthHttpClient:
    credentials: Credentials
    service: Services
    use_default_headers: bool = True
    verify_ssl: bool = True

    @lazyfield
    def aws_auth(self):
        return AwsAuthV4(
            self.credentials, self.service, self.use_default_headers
        )

    @lazyfield
    def session(self):
        session = aiohttp.ClientSession()
        session.verify = self.verify_ssl
        return session

    @property
    def is_closed(self):
        return self.session.closed

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        await self.session.close()

    async def do(self, opts: Opts[T]) -> T:
        response: aiohttp.ClientResponse = await self._methods[opts.method](
            **opts.kwargs()
        )
        return opts.response_handler(
            ResponseProxy(
                opts.url,
                headers=response.headers,
                status_code=HTTPStatus(response.status),
                content=await response.read(),
            )
        )

    async def iter(
        self, opt_generator: Generator[Opts[T], None, None]
    ) -> AsyncGenerator[T, None]:
        for item in opt_generator:
            yield await self.do(item)

    async def exhaust(
        self, opt_generator: Generator[Opts[T], None, None]
    ) -> Sequence[T]:
        return [await self.do(item) for item in opt_generator]

    async def exhaust_with_null(
        self, opt_generator: Generator[Opts, None, None]
    ) -> None:
        await self.exhaust(opt_generator)

    async def head(
        self,
        url: URL,
        headers: Optional[Mapping[str, str]] = None,
        raw: bool = False,
    ):
        headers = headers or {}
        headers = (
            headers
            if raw
            else self.aws_auth.headers(HEAD, url, headers=headers)
        )
        return await self.session.head(url.encode(), headers=headers)

    async def get(
        self,
        url: URL,
        headers: Optional[Mapping[str, str]] = None,
        raw: bool = False,
    ):
        headers = headers or {}
        headers = (
            headers
            if raw
            else self.aws_auth.headers(GET, url, headers=headers)
        )
        return await self.session.get(url.encode(), headers=headers)

    @overload
    async def post(
        self,
        url: URL,
        data: bytes = b"",
        headers: Optional[Mapping[str, str]] = None,
        files: Optional[Mapping[str, bytes]] = None,
        raw: bool = False,
    ) -> aiohttp.ClientResponse:
        ...

    @overload
    async def post(
        self,
        url: URL,
        data: Mapping[str, Any],
        headers: Optional[Mapping[str, str]] = None,
        files: Optional[Mapping[str, bytes]] = None,
        *,
        raw: Literal[True],
    ) -> aiohttp.ClientResponse:
        ...

    async def post(
        self,
        url: URL,
        data: Union[bytes, Mapping[str, Any]] = b"",
        headers: Optional[Mapping[str, str]] = None,
        files: Optional[Mapping[str, bytes]] = None,
        raw: bool = False,
    ):
        headers = headers or {}
        if not raw:
            if not isinstance(data, bytes):
                raise InvalidParam(
                    "data", data, "Requests using data as mapping must be raw"
                )
            headers = self.aws_auth.headers(
                POST, url, headers=headers, data=data
            )
        return await self.session.post(
            url.encode(), data=data, headers=headers, files=files
        )

    async def put(
        self,
        url: URL,
        data: Union[bytes, Mapping[str, Any]] = b"",
        headers: Optional[Mapping[str, str]] = None,
        files: Optional[Mapping[str, bytes]] = None,
        raw: bool = False,
    ):
        headers = headers or {}
        if not raw:
            if not isinstance(data, bytes):
                raise InvalidParam(
                    "data", data, "Requests using data as mapping must be raw"
                )
            headers = self.aws_auth.headers(
                PUT, url, headers=headers, data=data
            )
        return await self.session.put(
            url.encode(), data=data, headers=headers, files=files
        )

    _methods = {
        GET: get,
        POST: post,
        PUT: put,
        HEAD: head,
    }


@define(pydantic=False)
class AsyncAuthHttpAdapter(AsyncAdapter[AsyncAuthHttpClient]):
    credentials: Credentials
    service: Services
    use_default_headers: bool = True
    verify_ssl: bool = True

    async def is_closed(self, client: AsyncAuthHttpClient) -> bool:
        return client.is_closed

    async def release(self, client: AsyncAuthHttpClient) -> None:
        await client.close()

    async def new(self):
        return AsyncAuthHttpClient(
            self.credentials,
            self.service,
            self.use_default_headers,
            self.verify_ssl,
        )
