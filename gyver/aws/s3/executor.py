from typing import (
    Any,
    AsyncGenerator,
    Coroutine,
    Generator,
    Generic,
    Optional,
    Sequence,
    TypeVar,
    overload,
)

from gyver.attrs import define, info
from gyver.aws.constants import constants
from gyver.aws.http import AsyncAuthHttpClient, AuthHttpClient
from gyver.aws.s3.config import S3ObjectConfig
from gyver.aws.s3.handlers import (
    Copy,
    CopyParams,
    DeleteMany,
    Get,
    List,
    ObjectTuple,
    S3Core,
    Upload,
)
from gyver.aws.s3.models import FileInfo
from gyver.url import URL
from gyver.utils import lazyfield

HttpInterface = TypeVar("HttpInterface", AsyncAuthHttpClient, AuthHttpClient)


@define
class S3Executor(Generic[HttpInterface]):
    """
    A class that provides an interface to interact with Amazon S3 objects.

    :param HttpInterface http_interface: The HTTP client interface to use for making requests to S3.
    :param S3ObjectConfig config: The configuration object to use for S3. If not provided, a default one will be used.
    """

    http_interface: HttpInterface
    config: S3ObjectConfig = info(
        default_factory=constants.config_factory.maker(S3ObjectConfig)
    )

    @lazyfield
    def core(self):
        return S3Core(self.http_interface.credentials, self.config)

    def presigned_url(
        self, object_name: str, version: Optional[str] = None
    ) -> URL:
        """Generate a presigned URL for an S3 object.

        :param object_name: Name of the object to generate a presigned URL for.
        :param version: (optional) Version ID of the object to generate a presigned URL for.
        :returns: A presigned URL for the specified object.
        """
        return Get(self.core, object_name, version).presigned_url()

    @overload
    def download(
        self: "S3Executor[AsyncAuthHttpClient]",
        object_name: str,
        version: Optional[str] = None,
    ) -> Coroutine[Any, Any, bytes]:
        ...

    @overload
    def download(
        self: "S3Executor[AuthHttpClient]",
        object_name: str,
        version: Optional[str] = None,
    ) -> bytes:
        ...

    def download(self, object_name: str, version: Optional[str] = None):
        """Download an S3 object.

        :param object_name: Name of the object to download.
        :param version: (optional) Version ID of the object to download.
        :returns: A byte string containing the contents of the specified object.
        :raises RequestFailed: If the download fails due to a non-2xx response.
        """
        get = Get(self.core, object_name, version)
        return self.http_interface.do(get.download())

    @overload
    def info(
        self: "S3Executor[AsyncAuthHttpClient]",
        object_name: str,
        version: Optional[str] = None,
    ) -> Coroutine[Any, Any, FileInfo]:
        ...

    @overload
    def info(
        self: "S3Executor[AuthHttpClient]",
        object_name: str,
        version: Optional[str] = None,
    ) -> FileInfo:
        ...

    def info(
        self,
        object_name: str,
        version: Optional[str] = None,
    ):
        """Get information about an S3 object.

        :param object_name: Name of the object to get information about.
        :param version: (optional) Version ID of the object to get information about.
        :returns: A `FileInfo` object containing information about the specified object.
        :raises RequestFailed: If the request fails due to a non-2xx response.
        :raises NotFound: If the specified object is not found.
        """
        get = Get(self.core, object_name, version)
        return self.http_interface.do(get.info())

    @overload
    def delete(
        self: "S3Executor[AsyncAuthHttpClient]",
        object_name: str,
        version: Optional[str] = None,
    ) -> Coroutine[Any, Any, None]:
        ...

    @overload
    def delete(
        self: "S3Executor[AuthHttpClient]",
        object_name: str,
        version: Optional[str] = None,
    ) -> None:
        ...

    def delete(
        self,
        object_name: str,
        version: Optional[str] = None,
    ):
        """
        Deletes an object from the S3 service.

        :param object_name: The name of the object to be deleted.
        :param version: The version of the object to be deleted. If not specified,
            the latest version will be deleted. (default None)
        :raises RequestFailed: If the HTTP request fails.
        :return: None if the request was successful.
        """
        delete = DeleteMany(self.core, (ObjectTuple(object_name, version),))
        return self.http_interface.do(delete.delete())

    @overload
    def delete_many(
        self: "S3Executor[AsyncAuthHttpClient]",
        objects: Sequence[ObjectTuple],
    ) -> Coroutine[Any, Any, None]:
        ...

    @overload
    def delete_many(
        self: "S3Executor[AuthHttpClient]",
        objects: Sequence[ObjectTuple],
    ) -> None:
        ...

    def delete_many(
        self,
        objects: Sequence[ObjectTuple],
    ):
        """
        Deletes multiple objects from the S3 service.

        :param objects: A sequence of ObjectTuple instances representing the objects
            to be deleted.
        :raises RequestFailed: If the HTTP request fails.
        :return: None if the request was successful.
        """
        delete = DeleteMany(self.core, objects)
        return self.http_interface.do(delete.delete())

    @overload
    def upload(
        self: "S3Executor[AsyncAuthHttpClient]",
        object_name: str,
        content: bytes,
        *,
        content_type: Optional[str] = None,
        request_timeout_seconds: int = 30 * 60,
    ) -> Coroutine[Any, Any, None]:
        ...

    @overload
    def upload(
        self: "S3Executor[AuthHttpClient]",
        object_name: str,
        content: bytes,
        *,
        content_type: Optional[str] = None,
        request_timeout_seconds: int = 30 * 60,
    ) -> None:
        ...

    def upload(
        self,
        object_name: str,
        content: bytes,
        *,
        content_type: Optional[str] = None,
        request_timeout_seconds: int = 30 * 60,
    ):
        """
        Uploads the given content to S3 with the given object name.

        :param object_name: The object name of the content to upload.
        :param content: The content to upload.
        :param content_type: The content type of the content to upload.
        :param request_timeout_seconds: The maximum time (in seconds) to wait for the request to complete.
        :raises RequestFailed: If the upload request failed (i.e. the HTTP status code is not 204).
        :return: If the executor is asynchronous, returns an awaitable that resolves to None once the upload is complete.
            Otherwise, returns None.
        """
        upload = Upload(
            self.core,
            object_name,
            content,
            content_type,
            request_timeout_seconds,
        )
        return self.http_interface.do(upload.upload())

    @overload
    def copy(
        self: "S3Executor[AsyncAuthHttpClient]",
        source: CopyParams,
        target: CopyParams,
        *,
        prevalidate: bool = True,
    ) -> Coroutine[Any, Any, None]:
        ...

    @overload
    def copy(
        self: "S3Executor[AuthHttpClient]",
        source: CopyParams,
        target: CopyParams,
        *,
        prevalidate: bool = True,
    ) -> None:
        ...

    def copy(
        self,
        source: CopyParams,
        target: CopyParams,
        *,
        prevalidate: bool = True,
    ):
        """Copy an object from source to target location within possibly different buckets.

        :param source: Parameters of the source object to be copied.
        :param target: Parameters of the target object to be created.
        :param prevalidate: Whether to validate the existence of the source object before copying. Default is True.
        :raises: RequestFailed error if the request fails.
        :raises NotFound: If the specified object is not found and prevalidate was True.
        :returns: A sequence of None or a coroutine that yields a sequence of None.
        """
        copyobj = Copy(self.core, prevalidate)
        return self.http_interface.exhaust_with_null(
            copyobj.copy(source, target)
        )

    @overload
    def copy_from(
        self: "S3Executor[AsyncAuthHttpClient]",
        source: CopyParams,
        target_name: Optional[str] = None,
        *,
        prevalidate: bool = True,
    ) -> Coroutine[Any, Any, None]:
        ...

    @overload
    def copy_from(
        self: "S3Executor[AuthHttpClient]",
        source: CopyParams,
        target_name: Optional[str] = None,
        *,
        prevalidate: bool = True,
    ) -> None:
        ...

    def copy_from(
        self,
        source: CopyParams,
        target_name: Optional[str] = None,
        *,
        prevalidate: bool = True,
    ):
        """Copy an object from the source location to a target location in the bucket from config.

        :param source: Parameters of the source object to be copied.
        :param target_name: The name of the target object. If not specified, the name of the source object is used.
        :param prevalidate: Whether to validate the existence of the source object before copying. Default is True.
        :raises: RequestFailed error if the request fails.
        :raises: NotFound If the specified object is not found and prevalidate was True.
        :returns: A sequence of None or a coroutine that yields a sequence of None.
        """
        copyobj = Copy(self.core, prevalidate)
        return self.http_interface.exhaust_with_null(
            copyobj.copy_from(source, target_name)
        )

    @overload
    def copy_to(
        self: "S3Executor[AsyncAuthHttpClient]",
        target: CopyParams,
        source_name: Optional[str] = None,
        *,
        prevalidate: bool = True,
    ) -> Coroutine[Any, Any, None]:
        ...

    @overload
    def copy_to(
        self: "S3Executor[AuthHttpClient]",
        target: CopyParams,
        source_name: Optional[str] = None,
        *,
        prevalidate: bool = True,
    ) -> None:
        ...

    def copy_to(
        self,
        target: CopyParams,
        source_name: Optional[str] = None,
        *,
        prevalidate: bool = True,
    ):
        """Copy an object from the source location in the config bucket to a target location.

        :param target: Parameters of the target object to be created.
        :param source_name: The name of the source object. If not specified, the name of the target object is used.
        :param prevalidate: Whether to validate the existence of the source object before copying. Default is True.
        :raises: RequestFailed error if the request fails.
        :raises: NotFound If the specified object is not found and prevalidate was True.
        :returns: A sequence of None or a coroutine that yields a sequence of None.
        """
        copyobj = Copy(self.core, prevalidate)
        return self.http_interface.exhaust_with_null(
            copyobj.copy_to(target, source_name)
        )

    @overload
    def list_objects(
        self: "S3Executor[AsyncAuthHttpClient]",
        prefix: Optional[str] = None,
        chunksize: int = constants.max_chunksize,
    ) -> AsyncGenerator[list[FileInfo], None]:
        ...

    @overload
    def list_objects(
        self: "S3Executor[AuthHttpClient]",
        prefix: Optional[str] = None,
        chunksize: int = constants.max_chunksize,
    ) -> Generator[list[FileInfo], None, None]:
        ...

    def list_objects(
        self,
        prefix: Optional[str] = None,
        chunksize: int = constants.max_chunksize,
    ):
        """
        Lists objects in the S3 bucket, returning a generator that yields chunks of objects.

        :param prefix: Optional prefix to filter objects by.
        :param chunksize: Optional size of each chunk (defaults to `constants.max_chunksize` = 1000).
        :return: A generator that yields lists of `FileInfo` objects.
        :raises RequestFailed: If the request to the S3 API fails.
        """
        list_obj = List(self.core, prefix, chunksize)
        return self.http_interface.iter(list_obj.fetch())
