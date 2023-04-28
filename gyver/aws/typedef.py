from enum import Enum


class Methods(str, Enum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"

    def __str__(self):
        return self.value


GET = Methods.GET
HEAD = Methods.HEAD
POST = Methods.POST
PUT = Methods.PUT
PATCH = Methods.PATCH
DELETE = Methods.DELETE


class Services(str, Enum):
    S3 = "s3"

    def __str__(self):
        return self.value
