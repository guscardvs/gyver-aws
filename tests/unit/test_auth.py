from datetime import datetime, timezone

from gyver.url import URL
import pytest
from gyver.aws import constants

from gyver.aws.auth import AwsAuthV4, amz_dateformat
from gyver.aws.credentials import Credentials
from gyver.aws.typedef import GET, PUT, Services
from botocore.auth import S3SigV4Auth
from botocore.credentials import Credentials as BCredentials
from botocore.awsrequest import AWSRequest

now = datetime.fromisoformat("2013-05-24T00:00:00")
now.replace(tzinfo=timezone.utc)


@pytest.fixture
def botocore_signer(credential: Credentials):
    botocore_credentials = BCredentials(
        credential.access_key_id, credential.secret_access_key
    )
    return S3SigV4Auth(botocore_credentials, "s3", credential.region)


def make_botocore_signature(aws_request: AWSRequest, signer: S3SigV4Auth):
    signer._inject_signature_to_request(
        aws_request,
        signer.signature(
            signer.string_to_sign(
                aws_request, signer.canonical_request(aws_request)
            ),
            aws_request,
        ),
    )
    return aws_request.headers["authorization"]


def test_each_step_with_botocore(
    credential: Credentials, botocore_signer: S3SigV4Auth
):
    gyver_sigv4 = AwsAuthV4(credential, Services.S3)

    url = URL("https://examplebucket.s3.amazonaws.com/test.txt")
    method = GET
    headers = gyver_sigv4._base_headers(
        url,
        {"range": "bytes=0-9"},
        b"",
        constants.constants.content_type,
        now,
    )
    aws_request = AWSRequest(method, url.encode(), headers)
    aws_request.context = {"timestamp": amz_dateformat(now)}

    signed_headers, canonical_request = gyver_sigv4._get_canonical_request(
        method,
        url,
        headers,
        gyver_sigv4.hash_payload(b""),
    )
    assert botocore_signer.canonical_request(aws_request) == canonical_request

    assert botocore_signer.credential_scope(
        aws_request
    ) == gyver_sigv4._credential_scope(now)

    assert (
        ";".join(botocore_signer.headers_to_sign(aws_request))
        == signed_headers
    )

    assert botocore_signer.string_to_sign(
        aws_request, botocore_signer.canonical_request(aws_request)
    ) == gyver_sigv4._create_sign_string(
        now, gyver_sigv4.hash_payload(canonical_request.encode())
    )

    assert botocore_signer.signature(
        botocore_signer.string_to_sign(
            aws_request, botocore_signer.canonical_request(aws_request)
        ),
        aws_request,
    ) == gyver_sigv4.aws4_sign_string(
        gyver_sigv4._create_sign_string(
            now, gyver_sigv4.hash_payload(canonical_request.encode())
        ),
        now,
    )
    make_botocore_signature(aws_request, botocore_signer)

    headers = gyver_sigv4.headers(
        method, url, headers={"range": "bytes=0-9"}, now=now
    )

    assert aws_request.headers["authorization"] == headers["authorization"]


def test_aws_auth_returns_expected_result_get_case(
    credential: Credentials, botocore_signer: S3SigV4Auth
):
    aws_auth_v4 = AwsAuthV4(credential, Services.S3)
    url = URL("https://examplebucket.s3.amazonaws.com/test.txt")
    aws_request = AWSRequest(
        GET,
        url.encode(),
        aws_auth_v4._base_headers(
            url,
            {"range": "bytes=0-9"},
            b"",
            constants.constants.content_type,
            now,
        ),
    )
    aws_request.context = {"timestamp": amz_dateformat(now)}

    expected = make_botocore_signature(aws_request, botocore_signer)
    headers = aws_auth_v4.headers(
        GET,
        url,
        now=now,
        headers={"range": "bytes=0-9"},
    )
    assert headers["authorization"] == expected


def test_aws_auth_returns_expected_result_get_lifecycle_case(
    credential: Credentials, botocore_signer: S3SigV4Auth
):
    aws_auth_v4 = AwsAuthV4(credential, Services.S3)
    url = URL("https://examplebucket.s3.amazonaws.com/?lifecycle")
    aws_request = AWSRequest(
        GET,
        url.encode(),
        aws_auth_v4._base_headers(
            url,
            {},
            b"",
            constants.constants.content_type,
            now,
        ),
    )
    aws_request.context = {"timestamp": amz_dateformat(now)}

    expected = make_botocore_signature(aws_request, botocore_signer)
    headers = aws_auth_v4.headers(
        GET,
        url,
        now=now,
    )
    assert headers["authorization"] == expected


def test_aws_auth_returns_expected_result_put_object_case(
    credential: Credentials, botocore_signer: S3SigV4Auth
):
    body = "Welcome to Amazon S3.".encode()
    aws_auth_v4 = AwsAuthV4(credential, Services.S3, use_default_headers=False)
    url = URL("https://examplebucket.s3.amazonaws.com/test$file.text")
    aws_request = AWSRequest(
        PUT,
        url.encode(),
        aws_auth_v4._base_headers(
            url,
            {
                "date": "Fri, 24 May 2013 00:00:00 GMT",
                "x-amz-storage-class": "REDUCED_REDUNDANCY",
            },
            body,
            constants.constants.content_type,
            now,
        ),
        body,
    )
    aws_request.context = {"timestamp": amz_dateformat(now)}
    expected = make_botocore_signature(aws_request, botocore_signer)
    headers = aws_auth_v4.headers(
        PUT,
        URL("https://examplebucket.s3.amazonaws.com/test$file.text"),
        now=now,
        headers={
            "date": "Fri, 24 May 2013 00:00:00 GMT",
            "x-amz-storage-class": "REDUCED_REDUNDANCY",
        },
        data=body,
    )
    assert headers["authorization"] == expected


def test_aws_auth_returns_expected_result_list_object_case(
    credential: Credentials, botocore_signer: S3SigV4Auth
):
    aws_auth_v4 = AwsAuthV4(credential, Services.S3)
    url = URL("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J")
    aws_request = AWSRequest(
        GET,
        "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
        aws_auth_v4._base_headers(
            url,
            {},
            b"",
            constants.constants.content_type,
            now,
        ),
    )
    aws_request.context = {"timestamp": amz_dateformat(now)}

    expected = make_botocore_signature(aws_request, botocore_signer)
    headers = aws_auth_v4.headers(
        GET,
        url,
        now=now,
    )
    assert headers["authorization"] == expected
