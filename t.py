import asyncio
from gyver.aws.credentials import Credentials
from gyver.aws.http import AsyncAuthHttpAdapter
from gyver.aws.s3.config import S3ObjectConfig
from gyver.aws.s3.executor import S3Executor
from gyver.aws.typedef import Services
from gyver.context import AsyncContext

credentials = Credentials(
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
    endpoint_url="http://localhost.localstack.cloud:4566",
)

object_name = "pyrightconfig.json"
adapter = AsyncAuthHttpAdapter(credentials, Services.S3)
context = AsyncContext(adapter)


async def main():
    with open(object_name, "rb") as stream:
        content = stream.read()
    async with context as client:
        executor = S3Executor(client, S3ObjectConfig(bucket_name="test"))
        await executor.upload(object_name, content)
        async for obj in executor.list_objects():
            print(obj)
        print(await executor.info(object_name))


asyncio.run(main())
