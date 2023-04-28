from gyver.config import as_config


@as_config
class S3ObjectConfig:
    bucket_name: str
