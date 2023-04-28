from gyver.model import Model
from gyver.utils import strings


class AwsModel(Model):
    class Config:
        alias_generator = strings.upper_camel
