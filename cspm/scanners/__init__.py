from abc import ABC, abstractmethod

import boto3
from botocore.config import Config

from cspm.models import Finding

RETRY_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})


class BaseScanner(ABC):
    service_name: str = ""

    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region = region

    @abstractmethod
    def run(self) -> list[Finding]:
        ...

    def _get_client(self, service: str):
        return self.session.client(
            service, region_name=self.region, config=RETRY_CONFIG
        )


SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    SCANNER_REGISTRY[cls.service_name] = cls
    return cls
