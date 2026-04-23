import os

import pytest

from tests.schema.validate import load_schemas, validators


@pytest.fixture(scope="session")
def schemas():
    return load_schemas()


@pytest.fixture(scope="session")
def schema_validators(schemas):
    return validators(schemas)


@pytest.fixture(scope="session")
def strict_hashes() -> bool:
    return os.environ.get("TRACE_STRICT_HASHES") == "1"
