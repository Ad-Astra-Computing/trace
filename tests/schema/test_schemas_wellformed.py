"""Each schema file must itself be a valid Draft 2020-12 schema."""

import pytest
from jsonschema import Draft202012Validator

from tests.schema.validate import SCHEMA_FILES


@pytest.mark.parametrize("name,path", list(SCHEMA_FILES.items()))
def test_schema_is_well_formed_draft_2020_12(name, path, schemas):
    Draft202012Validator.check_schema(schemas[name])


def test_all_schemas_declare_id(schemas):
    for name, s in schemas.items():
        assert s.get("$id"), f"{name} schema is missing $id"


def test_all_schemas_declare_schema_dialect(schemas):
    dialect = "https://json-schema.org/draft/2020-12/schema"
    for name, s in schemas.items():
        assert s.get("$schema") == dialect, f"{name} schema $schema != {dialect}"
