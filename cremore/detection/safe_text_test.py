"""Provider facts retain ordinary metadata, never reflected test credentials."""

import base64
from urllib.parse import quote

import pytest

from cremore.detection.safe_text import safe_fact_text


@pytest.mark.parametrize("value", ["CreMore scan", "read:api, read_user", "2027-01-01T00:00:00Z",
                                  "/pictures/p%20q.jpg", "a" * 40, "Employees"])
def test_ordinary_facts_remain_exact(value):
    assert safe_fact_text(value) == value


@pytest.mark.parametrize("encode", [lambda value: value, lambda value: "".join(f"%{ord(char):02X}" for char in value),
                                    lambda value: base64.b64encode(value.encode()).decode(),
                                    lambda value: "".join(f"&#{ord(char)};" for char in value)])
def test_reflected_authentication_material_is_omitted_as_a_whole(encode):
    opaque = "synthetic-auth-material-19"
    assert safe_fact_text(encode(opaque), secrets=(opaque,)) is None


@pytest.mark.parametrize("value", [None, 17, "line\ntext", "x" * 2049])
def test_invalid_facts_are_omitted_without_truncation(value):
    assert safe_fact_text(value) is None


def test_catalog_shapes_are_omitted_even_when_the_fact_is_not_the_current_credential():
    from cremore.detection.engine_test import GH

    assert safe_fact_text(GH, secrets=("different-synthetic-credential",)) is None
    assert safe_fact_text("label_" + GH + "_suffix") is None
    assert safe_fact_text(quote(GH, safe="")) is None
    assert safe_fact_text(base64.b64encode(GH.encode()).decode()) is None
