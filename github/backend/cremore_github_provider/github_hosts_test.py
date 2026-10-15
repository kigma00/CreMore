import pytest

from cremore_github_provider.github_hosts import (
    api_base,
    host_from_api_base,
    is_public,
    normalize_host,
    web_base,
)


def test_github_com_is_the_default_and_its_aliases_collapse_to_public():
    for value in ("", None, "github.com", "https://github.com", "https://api.github.com", "www.github.com"):
        assert normalize_host(value) == "" and is_public(value)
    assert api_base("") == "https://api.github.com" and web_base("") == "https://github.com"


def test_enterprise_host_maps_to_api_v3_and_its_web_base():
    assert normalize_host("ghe.example.com") == "ghe.example.com"
    assert normalize_host("https://ghe.example.com/") == "ghe.example.com"
    assert api_base("ghe.example.com") == "https://ghe.example.com/api/v3"
    assert web_base("ghe.example.com") == "https://ghe.example.com"
    assert host_from_api_base(api_base("ghe.example.com")) == "ghe.example.com"
    assert host_from_api_base(api_base("")) == ""


def test_enterprise_cloud_data_residency_uses_its_api_subdomain():
    assert api_base("org.ghe.com") == "https://api.org.ghe.com"
    assert host_from_api_base(api_base("org.ghe.com")) == "org.ghe.com"
    assert web_base("org.ghe.com") == "https://org.ghe.com"


def test_a_host_that_is_not_a_plain_https_host_is_refused():
    for bad in ("http://ghe.example.com", "https://user:pw@ghe.example.com", "https://ghe.example.com:8443",
                "https://ghe.example.com/api/v3", "https://ghe.example.com/path", "not a host", "ghe_corp"):
        with pytest.raises(ValueError):
            normalize_host(bad)
