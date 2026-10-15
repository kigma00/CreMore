"""Compatibility calls into the explicitly registered provider content libraries."""

def _content(provider):
    from cremore.sources.registry import PROVIDERS
    return PROVIDERS[provider].content_module()


def SourceHTTP(provider, payload, client, **kwargs):
    return _content(provider).SourceHTTP(payload, client, **kwargs)


def EnterpriseCollector(provider, payload, client, **kwargs):
    return _content(provider).Collector(payload, client, **kwargs)


def roots(provider, payload, client, budget=None):
    return _content(provider).roots(payload, client, budget)


def build(provider, payload, client, **kwargs):
    return _content(provider).build(payload, client, **kwargs)


def adc_token():
    from cremore_gcp_provider.gcp_auth import adc_token as source
    return source()
