"""GitLab issuer metadata and explicit audit references, adapted from 744c48c."""

__version__ = "0.11.1"
UPGRADE_SOURCE_COMMIT = "18bccee1b2a33491d7da138d1a23ca298eed6e6c"


def collect_pages(*args, **kwargs):
    """Stream fenced coverage pages using the shared worker contract."""
    from .adapter import collect_pages as collect

    return collect(*args, **kwargs)


def validate_spec(spec):
    from .adapter import validate_spec as validate

    return validate(spec)


def validate_record(spec, record):
    from .adapter import validate_record as validate

    return validate(spec, record)


def validate_machine_record(spec, record):
    from .adapter import validate_machine_record as validate

    return validate(spec, record)


def export_records(records, **kwargs):
    from .adapter import export_records as export

    return export(records, **kwargs)


def compare_records(records, previous, **kwargs):
    from .adapter import compare_records as compare

    return compare(records, previous, **kwargs)
