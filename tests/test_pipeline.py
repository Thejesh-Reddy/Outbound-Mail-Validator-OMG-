from text_validation.pattern_catalog import (
    get_patterns,
    get_catalog_summary,
    load_pattern_catalog,
)


def test_catalog_contains_156_entries():
    catalog = load_pattern_catalog()

    assert catalog["pattern_count"] == 156
    assert len(catalog["patterns"]) == 156


def test_catalog_ids_are_unique():
    patterns = get_patterns()
    ids = [pattern["id"] for pattern in patterns]

    assert len(ids) == len(set(ids))


def test_catalog_codes_are_unique():
    patterns = get_patterns()
    codes = [pattern["code"] for pattern in patterns]

    assert len(codes) == len(set(codes))


def test_catalog_summary_counts_are_consistent():
    summary = get_catalog_summary()

    assert summary["total_patterns"] == 156
    assert (
        summary["implemented_patterns"]
        + summary["catalog_only_patterns"]
        == summary["total_patterns"]
    )
