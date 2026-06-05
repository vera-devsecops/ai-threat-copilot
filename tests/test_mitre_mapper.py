from app.mitre_mapper import map_to_mitre


def test_known_mapping():
    result = map_to_mitre("Public S3 Bucket")

    assert result["technique"] == "T1530"


def test_unknown_mapping():
    result = map_to_mitre("Random Finding")

    assert result["technique"] == "UNKNOWN"