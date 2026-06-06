from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_analyze_endpoint_returns_risk_score_and_remediation():
    payload = {
        "provider": "generic",
        "findings": [
            {
                "provider": "AWS",
                "severity": "High",
                "resource": "s3-bucket",
                "issue": "Public S3 bucket",
                "description": "Bucket is publicly exposed"
            }
        ]
    }

    response = client.post("/analyze", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert "highest_risks" in data
    assert data["highest_risks"][0]["risk_score"] > 0
    assert data["highest_risks"][0]["remediation"] != ""


def test_llm_remediation_endpoint_returns_structured_remediation():
    payload = {
        "provider": "generic",
        "findings": [
            {
                "provider": "AWS",
                "severity": "High",
                "resource": "s3-bucket",
                "issue": "Public S3 bucket",
                "description": "Bucket is publicly exposed"
            }
        ]
    }

    response = client.post("/llm-remediation", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert "results" in data
    assert data["results"][0]["status"] == "stub"
    assert "remediation" in data["results"][0]
    assert data["results"][0]["remediation"]["issue"] == "Public S3 bucket"
    assert "remediation_steps" in data["results"][0]["remediation"]