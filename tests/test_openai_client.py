from app.openai_client import (
    has_openai_api_key,
    generate_openai_response,
)


def test_openai_stub_response():

    result = generate_openai_response(
        "test prompt"
    )

    assert result is not None
    assert len(result) > 0