import os

from openai import OpenAI


def has_openai_api_key() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


def generate_openai_response(prompt: str) -> str:
    if not has_openai_api_key():
        return "OpenAI API key not configured. Returning stub response."

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
    )

    return response.output_text