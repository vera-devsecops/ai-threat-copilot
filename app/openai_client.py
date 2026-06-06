import json
import os

from openai import OpenAI


def has_openai_api_key() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


def generate_openai_response(prompt: str) -> str:

    if not has_openai_api_key():
        return json.dumps({
            "attack_scenario": "Stub attack scenario",
            "priority": "Medium",
        })

    client = OpenAI(
        api_key=os.getenv("OPENAI_API_KEY")
    )

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
    )

    return response.output_text