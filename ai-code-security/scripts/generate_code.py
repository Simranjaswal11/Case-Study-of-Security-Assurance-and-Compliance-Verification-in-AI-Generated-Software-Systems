"""
generate_code.py
----------------
Submits each prompt in prompt_corpus.json to GPT-4o and Claude 3.5 Sonnet
and saves the generated Python code to artifacts/<tool>/<prompt_id>.py

GitHub Copilot does not have a public API; those artifacts must be collected
manually in VS Code and saved to artifacts/copilot/<prompt_id>.py

Requirements:
    pip install openai anthropic

Environment variables:
    OPENAI_API_KEY
    ANTHROPIC_API_KEY
"""

import os
import json
import time

# ── OpenAI
try:
    from openai import OpenAI
    openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))
except ImportError:
    openai_client = None
    print("[WARN] openai package not installed — GPT-4o generation will be skipped.")

# ── Anthropic
try:
    import anthropic
    anthropic_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
except ImportError:
    anthropic_client = None
    print("[WARN] anthropic package not installed — Claude generation will be skipped.")

PROMPTS_FILE = os.path.join(os.path.dirname(__file__), "../prompts/prompt_corpus.json")
ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "../artifacts")

SYSTEM_INSTRUCTION = (
    "You are a helpful coding assistant. "
    "Generate only Python code with no explanation or markdown fences. "
    "The code should be complete and runnable."
)


def load_prompts():
    with open(PROMPTS_FILE, "r") as f:
        return json.load(f)


def save_artifact(tool: str, prompt_id: str, code: str):
    tool_dir = os.path.join(ARTIFACTS_DIR, tool)
    os.makedirs(tool_dir, exist_ok=True)
    filepath = os.path.join(tool_dir, f"{prompt_id}.py")
    with open(filepath, "w") as f:
        f.write(code)
    print(f"  Saved → {filepath}")


def generate_gpt4o(prompt_text: str) -> str:
    if openai_client is None:
        raise RuntimeError("openai not installed")
    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": prompt_text},
        ],
        temperature=0,
    )
    return response.choices[0].message.content.strip()


def generate_claude(prompt_text: str) -> str:
    if anthropic_client is None:
        raise RuntimeError("anthropic not installed")
    response = anthropic_client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system=SYSTEM_INSTRUCTION,
        messages=[{"role": "user", "content": prompt_text}],
    )
    return response.content[0].text.strip()


def run():
    prompts = load_prompts()
    print(f"Loaded {len(prompts)} prompts.\n")

    for entry in prompts:
        pid = entry["id"]
        text = entry["prompt"]
        print(f"[{pid}] {text[:60]}...")

        # GPT-4o
        if openai_client and os.environ.get("OPENAI_API_KEY"):
            try:
                code = generate_gpt4o(text)
                save_artifact("gpt4o", pid, code)
                time.sleep(1)  # rate-limit courtesy
            except Exception as e:
                print(f"  [ERROR] GPT-4o: {e}")
        else:
            print("  [SKIP] GPT-4o (no API key)")

        # Claude 3.5 Sonnet
        if anthropic_client and os.environ.get("ANTHROPIC_API_KEY"):
            try:
                code = generate_claude(text)
                save_artifact("claude", pid, code)
                time.sleep(1)
            except Exception as e:
                print(f"  [ERROR] Claude: {e}")
        else:
            print("  [SKIP] Claude (no API key)")

        print()

    print("Done. GitHub Copilot artifacts must be added manually to artifacts/copilot/")


if __name__ == "__main__":
    run()
