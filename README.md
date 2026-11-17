# Agent-harness safety classifier
POST (any path) -> results. An LLM extracts facts per case; app.py's decide() applies the policy deterministically.
Render: Docker, Free. Env vars: AIPIPE_TOKEN (required), MODEL (optional, default gpt-4.1-mini).
Health: GET https://HOST/  -> {"ok":true,...,"llm_error":null}
Submit: https://HOST/classify   (any path works; POST only)
Tests: python3 test_app.py
