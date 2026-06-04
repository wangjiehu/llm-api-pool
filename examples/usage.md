# Usage Examples

## OpenAI Compatible (most tools)

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto",
    "messages": [{"role": "user", "content": "Hello from the pool!"}],
    "stream": false
  }'
```

Python:
```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="any")
resp = client.chat.completions.create(model="auto", messages=[{"role":"user","content":"hi"}])
print(resp.choices[0].message.content)
```

For Cursor / Continue.dev / Aider: set base_url to http://localhost:8080/v1 , api_key any.

## Anthropic Compatible (Claude Code, etc.)

```bash
curl http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello from Anthropic format!"}]
  }'
```

With anthropic SDK (set base_url):

```python
import anthropic
client = anthropic.Anthropic(base_url="http://localhost:8080/v1", api_key="any")
msg = client.messages.create(model="auto", max_tokens=1024, messages=[{"role":"user", "content":"hi"}])
print(msg.content[0].text)
```

For Claude Code CLI: set ANTHROPIC_BASE_URL=http://localhost:8080/v1

## Monitoring

Visit http://localhost:8080/admin/status for JSON with real-time health, quotas (codex vs chat), in-flight, etc.

The dashboard at / shows everything visually.

## Adding Web Sessions (direct password)

POST /admin/channels with:
```json
{
  "type": "web_codex",
  "name": "my-codex",
  "email": "you@gmail.com",
  "password": "yourpass"
}
```

Or use the UI. The tool will headless login and drive the UI for subsequent API calls.

**Tip for reliability**: For high volume, prefer official API keys. Use web_* for extra quotas or when no key.

## Model Selection

The smart router chooses based on requested model, channel health, quota, etc.
You can set per-channel "aliases" in future config for mapping (e.g. "sonnet" -> specific).

Current: "auto" lets router pick; specific names like "claude-3-5-sonnet" bias toward claude channels.
