#!/usr/bin/env python3
"""
LLM API Pool
Unified OpenAI + Anthropic API for official keys and web sessions (Gemini/Claude/ChatGPT/Codex).

- Run locally (exe or python) or self-host
- Dashboard at / (also works as static file for GitHub Pages)
- See README for usage instructions
"""

import os
import json
import uuid
import asyncio
import time
import argparse
import base64
import copy
import hashlib
import hmac
import html
import random
import re
import secrets
import threading
import webbrowser
import platform
from collections import defaultdict, deque
from typing import List, Dict, Any, Optional, Tuple
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

import sys
from pathlib import Path

def get_app_dir() -> Path:
    """Directory for runtime user data (channels.json, .pw_data_*). For exe: next to the .exe (cwd at launch)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path.cwd()

def get_resource_path(name: str) -> Path:
    """Location of bundled static assets (dashboard.html) inside PyInstaller onefile/onedir or source tree.
    Critical for foolproof exe (onedir preferred for fast startup).
    """
    if getattr(sys, "frozen", False):
        if hasattr(sys, "_MEIPASS"):
            # onefile: assets extracted to temp
            return Path(sys._MEIPASS) / name
        else:
            # onedir: assets are loose next to the executable
            return Path(sys.executable).parent / name
    # dev/source: next to .py
    return Path(__file__).resolve().parent / name

# Simple persistence (channels.json next to the script or cwd)
CHANNELS_FILE = os.getenv("CHANNELS_FILE", str(get_app_dir() / "channels.json"))
CHANNELS: List[Dict[str, Any]] = []
_channels_lock = asyncio.Lock()  # protect mutations for high-concurrency safety (normativity)
SECRET_CONFIG_KEYS = {"api_key", "password", "cookies"}
SECRET_ENVELOPE_KEY = "__llm_pool_secret__"

def int_env(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default

DIAGNOSTIC_EVENT_LIMIT = int_env("DIAGNOSTIC_EVENT_LIMIT", 200, 20)
DIAGNOSTIC_EVENTS: deque = deque(maxlen=DIAGNOSTIC_EVENT_LIMIT)
SENSITIVE_DETAIL_MARKERS = (
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "password",
    "secret",
    "token",
    "x-api-key",
    "x-admin-token",
)

def redact_sensitive_text(value: Any) -> str:
    text = str(value)
    text = re.sub(r"(?i)\bbearer\s+[^,\s;}\]]+", "Bearer <redacted>", text)
    text = re.sub(
        r"(?i)\b(authorization|x-api-key|x-admin-token|api[_-]?key|token|password|cookie)s?(\s*[:=]\s*)([^,\s;}\]]+)",
        r"\1\2<redacted>",
        text,
    )
    text = re.sub(r"sk-[A-Za-z0-9_\-]{8,}", "<redacted>", text)
    text = re.sub(r"AIza[A-Za-z0-9_\-]{10,}", "<redacted>", text)
    return text

def sanitize_for_diagnostics(value: Any, key_name: str = "", depth: int = 0) -> Any:
    key_l = key_name.lower()
    if any(marker in key_l for marker in SENSITIVE_DETAIL_MARKERS):
        if key_l == "cookies" and isinstance(value, dict):
            return f"<redacted:{len(value)} cookies>"
        return "<redacted>"
    if depth >= 4:
        return "<truncated>"
    if isinstance(value, dict):
        return {str(k): sanitize_for_diagnostics(v, str(k), depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        items = [sanitize_for_diagnostics(v, key_name, depth + 1) for v in value[:25]]
        if len(value) > 25:
            items.append(f"<truncated:{len(value) - 25}>")
        return items
    if isinstance(value, tuple):
        return [sanitize_for_diagnostics(v, key_name, depth + 1) for v in value[:25]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            text = redact_sensitive_text(value)
            return text if len(text) <= 500 else text[:500] + "...<truncated>"
        return value
    return redact_sensitive_text(value)

def safe_path_for_diagnostics(value: Any) -> str:
    text = str(value)
    try:
        home = str(Path.home())
        if home and text.lower().startswith(home.lower()):
            return "~" + text[len(home):]
    except Exception:
        pass
    return text

def record_diagnostic_event(level: str, message: str, **details: Any) -> None:
    try:
        DIAGNOSTIC_EVENTS.append({
            "ts": round(time.time(), 3),
            "level": level,
            "message": redact_sensitive_text(message)[:160],
            "details": sanitize_for_diagnostics(details),
        })
    except Exception:
        pass

def _is_windows() -> bool:
    return sys.platform.startswith("win")

def _dpapi_protect(data: bytes) -> bytes:
    if not _is_windows():
        raise RuntimeError("Windows DPAPI is unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    in_buf = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.c_void_p))
    out_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)

def _dpapi_unprotect(data: bytes) -> bytes:
    if not _is_windows():
        raise RuntimeError("Windows DPAPI is unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    in_buf = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.c_void_p))
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)

def is_secret_envelope(value: Any) -> bool:
    return isinstance(value, dict) and value.get(SECRET_ENVELOPE_KEY) == "dpapi"

def protect_secret_value(value: Any) -> Any:
    if value is None or is_secret_envelope(value):
        return value
    if not _is_windows():
        if os.getenv("LLM_POOL_ALLOW_PLAINTEXT_SECRETS") != "1":
            print("[secrets] DPAPI unavailable; saving plaintext secrets. Set LLM_POOL_ALLOW_PLAINTEXT_SECRETS=1 to silence this warning.")
        return value
    payload = json.dumps({"value": value}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encrypted = _dpapi_protect(payload)
    return {
        SECRET_ENVELOPE_KEY: "dpapi",
        "scope": "current_user",
        "value": base64.b64encode(encrypted).decode("ascii"),
    }

def unprotect_secret_value(value: Any) -> Any:
    if not is_secret_envelope(value):
        return value
    encrypted = base64.b64decode(value.get("value", ""))
    payload = _dpapi_unprotect(encrypted)
    return json.loads(payload.decode("utf-8")).get("value")

def encrypt_channel_for_disk(ch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(ch)
    cfg = out.get("config") or {}
    for key in SECRET_CONFIG_KEYS:
        if key in cfg:
            cfg[key] = protect_secret_value(cfg[key])
    out["config"] = cfg
    return out

def decrypt_channel_from_disk(ch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(ch)
    cfg = out.get("config") or {}
    for key in SECRET_CONFIG_KEYS:
        if key in cfg and is_secret_envelope(cfg[key]):
            try:
                cfg[key] = unprotect_secret_value(cfg[key])
            except Exception as e:
                print(f"[secrets] Could not decrypt {key} for channel {out.get('id')}: {e}")
    out["config"] = cfg
    return out

def has_plaintext_secret(ch: Dict[str, Any]) -> bool:
    cfg = ch.get("config") or {}
    return any(key in cfg and cfg[key] is not None and not is_secret_envelope(cfg[key]) for key in SECRET_CONFIG_KEYS)

def restrict_channels_file_permissions():
    try:
        os.chmod(CHANNELS_FILE, 0o600)
    except Exception:
        pass

def load_channels():
    global CHANNELS
    if os.path.exists(CHANNELS_FILE):
        try:
            with open(CHANNELS_FILE, "r", encoding="utf-8-sig") as f:  # utf-8-sig tolerates BOM from Notepad/PS writes
                raw_channels = json.load(f)
            needs_resave = any(has_plaintext_secret(c) for c in raw_channels)
            CHANNELS = [decrypt_channel_from_disk(c) for c in raw_channels]
            print(f"Loaded {len(CHANNELS)} channels from {CHANNELS_FILE}")
            record_diagnostic_event("info", "channels_loaded", count=len(CHANNELS), channels_file=safe_path_for_diagnostics(CHANNELS_FILE))
            if needs_resave:
                print("[secrets] Migrating plaintext channel secrets to encrypted storage.")
                record_diagnostic_event("info", "plaintext_secrets_migrated", count=len(CHANNELS), channels_file=safe_path_for_diagnostics(CHANNELS_FILE))
                save_channels()
        except Exception as e:
            print(f"Failed to load channels: {e}")
            record_diagnostic_event("error", "channels_load_failed", error=str(e), channels_file=safe_path_for_diagnostics(CHANNELS_FILE))

def save_channels():
    """Atomic save to prevent corruption on crash/power loss (critical for portable exe)."""
    tmp = CHANNELS_FILE + ".tmp"
    try:
        disk_channels = [encrypt_channel_for_disk(c) for c in CHANNELS]
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(disk_channels, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CHANNELS_FILE)  # atomic on POSIX/Windows
        restrict_channels_file_permissions()
    except Exception as e:
        print(f"Failed to save channels: {e}")
        record_diagnostic_event("error", "channels_save_failed", error=str(e), channels_file=safe_path_for_diagnostics(CHANNELS_FILE))
        # best effort cleanup
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except:
            pass

# Load on start
load_channels()

# Config
PORT = int(os.getenv("PORT", "8080"))
HOST = os.getenv("HOST", "127.0.0.1")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
GENERATED_ADMIN_TOKEN = False
if not ADMIN_TOKEN:
    ADMIN_TOKEN = secrets.token_urlsafe(24)
    GENERATED_ADMIN_TOKEN = True
API_TOKEN = os.getenv("API_TOKEN", "")  # Optional protection for /v1 endpoints on remote instances
RATE_LIMIT_PER_MINUTE = int_env("RATE_LIMIT_PER_MINUTE", 120, 0)
DEBUG_ERRORS = os.getenv("DEBUG_ERRORS", "").lower() in {"1", "true", "yes"}

VALID_CHANNEL_TYPES = {
    "official_gemini",
    "official_claude",
    "official_openai",
    "web_gemini",
    "web_claude",
    "web_chatgpt",
    "web_codex",
}

DEFAULT_MODELS = {
    "official_openai": "gpt-4o-mini",
    "official_claude": "claude-3-5-sonnet-20241022",
    "official_gemini": "gemini-2.5-flash",
}

class Channel(BaseModel):
    id: str
    type: str  # official_gemini | official_claude | official_openai | web_gemini | web_claude | web_chatgpt
    name: str
    config: Dict[str, Any]  # api_key or {"cookies": {...}, "email": "..."} etc.

class AddChannelRequest(BaseModel):
    type: Optional[str] = None
    name: Optional[str] = None
    api_key: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None  # For web: direct cookie paste
    quota: Optional[int] = None  # estimated quota for monitoring
    quota_category: Optional[str] = None  # "chat", "codex", "general"
    aliases: Optional[Dict[str, str]] = None  # e.g. {"sonnet": "claude-3-5-sonnet-20241022"}
    priority: Optional[int] = 1
    max_concurrent: Optional[int] = None
    default_model: Optional[str] = None

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    stream: Optional[bool] = False
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None

# ==================== Unified Canonical Format (our own, not copied) ====================
# All incoming (OpenAI or Anthropic) normalized to this, backends produce this,
# then converted back. This unifies everything for smart routing, monitoring, logging.

class CanonicalMessage(BaseModel):
    role: str
    content: Optional[str | list] = None   # str or content blocks for vision/tools
    name: Optional[str] = None

class CanonicalTool(BaseModel):
    type: str = "function"
    function: dict

class CanonicalRequest(BaseModel):
    model: str
    messages: List[CanonicalMessage]
    system: Optional[str] = None
    tools: Optional[List[CanonicalTool]] = None
    tool_choice: Any = None
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    stream: bool = False
    metadata: dict = Field(default_factory=dict)  # for extra like original_format

class CanonicalChoice(BaseModel):
    index: int = 0
    message: dict   # {"role": "assistant", "content": "...", "tool_calls": [...]}
    finish_reason: Optional[str] = "stop"

class CanonicalResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[CanonicalChoice]
    usage: dict = Field(default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
    # for stream we use different handling

def model_to_dict(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return obj

def canonical_choices_to_dicts(resp: CanonicalResponse) -> List[dict]:
    return [model_to_dict(choice) for choice in resp.choices]

def redact_config(config: Dict[str, Any]) -> Dict[str, Any]:
    redacted = {}
    for key, value in (config or {}).items():
        if key in SECRET_CONFIG_KEYS:
            if key == "cookies" and isinstance(value, dict):
                redacted[key] = f"<redacted:{len(value)} cookies>"
            else:
                redacted[key] = "<redacted>"
        else:
            redacted[key] = value
    return redacted

def require_admin_token() -> bool:
    return bool(ADMIN_TOKEN)

def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None

def safe_token_match(supplied: Optional[str], expected: str) -> bool:
    if not supplied or not expected:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

async def require_admin(
    request: Request,
    x_admin_token: Optional[str] = Header(default=None),
):
    if not require_admin_token():
        return
    supplied = x_admin_token or extract_bearer_token(request)
    if not safe_token_match(supplied, ADMIN_TOKEN):
        record_diagnostic_event("warn", "bad_admin_token", client=client_ip(request), path=str(request.url.path))
        raise HTTPException(401, "bad admin token")

async def require_api_token(request: Request, x_api_key: Optional[str] = Header(default=None)):
    if not API_TOKEN:
        return
    supplied = x_api_key or extract_bearer_token(request)
    if not safe_token_match(supplied, API_TOKEN):
        record_diagnostic_event("warn", "bad_api_token", client=client_ip(request), path=str(request.url.path))
        raise HTTPException(401, "bad api token")

class SlidingWindowRateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit_per_minute = max(0, int(limit_per_minute))
        self.window_seconds = 60.0
        self._hits: Dict[str, deque] = defaultdict(deque)

    def check(self, key: str) -> bool:
        if self.limit_per_minute <= 0:
            return True
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        if len(hits) >= self.limit_per_minute:
            return False
        hits.append(now)
        return True

api_rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_PER_MINUTE)

def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

async def require_api_access(request: Request, x_api_key: Optional[str] = Header(default=None)):
    await require_api_token(request, x_api_key)
    supplied = x_api_key or extract_bearer_token(request) or "anonymous"
    token_hash = hashlib.sha256(supplied.encode("utf-8")).hexdigest()[:16]
    if not api_rate_limiter.check(f"{client_ip(request)}:{token_hash}:{request.url.path}"):
        record_diagnostic_event("warn", "api_rate_limited", client=client_ip(request), path=str(request.url.path))
        raise HTTPException(429, "rate limit exceeded")

# Adapters - implemented ourselves for clean unified handling
def openai_to_canonical(body: dict) -> CanonicalRequest:
    msgs = []
    system = None
    for m in body.get("messages", []):
        role = m.get("role", "user")
        content = m.get("content")
        if role == "system":
            system = content if isinstance(content, str) else str(content)
            continue
        msgs.append(CanonicalMessage(role=role, content=content))
    return CanonicalRequest(
        model=body.get("model", "auto"),
        messages=msgs,
        system=system,
        tools=body.get("tools"),
        tool_choice=body.get("tool_choice"),
        temperature=body.get("temperature", 0.7),
        max_tokens=body.get("max_tokens"),
        stream=body.get("stream", False),
        metadata={"original_format": "openai"}
    )

def anthropic_to_canonical(body: dict) -> CanonicalRequest:
    msgs = []
    system = body.get("system")
    if isinstance(system, list):
        system = " ".join([b.get("text", "") for b in system if isinstance(b, dict)])
    for m in body.get("messages", []):
        role = m.get("role", "user")
        content = m.get("content")
        if isinstance(content, list):
            # simplify to text for now (full tool/vision later)
            text_parts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
            content = "\n".join(text_parts) or str(content)
        msgs.append(CanonicalMessage(role=role, content=content))
    return CanonicalRequest(
        model=body.get("model", "auto"),
        messages=msgs,
        system=system,
        tools=body.get("tools"),
        tool_choice=body.get("tool_choice"),
        temperature=body.get("temperature", 0.7),
        max_tokens=body.get("max_tokens"),
        stream=body.get("stream", False),
        metadata={"original_format": "anthropic"}
    )

def canonical_to_openai(resp: CanonicalResponse, stream: bool = False) -> dict:
    choices = canonical_choices_to_dicts(resp)
    if stream:
        # caller will handle chunked
        return {"model": resp.model, "choices": choices}
    return {
        "id": resp.id,
        "object": "chat.completion",
        "created": resp.created,
        "model": resp.model,
        "choices": choices,
        "usage": resp.usage
    }

def canonical_to_anthropic(resp: CanonicalResponse, stream: bool = False) -> dict:
    # Basic translation for Claude Code etc.
    content = []
    choices = canonical_choices_to_dicts(resp)
    for ch in choices:
        msg = ch.get("message", {})
        text = msg.get("content", "")
        content.append({"type": "text", "text": text})
    if stream:
        return {"type": "message", "content": content}
    finish_reason = choices[0].get("finish_reason") if choices else "stop"
    stop_reason = "end_turn" if finish_reason in (None, "stop") else finish_reason
    return {
        "id": resp.id,
        "type": "message",
        "role": "assistant",
        "model": resp.model,
        "content": content,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": resp.usage.get("prompt_tokens", 0),
            "output_tokens": resp.usage.get("completion_tokens", 0)
        }
    }

def make_canonical_response(text: str, model: str = "pooled", original_format: str = "openai") -> CanonicalResponse:
    return CanonicalResponse(
        id=f"pool-{uuid.uuid4()}",
        created=int(time.time()),
        model=model,
        choices=[CanonicalChoice(index=0, message={"role": "assistant", "content": text}, finish_reason="stop")],
        usage={"prompt_tokens": 0, "completion_tokens": len(text)//4, "total_tokens": len(text)//4}
    )

def canonical_to_text_prompt(req: CanonicalRequest) -> str:
    lines = []
    for msg in req.messages:
        content = msg.content if isinstance(msg.content, str) else json.dumps(msg.content, ensure_ascii=False)
        role = msg.role or "user"
        if role == "assistant":
            lines.append(f"Assistant: {content}")
        elif role == "system":
            lines.append(f"System: {content}")
        else:
            lines.append(f"User: {content}")
    if not lines and req.system:
        return req.system
    return "\n\n".join(lines)

def get_channel_by_id(cid: str) -> Optional[Dict]:
    for ch in CHANNELS:
        if ch["id"] == cid:
            return ch
    return None

# ==================== Playwright web session driver (for web_xxx channels) ====================
# Keeps browser contexts alive per channel so the web login session (from email+pass or cookies)
# can be reused to actually drive the real chat UI and turn it into an API.
# This is "heavy" but the most reliable way to use the web quotas without fragile HTTP reverse engineering.
# Selectors may need occasional updates if the sites change their DOM.

_playwright = None
_web_contexts: Dict[str, Any] = {}  # channel_id -> BrowserContext
_browser_checked = False

async def get_playwright():
    global _playwright
    if _playwright is None:
        from playwright.async_api import async_playwright
        _playwright = await async_playwright().start()
    return _playwright

def cookie_domains_for_channel(ch_type: str) -> List[str]:
    if "gemini" in ch_type:
        return [".google.com", "gemini.google.com"]
    if "claude" in ch_type:
        return [".claude.ai", "claude.ai", ".anthropic.com"]
    if "chatgpt" in ch_type or "codex" in ch_type or "openai" in ch_type:
        return [".chatgpt.com", "chatgpt.com", ".openai.com", "auth.openai.com"]
    return []

async def get_or_create_web_context(ch: Dict[str, Any]):
    """Get or create a persistent browser context injected with the channel's cookies."""
    cid = ch["id"]
    if cid in _web_contexts:
        return _web_contexts[cid]

    cookies = ch.get("config", {}).get("cookies", {})
    if not cookies:
        record_diagnostic_event("warn", "web_channel_missing_cookies", channel_id=cid, type=ch.get("type"), name=ch.get("name"))
        raise HTTPException(400, f"web channel '{ch.get('name')}' has no cookies. Use email+password in /admin to auto-login, or paste cookies.")

    await ensure_browsers_installed()
    p = await get_playwright()
    # Use a per-channel user data dir so logins/cookies can persist across restarts.
    # Use get_app_dir() so it works correctly in PyInstaller onedir (next to exe) and dev.
    user_data = str(get_app_dir() / f".pw_data_{cid}")
    os.makedirs(user_data, exist_ok=True)

    context = await p.chromium.launch_persistent_context(
        user_data_dir=user_data,
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
        ],
        viewport={"width": 1280, "height": 800},
    )

    # Inject/override cookies (works even if some are already in the profile)
    pw_cookies = []
    domains = cookie_domains_for_channel(ch["type"])
    for name, value in cookies.items():
        if isinstance(value, dict):
            cookie = {**value}
            cookie["value"] = str(cookie.get("value", ""))
            cookie.setdefault("path", "/")
            pw_cookies.append(cookie)
            continue
        for domain in domains:
            pw_cookies.append({
                "name": name,
                "value": str(value),
                "domain": domain,
                "path": "/",
            })

    if pw_cookies:
        await context.add_cookies(pw_cookies)

    _web_contexts[cid] = context
    print(f"[web] Browser context ready for {ch['name']} ({ch['type']})")
    record_diagnostic_event("info", "web_context_ready", channel_id=cid, type=ch.get("type"), name=ch.get("name"))
    return context

async def drive_web_chat(ch: Dict[str, Any], prompt: str, timeout_ms: int = 120000) -> str:
    """Drive the real web chat UI with an already-authenticated context and return the last response text.
    Robust to minor UI changes via multiple selectors + JS fallback + error detection.
    """
    context = await get_or_create_web_context(ch)
    page = await context.new_page()

    try:
        ch_type = ch["type"]
        if "gemini" in ch_type:
            url = "https://gemini.google.com/app"
            # More robust locators (Playwright preferred over fragile CSS)
            input_locators = [
                'textarea[aria-label*="prompt" i]',
                'div[contenteditable="true"][role="textbox"]',
                'textarea[placeholder*="Message" i]',
                'textarea',
            ]
            send_keys = "Enter"
            extract_js = """() => {
                const containers = document.querySelectorAll('.model-response, [class*="response"], [class*="markdown"], [data-test-id*="model-response"]');
                for (let i = containers.length - 1; i >= 0; i--) {
                    const t = (containers[i].innerText || '').trim();
                    if (t.length > 10) return t;
                }
                return '';
            }"""
            error_indicators = ['rate limit', 'try again later', 'something went wrong']
        elif "claude" in ch_type:
            url = "https://claude.ai/chat"
            input_locators = [
                'div[contenteditable="true"]',
                'textarea[placeholder*="Message" i]',
                '[role="textbox"]',
                'textarea',
            ]
            send_keys = "Enter"
            extract_js = """() => {
                const msgs = document.querySelectorAll('[data-test-id*="message"], [class*="message-content"], .prose');
                for (let i = msgs.length - 1; i >= 0; i--) {
                    const t = (msgs[i].innerText || '').trim();
                    if (t.length > 10) return t;
                }
                return '';
            }"""
            error_indicators = ['rate limit', 'overloaded', 'try again']
        else:
            # chatgpt / codex
            url = "https://chatgpt.com/"
            input_locators = [
                'textarea#prompt-textarea',
                'textarea[placeholder*="Message" i]',
                '[contenteditable="true"]',
                'textarea',
            ]
            send_keys = "Enter"
            extract_js = """() => {
                const msgs = document.querySelectorAll('[data-message-author-role="assistant"], [class*="message"], .markdown');
                for (let i = msgs.length - 1; i >= 0; i--) {
                    const t = (msgs[i].innerText || '').trim();
                    if (t.length > 10) return t;
                }
                return '';
            }"""
            error_indicators = ['rate limit', 'too many requests', 'chatgpt is at capacity']

        # Navigate with better state
        await page.goto(url, wait_until="domcontentloaded", timeout=45000)
        await page.wait_for_timeout(800)  # allow dynamic load

        # Type prompt with robust locator strategy (prefer Playwright API)
        typed = False
        for sel in input_locators:
            try:
                locator = page.locator(sel).first
                await locator.wait_for(timeout=6000, state="visible")
                await locator.click()
                await locator.fill(prompt)  # fill is more reliable than type for long prompts
                await page.keyboard.press(send_keys)
                typed = True
                break
            except Exception:
                continue

        if not typed:
            # JS fallback (last resort)
            escaped = prompt.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')
            await page.evaluate(f"""
                (p) => {{
                    const el = document.querySelector('textarea') ||
                               document.querySelector('[contenteditable="true"]') ||
                               document.querySelector('[role="textbox"]');
                    if (el) {{
                        el.focus();
                        if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {{
                            el.value = p;
                        }} else {{
                            el.innerText = p;
                        }}
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    }}
                }}
            """, escaped)
            await page.keyboard.press("Enter")

        # Wait and poll for response, with error detection
        await page.wait_for_timeout(1800)
        start = time.time() * 1000
        last_text = ""
        while (time.time() * 1000 - start) < timeout_ms:
            try:
                text = await page.evaluate(extract_js)
                if text and len(text) > 8:
                    # Check for error states in the response
                    low = text.lower()
                    if any(ind in low for ind in error_indicators):
                        # Transient error, return what we have + hint
                        return text.strip() + " [web UI reported rate limit or error; pool will cooldown this channel]"
                    if text != last_text:
                        last_text = text
                        await page.wait_for_timeout(900)
                        text2 = await page.evaluate(extract_js)
                        if text2 and len(text2) > len(last_text):
                            last_text = text2
                        if last_text and len(last_text) > 15:
                            break
            except Exception:
                pass
            await page.wait_for_timeout(600)

        final = (last_text or "").strip()
        if not final:
            return "(no usable response extracted — web UI may have changed or requires manual intervention; consider pasting fresh cookies)"
        return final

    except Exception as e:
        # Surface for router to mark failure/cooldown
        # Classify for better recovery (feasibility)
        err = str(e).lower()
        if "rate limit" in err or "overloaded" in err or "capacity" in err:
            raise RuntimeError(f"WEB_RATE_LIMIT:{ch.get('name')}")
        raise RuntimeError(f"Web drive failed for {ch.get('name')}: {str(e)[:200]}")
    finally:
        try:
            await page.close()
        except:
            pass  # tab close best effort; context reused

async def drive_web_chat_stream(ch: dict, prompt: str, interval: float = 0.35):
    """Best-effort streaming for web sessions by polling the rendered UI and yielding deltas.
    Used for agents that prefer stream=True even on web channels.
    """
    context = await get_or_create_web_context(ch)
    page = await context.new_page()
    try:
        ch_type = ch["type"]
        if "gemini" in ch_type:
            url = "https://gemini.google.com/app"
            extract_js = """() => {
                const els = document.querySelectorAll('.model-response, [class*="response"], [class*="markdown"]');
                return els.length ? (els[els.length-1].innerText || '') : '';
            }"""
        elif "claude" in ch_type:
            url = "https://claude.ai/chat"
            extract_js = """() => {
                const els = document.querySelectorAll('[data-test-id*="message"], [class*="message-content"]');
                return els.length ? (els[els.length-1].innerText || '') : '';
            }"""
        else:
            url = "https://chatgpt.com/"
            extract_js = """() => {
                const els = document.querySelectorAll('[data-message-author-role="assistant"], [class*="message"]');
                return els.length ? (els[els.length-1].innerText || '') : '';
            }"""

        await page.goto(url, wait_until="domcontentloaded", timeout=40000)
        await page.wait_for_timeout(700)

        # Type (reuse robust logic)
        typed = False
        for sel in (['textarea', '[contenteditable="true"]', '[role="textbox"]'] if "chatgpt" in ch_type or "codex" in ch_type else
                    ['div[contenteditable="true"]', 'textarea', '[role="textbox"]'] if "claude" in ch_type else
                    ['textarea[aria-label*="prompt" i]', 'div[contenteditable="true"]', 'textarea']):
            try:
                loc = page.locator(sel).first
                await loc.wait_for(timeout=5000, state="visible")
                await loc.fill(prompt)
                await page.keyboard.press("Enter")
                typed = True
                break
            except Exception as e:
                print(f"[web-drive] input locator {sel} failed: {e}")
                continue
        if not typed:
            await page.evaluate("(p) => { const el = document.querySelector('textarea,[contenteditable]'); if(el){el.focus(); el.value=el.innerText=p; el.dispatchEvent(new Event('input',{bubbles:true})); } }", prompt)
            await page.keyboard.press("Enter")

        await page.wait_for_timeout(1500)

        seen = ""
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                current = await page.evaluate(extract_js)
                if current and current != seen:
                    delta = current[len(seen):]
                    seen = current
                    if delta.strip():
                        yield {"choices": [{"delta": {"content": delta}}]}
                        await asyncio.sleep(0.05)
            except Exception as e:
                print(f"[web-stream-poll] {e}")
                pass
            await asyncio.sleep(interval)
    finally:
        try:
            await page.close()
        except:
            pass


# ==================== Provider Backends (unified via Canonical) ====================
# All backends implement: async def generate(self, req: CanonicalRequest, ch: dict) -> CanonicalResponse

class BaseBackend:
    async def generate(self, req: CanonicalRequest, ch: dict) -> Tuple[CanonicalResponse, dict]:
        raise NotImplementedError

    async def stream(self, req: CanonicalRequest, ch: dict):
        """Yield chunk dicts for streaming (openai compatible delta format). Override for real streaming."""
        # default fallback to non-stream and fake (for web)
        resp, _headers = await self.generate(req, ch)
        text = ""
        if resp.choices:
            first_choice = model_to_dict(resp.choices[0])
            text = first_choice.get("message", {}).get("content", "")
        for i in range(0, len(text), 20):
            yield {"choices": [{"delta": {"content": text[i:i+20]}}]}
            await asyncio.sleep(0.01)
        yield {"choices": [{"delta": {"content": ""}}]}  # end marker, caller adds [DONE]

class OfficialOpenAIBackend(BaseBackend):
    def __init__(self):
        self._clients = {}  # api_key -> AsyncOpenAI for reuse (perf, connection pooling)

    async def generate(self, req: CanonicalRequest, ch: dict) -> Tuple[CanonicalResponse, dict]:
        key = ch["config"]["api_key"]
        if key not in self._clients:
            from openai import AsyncOpenAI
            self._clients[key] = AsyncOpenAI(api_key=key)
        client = self._clients[key]
        oai_msgs = []
        if req.system:
            oai_msgs.append({"role": "system", "content": req.system})
        for m in req.messages:
            oai_msgs.append({"role": m.role, "content": m.content})
        raw_resp = await client.chat.completions.with_raw_response.create(
            model=req.model or "gpt-4o",
            messages=oai_msgs,
            temperature=req.temperature,
            max_tokens=req.max_tokens,
            stream=False,
        )
        resp = raw_resp.parse()
        text = resp.choices[0].message.content or ""
        # Capture headers for real-time quota in record_result (feasibility for agents)
        canon_resp = make_canonical_response(text, model=resp.model or req.model, original_format="openai")
        return canon_resp, dict(raw_resp.headers)

    async def stream(self, req: CanonicalRequest, ch: dict):
        key = ch["config"]["api_key"]
        if key not in self._clients:
            from openai import AsyncOpenAI
            self._clients[key] = AsyncOpenAI(api_key=key)
        client = self._clients[key]
        oai_msgs = []
        if req.system:
            oai_msgs.append({"role": "system", "content": req.system})
        for m in req.messages:
            oai_msgs.append({"role": m.role, "content": m.content})
        stream = await client.chat.completions.create(
            model=req.model or "gpt-4o",
            messages=oai_msgs,
            temperature=req.temperature,
            max_tokens=req.max_tokens,
            stream=True,
        )
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                yield {"choices": [{"delta": {"content": chunk.choices[0].delta.content}}]}
        yield {"choices": [{"delta": {"content": ""}}]}

class OfficialAnthropicBackend(BaseBackend):
    def __init__(self):
        self._clients = {}

    async def generate(self, req: CanonicalRequest, ch: dict) -> Tuple[CanonicalResponse, dict]:
        key = ch["config"]["api_key"]
        if key not in self._clients:
            import anthropic
            self._clients[key] = anthropic.AsyncAnthropic(api_key=key)
        client = self._clients[key]
        anth_msgs = [{"role": m.role, "content": m.content} for m in req.messages]
        msg = await client.messages.create(
            model=req.model or "claude-3-5-sonnet-20241022",
            max_tokens=req.max_tokens or 4096,
            system=req.system,
            messages=anth_msgs,
            temperature=req.temperature,
        )
        text = ""
        if msg.content:
            text = "".join(getattr(b, "text", str(b)) for b in msg.content)
        canon_resp = make_canonical_response(text, model=msg.model, original_format="anthropic")
        return canon_resp, {}  # headers not easily available without raw, but for feasibility we can extend later

    async def stream(self, req: CanonicalRequest, ch: dict):
        key = ch["config"]["api_key"]
        if key not in self._clients:
            import anthropic
            self._clients[key] = anthropic.AsyncAnthropic(api_key=key)
        client = self._clients[key]
        anth_msgs = [{"role": m.role, "content": m.content} for m in req.messages]
        kwargs = {
            "model": req.model or "claude-3-5-sonnet-20241022",
            "max_tokens": req.max_tokens or 4096,
            "system": req.system,
            "messages": anth_msgs,
            "temperature": req.temperature,
        }
        if hasattr(client.messages, "stream"):
            async with client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    if text:
                        yield {"choices": [{"delta": {"content": text}}]}
        else:
            stream = await client.messages.create(**kwargs, stream=True)
            async for event in stream:
                if event.type == "content_block_delta" and hasattr(event.delta, "text"):
                    yield {"choices": [{"delta": {"content": event.delta.text}}]}
        yield {"choices": [{"delta": {"content": ""}}]}

class OfficialGeminiBackend(BaseBackend):
    def __init__(self):
        self._clients = {}

    def _client(self, key: str):
        if key not in self._clients:
            from google import genai
            self._clients[key] = genai.Client(api_key=key)
        return self._clients[key]

    def _config(self, req: CanonicalRequest):
        from google.genai import types
        kwargs = {}
        if req.system:
            kwargs["system_instruction"] = req.system
        if req.temperature is not None:
            kwargs["temperature"] = req.temperature
        if req.max_tokens:
            kwargs["max_output_tokens"] = req.max_tokens
        return types.GenerateContentConfig(**kwargs) if kwargs else None

    async def generate(self, req: CanonicalRequest, ch: dict) -> Tuple[CanonicalResponse, dict]:
        key = ch["config"]["api_key"]
        client = self._client(key)
        model = req.model or DEFAULT_MODELS["official_gemini"]
        resp = await client.aio.models.generate_content(
            model=model,
            contents=canonical_to_text_prompt(req),
            config=self._config(req),
        )
        canon_resp = make_canonical_response(getattr(resp, "text", str(resp)), model=model, original_format="gemini")
        return canon_resp, {}  # headers limited in this SDK path

    async def stream(self, req: CanonicalRequest, ch: dict):
        key = ch["config"]["api_key"]
        client = self._client(key)
        model = req.model or DEFAULT_MODELS["official_gemini"]
        stream = await client.aio.models.generate_content_stream(
            model=model,
            contents=canonical_to_text_prompt(req),
            config=self._config(req),
        )
        async for chunk in stream:
            if hasattr(chunk, "text") and chunk.text:
                yield {"choices": [{"delta": {"content": chunk.text}}]}
        yield {"choices": [{"delta": {"content": ""}}]}

class WebBrowserBackend(BaseBackend):
    """Common for all web_* : uses the playwright drive (your logged in web session)"""
    async def generate(self, req: CanonicalRequest, ch: dict) -> Tuple[CanonicalResponse, dict]:
        prompt = ""
        for m in reversed(req.messages):
            if m.role == "user" and m.content:
                prompt = m.content if isinstance(m.content, str) else str(m.content)
                break
        if not prompt and req.messages:
            prompt = str(req.messages[-1].content)
        text = await drive_web_chat(ch, prompt)
        est_tokens = (len(prompt) + len(text)) // 4
        ch.setdefault("stats", {})["last_estimated_tokens"] = est_tokens
        canon_resp = make_canonical_response(text, model=ch.get("name", "web"), original_format="web")
        return canon_resp, {}  # web has no HTTP headers for quota, uses estimation

    async def stream(self, req: CanonicalRequest, ch: dict):
        prompt = ""
        for m in reversed(req.messages):
            if m.role == "user" and m.content:
                prompt = m.content if isinstance(m.content, str) else str(m.content)
                break
        if not prompt and req.messages:
            prompt = str(req.messages[-1].content)
        async for chunk in drive_web_chat_stream(ch, prompt):
            yield chunk
        yield {"choices": [{"delta": {"content": ""}}]}

BACKENDS = {
    "official_openai": OfficialOpenAIBackend(),
    "official_claude": OfficialAnthropicBackend(),
    "official_gemini": OfficialGeminiBackend(),
    "web_gemini": WebBrowserBackend(),
    "web_claude": WebBrowserBackend(),
    "web_chatgpt": WebBrowserBackend(),
    "web_codex": WebBrowserBackend(),  # Codex / Copilot style GPT account quotas (distinguish from plain web_chatgpt)
}

# ==================== SmartRouter + Real-time Quota Monitoring + High-freq resilience ====================
# Intelligent selection to prevent stuck/dead channels.
# Real-time stats: official headers + web estimates + health + cooldowns.
# Per-channel concurrency limit (critical for agent high-freq + browser web channels).

class SmartRouter:
    def __init__(self):
        self.stats: Dict[str, dict] = {}  # channel_id -> live stats
        self.sems: Dict[str, asyncio.Semaphore] = {}  # concurrency control
        self.cooldowns: Dict[str, float] = {}
        self._last_save = 0.0

    def _get_stats(self, ch_id: str) -> dict:
        if ch_id not in self.stats:
            self.stats[ch_id] = {
                "health": 1.0,
                "avg_latency": 4.0,
                "calls": 0,
                "success": 0,
                "used_est_tokens": 0,
                "quota_est": 100000,  # user can override in channel config
                "in_flight": 0,
                "consec_fail": 0,
                "last_call": 0,
                "last_quota_remaining": None,  # from headers for official
                "quota_category": "general",  # "chat", "codex", "general"
            }
        return self.stats[ch_id]

    def _sync_stats_from_config(self, ch: dict) -> dict:
        s = self._get_stats(ch["id"])
        cfg = ch.get("config", {}) or {}
        if "quota" in cfg:
            try:
                s["quota_est"] = int(cfg["quota"])
            except (TypeError, ValueError):
                pass
        if "quota_category" in cfg:
            s["quota_category"] = cfg["quota_category"]
        return s

    def get_sem(self, ch: dict) -> asyncio.Semaphore:
        cid = ch["id"]
        if cid not in self.sems:
            cfg = ch.get("config", {}) or {}
            max_conc = cfg.get("max_concurrent")
            if max_conc is None:
                max_conc = 2 if ch["type"].startswith("web_") else 8
            self.sems[cid] = asyncio.BoundedSemaphore(int(max_conc))
        return self.sems[cid]

    def is_compatible(self, ch: dict, model: str) -> bool:
        t = ch["type"]
        m = model.lower()
        aliases = ch.get("config", {}).get("aliases", {}) or {}
        # check if model or alias matches this channel's type
        for alias_key, alias_val in aliases.items():
            if m == alias_key.lower() or m == alias_val.lower():
                return True
        if "codex" in m or "copilot" in m:
            return "codex" in t or "gpt" in t
        if "claude" in m or "sonnet" in m or "opus" in m or "haiku" in m:
            return "claude" in t
        if "gemini" in m:
            return "gemini" in t
        if "gpt" in m or m.startswith(("o1", "o3", "o4")):
            return "openai" in t or "gpt" in t or "chatgpt" in t or "codex" in t
        return True  # fallback

    def compute_score(self, ch: dict, req: CanonicalRequest) -> float:
        s = self._sync_stats_from_config(ch)
        now = time.time()
        if self.cooldowns.get(ch["id"], 0) > now:
            return 0.0
        if s["consec_fail"] >= 4:
            return 0.05
        health = s["health"]
        quota_rem = s.get("last_quota_remaining") or (s["quota_est"] - s["used_est_tokens"])
        quota_factor = max(0.05, min(1.0, quota_rem / max(1, s["quota_est"])))
        latency_factor = 1.0 / (1.0 + s["avg_latency"] / 8.0)
        load = s["in_flight"]
        load_factor = 1.0 / (1.0 + load * 0.5)
        model_bonus = 1.8 if self.is_compatible(ch, req.model) else 0.6
        # prefer exact quota category for codex etc.
        cat_bonus = 1.5 if ("codex" in req.model.lower() and s.get("quota_category") == "codex") else 1.0
        prio = ch.get("config", {}).get("priority", 1) or 1
        prio_bonus = max(0.5, min(3.0, prio))
        score = health * quota_factor * latency_factor * load_factor * model_bonus * cat_bonus * prio_bonus
        return max(0.01, score)

    def select(self, req: CanonicalRequest) -> Optional[dict]:
        """Intelligent selection, prevents stuck by scoring + cooldown + health."""
        candidates = [c for c in CHANNELS if self.is_compatible(c, req.model)]
        if not candidates:
            candidates = CHANNELS
        if not candidates:
            return None
        scored = [(self.compute_score(c, req), c) for c in candidates]
        scored = [x for x in scored if x[0] > 0]
        if not scored:
            # all in cooldown or dead — pick the least bad with backoff
            scored = [(self.compute_score(c, req) or 0.01, c) for c in candidates]
        scored.sort(key=lambda x: x[0], reverse=True)
        # small jitter to avoid always hammering the same
        top = scored[:min(3, len(scored))]
        chosen = random.choice(top)[1] if top else scored[0][1]
        return chosen

    def resolve_model(self, ch: dict, requested_model: str) -> str:
        """Use channel aliases to map requested model to backend-specific model name."""
        aliases = ch.get("config", {}).get("aliases", {}) or {}
        requested_model = requested_model or "auto"
        m = requested_model.lower()
        if m == "auto":
            return ch.get("config", {}).get("default_model") or DEFAULT_MODELS.get(ch["type"], requested_model)
        for k, v in aliases.items():
            if m == k.lower() or m == v.lower():
                return v
        return requested_model  # default to requested, backend will handle "auto"

    async def acquire(self, ch: dict):
        sem = self.get_sem(ch)
        await sem.acquire()
        s = self._get_stats(ch["id"])
        s["in_flight"] += 1

    def release(self, ch: dict):
        sem = self.get_sem(ch)
        try:
            sem.release()
        except ValueError:
            pass  # already released or at bound (prevents crashes from mismatched acquire/release)
        s = self._get_stats(ch["id"])
        s["in_flight"] = max(0, s["in_flight"] - 1)

    @asynccontextmanager
    async def use_channel(self, ch: dict):
        """Context manager for safe acquire/release (normativity, prevents leaks on exceptions/cancellation)."""
        await self.acquire(ch)
        try:
            yield
        finally:
            self.release(ch)

    def record_result(self, ch: dict, success: bool, latency: float, tokens_used: int = 0, headers: dict | None = None):
        """Update real-time monitoring stats. Called after every call."""
        s = self._sync_stats_from_config(ch)
        s["calls"] += 1
        s["last_call"] = time.time()
        s["avg_latency"] = (s["avg_latency"] * 0.7 + latency * 0.3) if s["calls"] > 1 else latency
        s["used_est_tokens"] += tokens_used

        if success:
            s["success"] += 1
            s["consec_fail"] = 0
            s["health"] = min(1.0, s["health"] + 0.05)
        else:
            s["consec_fail"] += 1
            s["health"] = max(0.1, s["health"] * 0.6)

        # Parse official rate limit headers for real-time quota (very useful for agents)
        if headers:
            for k, v in headers.items():
                kl = k.lower()
                if "ratelimit-remaining" in kl or "remaining" in kl:
                    try:
                        s["last_quota_remaining"] = int(v)
                    except:
                        pass
                if "codex" in kl or "copilot" in kl:  # some custom
                    s["quota_category"] = "codex"

        # Cooldown on repeated failure or low quota
        if s["consec_fail"] >= 3 or (s.get("last_quota_remaining") is not None and s["last_quota_remaining"] < 100):
            self.cooldowns[ch["id"]] = time.time() + (30 * s["consec_fail"])  # progressive

        # persist stats into channel for dashboard (save is throttled in callers)
        ch["stats"] = {**s, "cooldown_until": self.cooldowns.get(ch["id"], 0)}

    def throttled_save(self, interval: float = 1.5):
        now = time.time()
        if now - self._last_save > interval:
            save_channels()
            self._last_save = now

    def get_status(self) -> list:
        out = []
        for ch in CHANNELS:
            s = self._sync_stats_from_config(ch)
            out.append({
                "id": ch["id"],
                "name": ch["name"],
                "type": ch["type"],
                "health": round(s["health"], 2),
                "used_est": s["used_est_tokens"],
                "quota_est": s["quota_est"],
                "remaining_est": max(0, s["quota_est"] - s["used_est_tokens"]),
                "in_flight": s["in_flight"],
                "consec_fail": s["consec_fail"],
                "avg_latency": round(s["avg_latency"], 1),
                "cooldown": self.cooldowns.get(ch["id"], 0) > time.time(),
                "quota_category": s.get("quota_category", "general"),
                "last_quota_remaining": s.get("last_quota_remaining"),
            })
        return out

router = SmartRouter()

# (load_channels / save_channels defined once near top of file; the early module-level call + later saves use it.
#  channels.json path is resolved via get_app_dir() so it lands next to the exe for portable installs.)

# ==================== Login Helper (Playwright for email+pass -> cookies) ====================

async def ensure_browsers_installed():
    """Auto-download Chromium when web login is used and the browser is missing.
    This keeps first-run setup straightforward for local desktop users.
    """
    global _browser_checked
    if _browser_checked:
        return True
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            # Try to launch to check if browser exists
            browser = await p.chromium.launch(headless=True)
            await browser.close()
        _browser_checked = True
        return True
    except Exception as e:
        msg = str(e).lower()
        if "executable" in msg or "browser" in msg or "not found" in msg or "playwright" in msg:
            print("\n[LLM Pool] First-time setup for web login features: downloading Chromium browser (~150MB, one-time only)...")
            print("This may take 1-2 minutes depending on your network. Please wait...")
            import subprocess
            import sys
            try:
                if getattr(sys, "frozen", False):
                    print("[LLM Pool] Running from exe (onedir). Browser install from frozen may fail; pre-install with source python before build or use --install-browser.")
                subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium", "--with-deps"])
                print("[LLM Pool] Browser installed successfully! Proceeding with login...")
                _browser_checked = True
                return True
            except Exception as install_err:
                print(f"[LLM Pool] Auto-install failed: {install_err}")
                print("Please run manually: python -m playwright install chromium (from source python recommended for exe builds)")
                record_diagnostic_event("error", "browser_auto_install_failed", error=str(install_err))
                raise HTTPException(500, "Failed to auto-install browser. Please install manually and restart.")
        record_diagnostic_event("error", "browser_check_failed", error=str(e))
        raise

async def extract_cookies_with_playwright(email: str, password: str, provider: str) -> Dict[str, str]:
    """
    Headless login to get session cookies.
    User just inputs email+password in the UI/API.
    This is the "direct account password" flow.
    Risk: May trigger account review / captcha / 2FA. User accepts.
    """
    await ensure_browsers_installed()

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise HTTPException(500, "playwright not installed in env. pip install playwright && playwright install chromium")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        cookies = {}

        if provider == "web_gemini":
            # Go to gemini, trigger Google login flow
            await page.goto("https://gemini.google.com/")
            # Click sign in if needed
            try:
                await page.get_by_role("button", name="Sign in").click(timeout=5000)
            except:
                pass

            # The flow goes to accounts.google.com
            # Fill email
            await page.fill('input[type="email"]', email, timeout=10000)
            await page.click('button:has-text("Next")')
            await page.wait_for_timeout(1500)

            # Password
            await page.fill('input[type="password"]', password)
            await page.click('button:has-text("Next")')

            # Wait for redirect back to gemini
            await page.wait_for_url("**/gemini.google.com/**", timeout=30000)

            # Extract the important cookies
            all_cookies = await context.cookies()
            for c in all_cookies:
                if c["name"] in ["__Secure-1PSID", "__Secure-1PSIDTS", "__Secure-1PSIDCC"]:
                    cookies[c["name"]] = c["value"]

            if not cookies.get("__Secure-1PSID"):
                # Sometimes needs more wait or "continue" button
                await page.wait_for_timeout(3000)
                all_cookies = await context.cookies()
                for c in all_cookies:
                    if c["name"].startswith("__Secure-1PSID"):
                        cookies[c["name"]] = c["value"]
            if not cookies:
                raise RuntimeError("Login may have failed (2FA, captcha, or UI change). Please login manually in browser and paste cookies instead of using password.")

        elif provider == "web_claude":
            await page.goto("https://claude.ai/login")
            # For modern Claude, often magic link or SSO. For password accounts:
            try:
                await page.fill('input[type="email"]', email)
                await page.click('button:has-text("Continue")')
                await page.wait_for_timeout(1500)
                await page.fill('input[type="password"]', password)
                await page.click('button:has-text("Continue")')
                await page.wait_for_url("**/claude.ai/**", timeout=30000)
            except:
                pass
            all_cookies = await context.cookies()
            for c in all_cookies:
                if "claude" in c.get("domain", "") or c["name"] in ["sessionKey", "intercom-session"]:
                    cookies[c["name"]] = c["value"]

        elif provider in ("web_chatgpt", "web_codex"):
            # Two categories for GPT accounts:
            # - web_chatgpt: chatgpt.com general web quota
            # - web_codex: GPT account used for Codex/Copilot coding tools (separate or additional quotas)
            target = "https://chatgpt.com/" if provider == "web_chatgpt" else "https://chatgpt.com/"  # or copilot.github.com
            await page.goto(target)
            try:
                # Common OpenAI login
                await page.get_by_role("button", name="Log in").click(timeout=5000)
            except:
                pass
            await page.fill('input[type="email"]', email)
            await page.click('button:has-text("Continue")')
            await page.wait_for_timeout(1500)
            await page.fill('input[type="password"]', password)
            await page.click('button:has-text("Continue")')
            await page.wait_for_url("**/chatgpt.com/**", timeout=30000)
            # For codex, after login, optionally navigate to account or copilot settings to "activate" the quota
            if provider == "web_codex":
                await page.goto("https://chatgpt.com/#settings", timeout=10000)
                await page.wait_for_timeout(2000)
            all_cookies = await context.cookies()
            for c in all_cookies:
                domain = c.get("domain", "")
                if "openai" in domain or "chatgpt" in domain or c["name"].startswith("_"):
                    cookies[c["name"]] = c["value"]

        await browser.close()
        return cookies

# ==================== API ====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup messages are now in main() for a clearer local desktop experience.
    yield
    print("Shutting down browsers...")
    for ctx in list(_web_contexts.values()):
        try:
            await ctx.close()
        except Exception:
            pass
    if _playwright:
        try:
            await _playwright.stop()
        except Exception:
            pass
    print("Shutdown complete.")

def parse_csv_env(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]

CORS_ORIGINS = parse_csv_env("CORS_ORIGINS")
CORS_ORIGIN_REGEX = os.getenv(
    "CORS_ORIGIN_REGEX",
    r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$",
)

app = FastAPI(title="LLM API Pool", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-Token", "X-Api-Key"],
)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    """Serve the external dashboard.html.
    - Fast Python startup (small main.py, external html)
    - Works when run as python or as PyInstaller exe (onefile extracts assets to _MEIPASS)
    - Same dashboard.html can be dropped as index.html on GitHub Pages for the static "web version" UI (just enter your backend URL once).
    """
    try:
        p = get_resource_path("dashboard.html")
        with open(p, "r", encoding="utf-8") as f:
            text = f.read()
        if GENERATED_ADMIN_TOKEN and request.client and request.client.host in {"127.0.0.1", "::1", "localhost"}:
            bootstrap = (
                "<script>"
                f"window.__LLM_POOL_BOOTSTRAP__={{adminToken:{json.dumps(ADMIN_TOKEN)},generatedAdminToken:true}};"
                "</script>"
            )
            text = text.replace("</head>", f"{bootstrap}\n</head>", 1)
        return HTMLResponse(text)
    except Exception as e:
        details = ""
        if DEBUG_ERRORS:
            app_dir = html.escape(str(get_app_dir()))
            meip = html.escape(str(getattr(sys, "_MEIPASS", None)))
            err = html.escape(str(e))
            details = f"<p>Error: {err}</p><p>cwd/app_dir: {app_dir}</p><p>_MEIPASS: {meip}</p>"
        return HTMLResponse(
            "<h1>dashboard.html not found</h1>"
            "<p>Make sure dashboard.html is next to the exe or source file, then rebuild if needed.</p>"
            f"{details}",
            status_code=404,
        )

@app.get("/health")
async def health():
    return {"status": "ok", "channels": len(CHANNELS), "arch": runtime_info()["arch"]}

def new_channel_id() -> str:
    while True:
        cid = uuid.uuid4().hex[:12]
        if not any(c.get("id") == cid for c in CHANNELS):
            return cid

def is_loopback_bind(host: str) -> bool:
    return (host or "").lower() in {"127.0.0.1", "localhost", "::1"}

def runtime_info() -> dict:
    arch = os.getenv("PROCESSOR_ARCHITEW6432") or os.getenv("PROCESSOR_ARCHITECTURE") or platform.machine() or "unknown"
    return {
        "host": HOST,
        "port": PORT,
        "arch": arch,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "admin_token_generated": GENERATED_ADMIN_TOKEN,
        "api_token_required": bool(API_TOKEN),
        "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
        "secrets_encryption": "dpapi" if _is_windows() else "plaintext-fallback",
    }

def validate_startup_security():
    if not is_loopback_bind(HOST):
        if GENERATED_ADMIN_TOKEN:
            raise SystemExit("Refusing non-local bind without explicit ADMIN_TOKEN.")
        if not API_TOKEN:
            raise SystemExit("Refusing non-local bind without API_TOKEN.")

def channel_diagnostics() -> List[Dict[str, Any]]:
    rows = []
    for ch in CHANNELS:
        cfg = ch.get("config") or {}
        rows.append({
            "id": ch.get("id"),
            "type": ch.get("type"),
            "name": ch.get("name"),
            "config": redact_config(cfg),
            "secret_fields_present": sorted([key for key in SECRET_CONFIG_KEYS if cfg.get(key)]),
            "has_web_context": bool(ch.get("id") in _web_contexts),
            "stats": sanitize_for_diagnostics(ch.get("stats", {})),
        })
    return rows

def diagnostics_payload() -> Dict[str, Any]:
    return {
        "timestamp": time.time(),
        "runtime": runtime_info(),
        "paths": {
            "app_dir": safe_path_for_diagnostics(get_app_dir()),
            "channels_file": safe_path_for_diagnostics(CHANNELS_FILE),
            "channels_file_exists": os.path.exists(CHANNELS_FILE),
        },
        "security": {
            "admin_token_required": require_admin_token(),
            "admin_token_generated": GENERATED_ADMIN_TOKEN,
            "api_token_required": bool(API_TOKEN),
            "remote_bind": not is_loopback_bind(HOST),
            "cors_origins": CORS_ORIGINS,
            "cors_origin_regex": CORS_ORIGIN_REGEX,
            "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
            "secrets_encryption": "dpapi" if _is_windows() else "plaintext-fallback",
        },
        "browser": {
            "playwright_checked": _browser_checked,
            "open_contexts": len(_web_contexts),
        },
        "channels": channel_diagnostics(),
        "router_status": router.get_status(),
        "events": list(DIAGNOSTIC_EVENTS),
    }

@app.get("/admin/diagnostics")
async def diagnostics(_admin: None = Depends(require_admin)):
    return diagnostics_payload()

@app.get("/admin/channels")
async def list_channels(_admin: None = Depends(require_admin)):
    return [
        {
            "id": c["id"],
            "type": c["type"],
            "name": c["name"],
            "config": redact_config(c.get("config", {}))
        }
        for c in CHANNELS
    ]

@app.post("/admin/channels")
async def add_channel(body: AddChannelRequest, _admin: None = Depends(require_admin)):
    if not body.type or body.type not in VALID_CHANNEL_TYPES:
        raise HTTPException(400, f"type must be one of: {', '.join(sorted(VALID_CHANNEL_TYPES))}")
    cid = new_channel_id()
    ch = {
        "id": cid,
        "type": body.type,
        "name": body.name or f"{body.type}-{cid}",
        "config": {}
    }

    if body.type.startswith("official_"):
        if not body.api_key:
            raise HTTPException(400, "api_key required for official")
        ch["config"]["api_key"] = body.api_key
    else:
        # web (including codex as separate GPT account category for quotas)
        if body.cookies:
            ch["config"]["cookies"] = body.cookies
            ch["config"]["email"] = body.email
        elif body.email and body.password:
            print(f"[login] Attempting headless login for {body.type} {body.email}")
            try:
                cookies = await extract_cookies_with_playwright(body.email, body.password, body.type)
                ch["config"]["cookies"] = cookies
                ch["config"]["email"] = body.email
                print(f"[login] Success for {body.type}")
                record_diagnostic_event("info", "web_login_succeeded", type=body.type)
            except Exception as e:
                print(f"[login] Failed: {e}")
                record_diagnostic_event("warn", "web_login_failed", type=body.type, error=str(e))
                # Note: For accounts with 2FA/SMS/captcha, password login often fails or requires interaction.
                # Strongly recommend: login manually in real browser, then paste the cookies JSON in the form.
                # Password mode works best for simple no-2FA accounts.
                raise HTTPException(400, f"Web login failed. Paste cookies instead. Detail: {str(e)[:180]}")
        else:
            raise HTTPException(400, "For web channel provide cookies or email+password")

        if body.type == "web_codex":
            ch["config"]["quota_category"] = body.quota_category or "codex"
            ch["config"]["quota"] = body.quota or ch["config"].get("quota", 300)
        elif "chatgpt" in body.type:
            ch["config"]["quota_category"] = body.quota_category or "chat"
            ch["config"]["quota"] = body.quota or ch["config"].get("quota", 100000)

    if body.quota is not None:
        ch["config"]["quota"] = body.quota
    if body.quota_category:
        ch["config"]["quota_category"] = body.quota_category
    if body.aliases:
        ch["config"]["aliases"] = body.aliases
    if body.priority is not None:
        ch["config"]["priority"] = body.priority
    if body.max_concurrent is not None:
        ch["config"]["max_concurrent"] = body.max_concurrent
    if body.default_model:
        ch["config"]["default_model"] = body.default_model

    async with _channels_lock:
        CHANNELS.append(ch)
        save_channels()
    record_diagnostic_event("info", "channel_added", channel_id=cid, type=ch["type"], name=ch["name"])
    return {"id": cid, "status": "added", "note": "For web with password, cookies were extracted if successful."}

@app.put("/admin/channels/{cid}")
async def update_channel(cid: str, body: AddChannelRequest, _admin: None = Depends(require_admin)):
    async with _channels_lock:
        for i, ch in enumerate(CHANNELS):
            if ch["id"] == cid:
                ch_type = body.type or ch["type"]
                if ch_type not in VALID_CHANNEL_TYPES:
                    raise HTTPException(400, f"type must be one of: {', '.join(sorted(VALID_CHANNEL_TYPES))}")
                ch["type"] = ch_type
                if body.name:
                    ch["name"] = body.name
                if ch_type.startswith("official_") and not (body.api_key or ch["config"].get("api_key")):
                    raise HTTPException(400, "api_key required for official")
                if not ch_type.startswith("official_") and not (body.cookies or ch["config"].get("cookies")):
                    raise HTTPException(400, "cookies required for web updates; password refresh is handled by re-adding the channel")
                if ch_type.startswith("official_") and body.api_key:
                    ch["config"]["api_key"] = body.api_key
                else:
                    if body.cookies:
                        ch["config"]["cookies"] = body.cookies
                    if body.email:
                        ch["config"]["email"] = body.email
                    # password not updated this way for security
                if body.quota is not None:
                    ch["config"]["quota"] = body.quota
                if body.quota_category:
                    ch["config"]["quota_category"] = body.quota_category
                if body.aliases:
                    ch["config"]["aliases"] = body.aliases
                if body.priority is not None:
                    ch["config"]["priority"] = body.priority
                if body.max_concurrent is not None:
                    ch["config"]["max_concurrent"] = body.max_concurrent
                    router.sems.pop(cid, None)
                if body.default_model:
                    ch["config"]["default_model"] = body.default_model
                save_channels()
                record_diagnostic_event("info", "channel_updated", channel_id=cid, type=ch["type"], name=ch["name"])
                return {"id": cid, "status": "updated"}
    raise HTTPException(404, "Channel not found")

@app.delete("/admin/channels/{cid}")
async def delete_channel(cid: str, _admin: None = Depends(require_admin)):
    global CHANNELS
    async with _channels_lock:
        deleted = next((c for c in CHANNELS if c["id"] == cid), None)
        if not deleted:
            raise HTTPException(404, "Channel not found")
        CHANNELS = [c for c in CHANNELS if c["id"] != cid]
        save_channels()
    # Cleanup browser context to free resources (important for long-running exe with many add/delete cycles)
    if cid in _web_contexts:
        try:
            await _web_contexts[cid].close()
        except Exception:
            pass
        _web_contexts.pop(cid, None)
    router.sems.pop(cid, None)
    router.stats.pop(cid, None)
    router.cooldowns.pop(cid, None)
    record_diagnostic_event("info", "channel_deleted", channel_id=cid, type=deleted.get("type"), name=deleted.get("name"))
    return {"deleted": cid}

# ==================== Unified API Endpoints (OpenAI + Anthropic selectable) ====================

@app.post("/v1/chat/completions")
async def chat_completions(body: dict, _api: None = Depends(require_api_access)):
    """OpenAI compatible. Agents can choose this format."""
    canon = openai_to_canonical(body)
    ch = router.select(canon)
    if not ch:
        record_diagnostic_event("warn", "no_suitable_channel", endpoint="/v1/chat/completions", model=canon.model)
        raise HTTPException(503, "No suitable channels in pool (all cooldown or incompatible).")

    canon.model = router.resolve_model(ch, canon.model)
    backend = BACKENDS.get(ch["type"])
    if not backend:
        raise HTTPException(400, f"No backend for {ch['type']}")

    await router.acquire(ch)
    start = time.time()
    success = False
    tokens_est = 0
    headers = {}
    try:
        if canon.stream:
            # Optimized architecture: real streaming for official (low latency for agents), best effort for web using drive
            success = True
            async def streamer():
                nonlocal tokens_est, success
                try:
                    async for chunk in backend.stream(canon, ch):
                        content = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "") or ""
                        tokens_est += max(0, len(content) // 4)
                        yield f"data: {json.dumps(chunk)}\n\n"
                    yield "data: [DONE]\n\n"
                except Exception as e:
                    success = False
                    record_diagnostic_event("error", "upstream_stream_failed", endpoint="/v1/chat/completions", channel_id=ch.get("id"), type=ch.get("type"), name=ch.get("name"), error=str(e))
                    yield f"data: {json.dumps({'error': {'message': str(e)[:180]}})}\n\n"
                    yield "data: [DONE]\n\n"
                finally:
                    latency = time.time() - start
                    router.record_result(ch, success, latency, tokens_est, headers)
                    router.release(ch)
                    router.throttled_save()
            return StreamingResponse(streamer(), media_type="text/event-stream")
        else:
            resp, headers = await backend.generate(canon, ch)
            success = True
            tokens_est = ch.get("stats", {}).get("last_estimated_tokens") or resp.usage.get("total_tokens", 0) or (len(str(canon.messages)) + 200) // 4
            result = canonical_to_openai(resp, stream=False)
            return JSONResponse(result)
    except Exception as e:
        print(f"[pool] {ch['name']} failed: {e}")
        err_str = str(e)
        if err_str.startswith("WEB_RATE_LIMIT"):
            success = False
            record_diagnostic_event("warn", "web_channel_rate_limited", endpoint="/v1/chat/completions", channel_id=ch.get("id"), type=ch.get("type"), name=ch.get("name"))
            raise HTTPException(429, "Web channel rate limited, cooled down")
        record_diagnostic_event("error", "upstream_failed", endpoint="/v1/chat/completions", channel_id=ch.get("id"), type=ch.get("type"), name=ch.get("name"), error=err_str)
        raise HTTPException(502, f"Upstream error: {err_str[:180]}")
    finally:
        if not canon.stream:
            latency = time.time() - start
            router.record_result(ch, success, latency, tokens_est, headers)
            router.release(ch)
            router.throttled_save()

@app.post("/v1/messages")
async def anthropic_messages(body: dict, _api: None = Depends(require_api_access)):
    """Anthropic compatible. For Claude Code, Cline, etc. Selectable format."""
    canon = anthropic_to_canonical(body)
    ch = router.select(canon)
    if not ch:
        record_diagnostic_event("warn", "no_suitable_channel", endpoint="/v1/messages", model=canon.model)
        raise HTTPException(503, "No suitable channels (try adding claude web/official).")

    canon.model = router.resolve_model(ch, canon.model)
    backend = BACKENDS.get(ch["type"])
    if not backend:
        raise HTTPException(400, f"No backend for {ch['type']}")

    await router.acquire(ch)
    start = time.time()
    success = False
    tokens_est = 0
    headers = {}
    try:
        if canon.stream:
            # Support real stream for anthropic too (using backend.stream for consistency and feasibility)
            success = True
            async def streamer():
                nonlocal tokens_est, success
                def event(name: str, data: dict) -> str:
                    return f"event: {name}\ndata: {json.dumps(data)}\n\n"

                message_id = f"msg_{uuid.uuid4().hex}"
                yield event("message_start", {
                    "type": "message_start",
                    "message": {
                        "id": message_id,
                        "type": "message",
                        "role": "assistant",
                        "model": canon.model,
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 0, "output_tokens": 0},
                    },
                })
                yield event("content_block_start", {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                })
                try:
                    async for chunk in backend.stream(canon, ch):
                        content = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "") or ""
                        if not content:
                            continue
                        tokens_est += max(0, len(content) // 4)
                        yield event("content_block_delta", {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {"type": "text_delta", "text": content},
                        })
                    yield event("content_block_stop", {"type": "content_block_stop", "index": 0})
                    yield event("message_delta", {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                        "usage": {"output_tokens": tokens_est},
                    })
                    yield event("message_stop", {"type": "message_stop"})
                except Exception as e:
                    success = False
                    record_diagnostic_event("error", "upstream_stream_failed", endpoint="/v1/messages", channel_id=ch.get("id"), type=ch.get("type"), name=ch.get("name"), error=str(e))
                    yield event("error", {
                        "type": "error",
                        "error": {"type": "api_error", "message": str(e)[:180]},
                    })
                finally:
                    latency = time.time() - start
                    router.record_result(ch, success, latency, tokens_est, headers)
                    router.release(ch)
                    router.throttled_save()
            return StreamingResponse(streamer(), media_type="text/event-stream")
        else:
            resp, headers = await backend.generate(canon, ch)
            success = True
            tokens_est = ch.get("stats", {}).get("last_estimated_tokens") or resp.usage.get("total_tokens", 0)
            result = canonical_to_anthropic(resp, stream=False)
            return JSONResponse(result)
    except Exception as e:
        record_diagnostic_event("error", "upstream_failed", endpoint="/v1/messages", channel_id=ch.get("id"), type=ch.get("type"), name=ch.get("name"), error=str(e))
        raise HTTPException(502, f"Upstream: {str(e)[:180]}")
    finally:
        if not canon.stream:
            latency = time.time() - start
            router.record_result(ch, success, latency, tokens_est, headers)
            router.release(ch)
            router.throttled_save()

@app.get("/v1/models")
async def list_models(_api: None = Depends(require_api_access)):
    """Basic models list for both formats."""
    models = []
    for ch in CHANNELS:
        t = ch["type"]
        default_model = ch.get("config", {}).get("default_model") or DEFAULT_MODELS.get(t)
        if default_model:
            models.append({"id": default_model, "owned_by": ch["name"]})
        for alias, model in (ch.get("config", {}).get("aliases", {}) or {}).items():
            models.append({"id": alias, "owned_by": ch["name"], "root": model})
    return {"object": "list", "data": models}

# Status & monitoring (real-time quotas, health, for agents and dashboard)
@app.get("/admin/status")
async def pool_status(_admin: None = Depends(require_admin)):
    return {
        "channels": router.get_status(),
        "total_channels": len(CHANNELS),
        "timestamp": time.time(),
        "runtime": runtime_info(),
    }

# (duplicate stub removed - we have full /v1/messages above using canonical + smart router)

def main():
    global HOST, PORT
    parser = argparse.ArgumentParser(description="LLM API Pool - Unified OpenAI/Anthropic proxy with web sessions")
    parser.add_argument("--host", default=HOST, help="Host to bind (default 127.0.0.1 for local)")
    parser.add_argument("--port", type=int, default=PORT, help="Port (default 8080)")
    parser.add_argument("--no-open", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--open-browser-delay", type=int, default=2, help="Seconds to wait before opening browser")
    parser.add_argument("--install-browser", action="store_true", help="Install Playwright Chromium for web login features (run once)")
    args = parser.parse_args()

    if args.install_browser:
        print("Installing Playwright Chromium for web sessions...")
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])
        print("Browser installed successfully. You can now use email+password web logins.")
        return

    HOST = args.host
    PORT = args.port
    validate_startup_security()

    print("=" * 60)
    print("LLM API Pool started")
    print(f"  Dashboard:   http://{HOST}:{PORT}/")
    print(f"  OpenAI API:  http://{HOST}:{PORT}/v1/chat/completions")
    print(f"  Anthropic API: http://{HOST}:{PORT}/v1/messages")
    print(f"  Status:      http://{HOST}:{PORT}/admin/status")
    print(f"  Architecture: {runtime_info()['arch']}")
    if GENERATED_ADMIN_TOKEN:
        print(f"  Local admin token: {ADMIN_TOKEN}")
        print("  The local dashboard receives this token automatically on loopback.")
    print("=" * 60)
    print("Open the dashboard URL in your browser to manage accounts and monitor the pool.")
    record_diagnostic_event("info", "server_starting", runtime=runtime_info())

    if not args.no_open:
        def open_browser():
            time.sleep(args.open_browser_delay)
            try:
                webbrowser.open(f"http://{HOST}:{PORT}/")
            except Exception as e:
                print(f"Could not auto-open browser: {e}")
        threading.Thread(target=open_browser, daemon=True).start()

    import uvicorn
    # Pass the app object directly (not string "main:app"). Critical for PyInstaller onefile bundles
    # where re-importing the 'main' module by name fails.
    uvicorn.run(app, host=HOST, port=PORT, reload=False, log_level="info")

if __name__ == "__main__":
    import argparse
    import webbrowser
    import threading
    import time
    main()

