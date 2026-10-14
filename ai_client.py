# -*- coding: utf-8 -*-
"""大模型接入客户端：OpenAI 兼容协议（/chat/completions、/models）。

只用标准库实现，理由见 docs/AI智能运维方案.md 决策 9：
requirements.txt 里没有 requests，容器内也不会有；urllib 自带代理支持，
换厂商只需要改 base_url。

约定：
- 任何异常都是 AiClientError，且 **绝不含 API Key**（错误信息统一过 redact）。
- 流式解析只认结构化字段：正文里的 JSON 文本永远不会被当成工具调用。
"""
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

KIND_NETWORK = "network"
KIND_TIMEOUT = "timeout"
KIND_AUTH = "auth"
KIND_NOT_FOUND = "not_found"
KIND_RATE_LIMIT = "rate_limit"
KIND_BAD_REQUEST = "bad_request"
KIND_SERVER = "server"
KIND_PROTOCOL = "protocol"
KIND_CANCELED = "canceled"

_ERROR_HINTS = {
    KIND_NETWORK: "无法连接到大模型服务，请检查地址、网络与代理",
    KIND_TIMEOUT: "大模型服务响应超时，可在配置里调大超时时间",
    KIND_AUTH: "鉴权失败，请检查 API Key 是否正确、是否已过期",
    KIND_NOT_FOUND: "地址或模型不存在，请检查 base_url 是否带 /v1、模型名是否正确",
    KIND_RATE_LIMIT: "被限流或额度不足，请稍后重试或检查账户余额",
    KIND_BAD_REQUEST: "请求被拒绝（参数或模型不支持，例如不支持流式输出/工具调用）",
    KIND_SERVER: "大模型服务内部错误，请稍后重试",
    KIND_PROTOCOL: "返回内容无法解析，可能不是 OpenAI 兼容接口",
    KIND_CANCELED: "已取消",
}


class AiClientError(Exception):
    """带分类的大模型调用异常。"""

    def __init__(self, message, kind=KIND_PROTOCOL, status=None):
        super().__init__(message)
        self.kind = kind
        self.status = status

    @property
    def hint(self):
        return _ERROR_HINTS.get(self.kind, "调用大模型失败")


def classify_status(status: int) -> str:
    if status in (401, 403):
        return KIND_AUTH
    if status == 404:
        return KIND_NOT_FOUND
    if status == 429:
        return KIND_RATE_LIMIT
    if status in (400, 405, 415, 422):
        return KIND_BAD_REQUEST
    if status >= 500:
        return KIND_SERVER
    return KIND_PROTOCOL


def redact(text, secrets=()):
    """把密钥一类的内容替换掉；日志、审计、错误信息、出站内容都要过这里。"""
    value = "" if text is None else str(text)
    for secret in secrets or ():
        if secret and len(str(secret)) >= 6:
            value = value.replace(str(secret), "***")
    return value


def mask_key(api_key: str) -> str:
    """只回显尾部片段，界面上永远拿不到完整 Key。"""
    key = (api_key or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return f"{key[:3]}****{key[-4:]}"


class _LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """限制跳转次数与协议，避免被诱导到 file:// 或无限跳转。"""

    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scheme = urllib.parse.urlparse(newurl).scheme
        if scheme not in ("http", "https"):
            raise urllib.error.HTTPError(newurl, code, "不允许的重定向协议", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_url(base_url: str, path: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise AiClientError("未配置大模型地址", KIND_BAD_REQUEST)
    return base + path


class OpenAIChatClient:
    """一个 provider 对应一个客户端实例。"""

    def __init__(self, base_url, api_key=None, model="", timeout=120, connect_timeout=10,
                 verify_tls=True, ca_bundle=None, proxy=None, extra_headers=None,
                 secrets=()):
        self.base_url = (base_url or "").strip()
        self.api_key = (api_key or "").strip()
        self.model = (model or "").strip()
        self.timeout = max(5, int(timeout or 120))
        self.connect_timeout = max(1, int(connect_timeout or 10))
        self.verify_tls = bool(verify_tls)
        self.ca_bundle = (ca_bundle or "").strip() or None
        self.proxy = (proxy or "").strip() or None
        self.extra_headers = dict(extra_headers or {})
        self.secrets = tuple(list(secrets or ()) + ([self.api_key] if self.api_key else []))
        self._opener = self._build_opener()

    # ---------- 传输层 ----------
    def _build_opener(self):
        if self.verify_tls:
            context = ssl.create_default_context(cafile=self.ca_bundle)
        else:
            context = ssl._create_unverified_context()
        handlers = [
            urllib.request.HTTPSHandler(context=context),
            _LimitedRedirectHandler(),
        ]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        return urllib.request.build_opener(*handlers)

    def _open(self, path, payload, accept):
        url = build_url(self.base_url, path)
        data = None
        headers = {
            "Accept": accept,
            "User-Agent": "ops-inspection-ai/1.0",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        headers.update(self.extra_headers)
        request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        try:
            return self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            raise AiClientError(self._http_error_message(exc), classify_status(exc.code), exc.code)
        except ssl.SSLError as exc:
            raise AiClientError(f"TLS 握手失败：{redact(exc, self.secrets)}", KIND_NETWORK)
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise AiClientError("连接大模型服务超时", KIND_TIMEOUT)
            raise AiClientError(f"无法连接大模型服务：{redact(reason, self.secrets)}", KIND_NETWORK)
        except (socket.timeout, TimeoutError):
            raise AiClientError("连接大模型服务超时", KIND_TIMEOUT)
        except OSError as exc:
            raise AiClientError(f"网络错误：{redact(exc, self.secrets)}", KIND_NETWORK)

    def _http_error_message(self, exc):
        detail = ""
        try:
            raw = exc.read()
            body = json.loads(raw.decode("utf-8", "ignore"))
            if isinstance(body, dict):
                error = body.get("error")
                if isinstance(error, dict):
                    detail = error.get("message") or error.get("type") or ""
                elif isinstance(error, str):
                    detail = error
                detail = detail or body.get("message") or body.get("detail") or ""
        except Exception:
            detail = ""
        detail = redact(str(detail)[:400], self.secrets)
        text = f"HTTP {exc.code} {exc.reason or ''}".strip()
        return f"{text}：{detail}" if detail else text

    # ---------- 对话 ----------
    def chat(self, messages, tools=None, temperature=None, max_tokens=None,
             stream=False, on_delta=None, cancel=None):
        """一次补全。stream=True 时逐片回调 on_delta(text)。

        返回 {"content", "tool_calls", "usage", "finish_reason"}；
        tool_calls 为 [{"id", "name", "arguments", "args"}]。
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": bool(stream),
        }
        if temperature is not None:
            payload["temperature"] = float(temperature)
        if max_tokens:
            payload["max_tokens"] = int(max_tokens)
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
            # Onboarding is ordered: create/update server -> discover -> import.
            # Prevent providers from racing dependent tool calls in one turn.
            payload["parallel_tool_calls"] = False
        if stream:
            return self._chat_stream(payload, on_delta, cancel)
        return self._chat_once(payload)

    def _chat_once(self, payload):
        response = self._open("/chat/completions", payload, "application/json")
        try:
            body = json.loads(response.read().decode("utf-8", "ignore") or "{}")
        except json.JSONDecodeError:
            raise AiClientError("返回内容不是合法 JSON，可能不是 OpenAI 兼容接口", KIND_PROTOCOL)
        finally:
            response.close()
        if isinstance(body, dict) and body.get("error"):
            raise AiClientError(redact(_error_text(body["error"]), self.secrets), KIND_BAD_REQUEST)
        choices = body.get("choices") or []
        if not choices:
            raise AiClientError("返回内容里没有 choices", KIND_PROTOCOL)
        message = choices[0].get("message") or {}
        return {
            "content": _content_text(message.get("content")),
            "tool_calls": _normalize_tool_calls(message.get("tool_calls")),
            "usage": body.get("usage") or {},
            "finish_reason": choices[0].get("finish_reason") or "",
        }

    def _chat_stream(self, payload, on_delta, cancel):
        payload = dict(payload)
        # include_usage 是 OpenAI 的扩展，部分服务不认识会直接 400。
        payload["stream_options"] = {"include_usage": True}
        try:
            response = self._open("/chat/completions", payload, "text/event-stream")
        except AiClientError as exc:
            if exc.kind != KIND_BAD_REQUEST:
                raise
            payload.pop("stream_options", None)
            response = self._open("/chat/completions", payload, "text/event-stream")

        content_parts = []
        tool_calls = {}
        usage = {}
        finish_reason = ""
        try:
            for raw_line in response:
                if cancel is not None and cancel.is_set():
                    raise AiClientError("已取消", KIND_CANCELED)
                line = raw_line.decode("utf-8", "ignore").strip()
                if not line or line.startswith(":"):
                    continue
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if isinstance(chunk, dict) and chunk.get("error"):
                    raise AiClientError(redact(_error_text(chunk["error"]), self.secrets),
                                        KIND_BAD_REQUEST)
                if chunk.get("usage"):
                    usage = chunk["usage"] or {}
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                choice = choices[0] or {}
                if choice.get("finish_reason"):
                    finish_reason = choice["finish_reason"]
                delta = choice.get("delta") or choice.get("message") or {}
                text = _content_text(delta.get("content"))
                if text:
                    content_parts.append(text)
                    if on_delta:
                        on_delta(text)
                for item in delta.get("tool_calls") or []:
                    slot = tool_calls.setdefault(item.get("index", 0),
                                                 {"id": "", "name": "", "arguments": ""})
                    if item.get("id"):
                        slot["id"] = item["id"]
                    function = item.get("function") or {}
                    if function.get("name"):
                        slot["name"] = function["name"]
                    if function.get("arguments"):
                        slot["arguments"] += function["arguments"]
        except (socket.timeout, TimeoutError):
            raise AiClientError("读取大模型响应超时", KIND_TIMEOUT)
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise AiClientError("读取大模型响应超时", KIND_TIMEOUT)
            raise AiClientError(f"流式连接中断：{redact(reason, self.secrets)}", KIND_NETWORK)
        finally:
            try:
                response.close()
            except Exception:  # pragma: no cover - 关闭失败不影响结果
                pass

        return {
            "content": "".join(content_parts),
            "tool_calls": _finalize_tool_calls(tool_calls),
            "usage": usage,
            "finish_reason": finish_reason,
        }

    # ---------- 运维辅助 ----------
    def list_models(self):
        response = self._open("/models", None, "application/json")
        try:
            body = json.loads(response.read().decode("utf-8", "ignore") or "{}")
        except json.JSONDecodeError:
            raise AiClientError("模型列表不是合法 JSON", KIND_PROTOCOL)
        finally:
            response.close()
        items = body.get("data") if isinstance(body, dict) else None
        if not isinstance(items, list):
            items = body if isinstance(body, list) else []
        models = []
        for item in items:
            if isinstance(item, dict) and item.get("id"):
                models.append(str(item["id"]))
            elif isinstance(item, str):
                models.append(item)
        return sorted(set(models))

    def test_connection(self):
        """先试 /models，服务不支持就退化成一次 max_tokens=1 的最小对话。"""
        try:
            models = self.list_models()
            return {"ok": True, "models": models,
                    "message": f"连接成功，可用模型 {len(models)} 个" if models else "连接成功"}
        except AiClientError as exc:
            if exc.kind not in (KIND_NOT_FOUND, KIND_PROTOCOL, KIND_BAD_REQUEST):
                return {"ok": False, "models": [], "message": str(exc), "kind": exc.kind}
        try:
            result = self.chat(
                [{"role": "user", "content": "ping"}],
                temperature=0, max_tokens=1, stream=False,
            )
            if result.get("content") is None and not result.get("finish_reason"):
                raise AiClientError("对话接口没有返回内容", KIND_PROTOCOL)
            return {"ok": True, "models": [], "message": "连接成功（该服务未提供模型列表接口）"}
        except AiClientError as exc:
            return {"ok": False, "models": [], "message": str(exc), "kind": exc.kind}


def _content_text(content):
    """兼容 string 与 [{type:text,text:...}] 两种 content 形态。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or ""))
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    return str(content)


def _error_text(error):
    if isinstance(error, dict):
        return str(error.get("message") or error.get("type") or error)
    return str(error)


def _normalize_tool_calls(raw_calls):
    slots = {}
    for index, item in enumerate(raw_calls or []):
        if not isinstance(item, dict):
            continue
        function = item.get("function") or {}
        slots[index] = {
            "id": item.get("id") or f"call_{index}",
            "name": function.get("name") or item.get("name") or "",
            "arguments": function.get("arguments") or "",
        }
    return _finalize_tool_calls(slots)


def _finalize_tool_calls(slots):
    result = []
    for index in sorted(slots):
        item = slots[index]
        raw_args = item.get("arguments") or ""
        try:
            args = json.loads(raw_args) if raw_args.strip() else {}
        except json.JSONDecodeError:
            args = {}
        if not isinstance(args, dict):
            args = {}
        result.append({
            "id": item.get("id") or f"call_{index}",
            "name": item.get("name") or "",
            "arguments": raw_args,
            "args": args,
        })
    return result
