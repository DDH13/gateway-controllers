# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Content safety guardrail using NVIDIA NeMo Guard (llama-3.1-nemoguard-8b-content-safety).

Buffers request and/or response bodies, extracts the relevant text via
configurable JSONPath expressions, and forwards the content to the NVIDIA
NeMo Guard content safety endpoint. Unsafe requests are rejected with a 400;
unsafe responses are replaced with a sanitised error message.

The model is a LoRA adapter on meta-llama/Llama-3.1-8B-Instruct served via
vLLM with --enable-lora. It accepts a structured prompt containing the safety
policy taxonomy and conversation, and returns a JSON assessment:
  {"User Safety": "safe|unsafe", "Response Safety": "safe|unsafe",
   "Safety Categories": "comma-separated category names"}

Categories S1-S23:
  S1 Violence, S2 Sexual, S3 Criminal Planning/Confessions,
  S4 Guns and Illegal Weapons, S5 Controlled/Regulated Substances,
  S6 Suicide and Self Harm, S7 Sexual (minor), S8 Hate/Identity Hate,
  S9 PII/Privacy, S10 Harassment, S11 Threat, S12 Profanity,
  S13 Needs Caution, S14 Other, S15 Manipulation, S16 Fraud/Deception,
  S17 Malware, S18 High Risk Gov Decision Making,
  S19 Political/Misinformation/Conspiracy,
  S20 Copyright/Trademark/Plagiarism, S21 Unauthorized Advice,
  S22 Illegal Activity, S23 Immoral/Unethical.
"""

from __future__ import annotations

import json
import logging
import re as _re
from typing import Any

import requests as http_client

from wso2_gateway_policy_sdk import (
    BodyProcessingMode,
    ExecutionContext,
    HeaderProcessingMode,
    ImmediateResponse,
    ProcessingMode,
    ResponsePolicy,
    RequestPolicy,
    UpstreamRequestModifications,
    DownstreamResponseModifications,
)
from wso2_gateway_policy_sdk.policy.v1alpha2.types import (
    PolicyMetadata,
    RequestContext,
    ResponseContext,
)

logger = logging.getLogger(__name__)

_PASSTHROUGH_REQUEST: UpstreamRequestModifications | None = None
_PASSTHROUGH_RESPONSE: DownstreamResponseModifications | None = None

# Safety policy taxonomy sent to the model in every prompt.
_SAFETY_POLICY = """\
S1: Violence
S2: Sexual
S3: Criminal Planning/Confessions
S4: Guns and Illegal Weapons
S5: Controlled/Regulated Substances
S6: Suicide and Self Harm
S7: Sexual (minor)
S8: Hate/Identity Hate
S9: PII/Privacy
S10: Harassment
S11: Threat
S12: Profanity
S13: Needs Caution
S14: Other
S15: Manipulation
S16: Fraud/Deception
S17: Malware
S18: High Risk Gov Decision Making
S19: Political/Misinformation/Conspiracy
S20: Copyright/Trademark/Plagiarism
S21: Unauthorized Advice
S22: Illegal Activity
S23: Immoral/Unethical"""

# Maps the full category names the model returns → S-codes used in policy params.
_CATEGORY_NAME_TO_CODE: dict[str, str] = {
    "violence": "S1",
    "sexual": "S2",
    "criminal planning/confessions": "S3",
    "criminal planning": "S3",
    "guns and illegal weapons": "S4",
    "controlled/regulated substances": "S5",
    "suicide and self harm": "S6",
    "sexual (minor)": "S7",
    "hate/identity hate": "S8",
    "pii/privacy": "S9",
    "harassment": "S10",
    "threat": "S11",
    "profanity": "S12",
    "needs caution": "S13",
    "other": "S14",
    "manipulation": "S15",
    "fraud/deception": "S16",
    "malware": "S17",
    "high risk gov decision making": "S18",
    "political/misinformation/conspiracy": "S19",
    "copyright/trademark/plagiarism": "S20",
    "unauthorized advice": "S21",
    "illegal activity": "S22",
    "immoral/unethical": "S23",
}

# Maps policy-param boolean key → S-code.
_CATEGORY_CODES: dict[str, str] = {
    "violence": "S1",
    "sexual": "S2",
    "criminal_planning": "S3",
    "guns_weapons": "S4",
    "regulated_substances": "S5",
    "suicide_self_harm": "S6",
    "sexual_minor": "S7",
    "hate_identity": "S8",
    "pii_privacy": "S9",
    "harassment": "S10",
    "threat": "S11",
    "profanity": "S12",
    "needs_caution": "S13",
    "other": "S14",
    "manipulation": "S15",
    "fraud_deception": "S16",
    "malware": "S17",
    "high_risk_gov": "S18",
    "misinformation": "S19",
    "copyright": "S20",
    "unauthorized_advice": "S21",
    "illegal_activity": "S22",
    "immoral_unethical": "S23",
}


def _blocked_codes(categories_cfg: dict) -> frozenset[str] | None:
    """Return the set of S-codes to block, or None to block all.

    None means no categories object configured → block everything (default).
    """
    if not isinstance(categories_cfg, dict) or not categories_cfg:
        return None
    return frozenset(
        code
        for key, code in _CATEGORY_CODES.items()
        if bool(categories_cfg.get(key, True))
    )


def _build_nemoguard_prompt(user_text: str, assistant_text: str | None = None) -> str:
    """Build the structured prompt required by the NVIDIA NeMo Guard model."""
    task = (
        "Check if there is unsafe content in the user or agent messages in the below "
        "conversation in accordance with our safety policy with the below categories. "
        "Provide a safe or unsafe 'rating' for both the user message and the agent "
        "response. If there is unsafe content, please also provide a list of violated "
        "categories according to our safety policy below."
    )

    conversation_lines = [f"user: {user_text}"]
    if assistant_text:
        conversation_lines.append(f"agent: {assistant_text}")

    output_schema = (
        '{"User Safety": safe or unsafe rating for the user message, '
        '"Response Safety": safe or unsafe rating for the agent response. '
        "Omit if no agent response present. "
        '"Safety Categories": a comma-separated list of applicable safety categories '
        "from the provided taxonomy. Omit if all safe.}"
    )

    return (
        f"Task: {task}\n"
        f"<BEGIN UNSAFE CONTENT CATEGORIES>\n{_SAFETY_POLICY}\n<END UNSAFE CONTENT CATEGORIES>\n"
        f"<BEGIN CONVERSATION>\n{chr(10).join(conversation_lines)}\n<END CONVERSATION>\n"
        f"Provide your safety assessment for the above conversation in the below output JSON format:\n"
        f"{output_schema}\n"
        f"Do not include anything other than the output JSON in your response.\n"
        f"Output JSON:"
    )


def _call_nemoguard(
    endpoint: str,
    api_key: str,
    model: str,
    timeout: int,
    messages: list[dict],
    check_phase: str = "request",
) -> tuple[bool, list[str]]:
    """Call the NVIDIA NeMo Guard endpoint. Returns (unsafe, [category_codes]).

    check_phase="request"  → inspects "User Safety" in the response JSON.
    check_phase="response" → inspects "Response Safety" in the response JSON.
    """
    user_text = next((m["content"] for m in messages if m["role"] == "user"), None)
    assistant_text = next((m["content"] for m in messages if m["role"] == "assistant"), None)

    if not user_text:
        return False, []

    prompt = _build_nemoguard_prompt(user_text, assistant_text)

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 200,
        "temperature": 0,
    }

    response = http_client.post(
        f"{endpoint}/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()

    raw: str = data["choices"][0]["message"]["content"].strip()

    try:
        result: dict = json.loads(raw)
    except json.JSONDecodeError:
        match = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if not match:
            logger.warning("nemoguard: could not parse model response as JSON: %r", raw[:200])
            return False, []
        result = json.loads(match.group())

    safety_key = "User Safety" if check_phase == "request" else "Response Safety"
    unsafe = result.get(safety_key, "safe").strip().lower() == "unsafe"

    if not unsafe:
        return False, []

    cats_str: str = result.get("Safety Categories", "")
    category_codes: list[str] = [
        _CATEGORY_NAME_TO_CODE.get(name.strip().lower(), name.strip())
        for name in cats_str.split(",")
        if name.strip()
    ]
    return True, category_codes


def _resolve_jsonpath(data: Any, path: str) -> Any:
    """Resolve a simple dotted JSONPath expression against *data*.

    Handles the patterns used throughout this codebase, e.g.:
      ``$.messages[-1].content``    →  data["messages"][-1]["content"]
      ``$.choices[0].message.content``  →  data["choices"][0]["message"]["content"]
    """
    if not path or path == "$":
        return data

    path = path.lstrip("$").lstrip(".")

    segments: list[str | int] = []
    buf = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == "[":
            if buf:
                segments.append(buf)
                buf = ""
            j = path.index("]", i)
            try:
                segments.append(int(path[i + 1 : j]))
            except ValueError:
                return None
            i = j + 1
            if i < len(path) and path[i] == ".":
                i += 1
        elif ch == ".":
            if buf:
                segments.append(buf)
                buf = ""
            i += 1
        else:
            buf += ch
            i += 1
    if buf:
        segments.append(buf)

    current = data
    for seg in segments:
        if current is None:
            return None
        if isinstance(seg, int):
            if isinstance(current, list) and -len(current) <= seg < len(current):
                current = current[seg]
            else:
                return None
        else:
            current = current.get(seg) if isinstance(current, dict) else None
    return current


class _NemoGuardBase:
    """Shared initialisation and helper logic for both policy variants."""

    def __init__(self, metadata: PolicyMetadata, params: dict) -> None:
        self._endpoint: str = params.get("endpoint", "").rstrip("/")
        self._api_key: str = params.get("apiKey", "")
        self._model: str = params.get("model", "nemoguard")
        self._timeout: int = int(params.get("timeout", 60))

        req_cfg = params.get("request", {}) if isinstance(params.get("request"), dict) else {}
        res_cfg = params.get("response", {}) if isinstance(params.get("response"), dict) else {}
        self._check_request: bool = bool(req_cfg.get("enabled", True))
        self._check_response: bool = bool(res_cfg.get("enabled", False))

    def _handle_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict,
    ) -> ImmediateResponse | UpstreamRequestModifications | None:
        req_cfg = params.get("request", {}) if isinstance(params.get("request"), dict) else {}
        if not req_cfg.get("enabled", True):
            return _PASSTHROUGH_REQUEST

        if not (ctx.body and ctx.body.present and ctx.body.content):
            return _PASSTHROUGH_REQUEST

        json_path: str = req_cfg.get("jsonPath", "$.messages[-1].content")
        passthrough_on_error: bool = bool(req_cfg.get("passthroughOnError", False))
        show_assessment: bool = bool(req_cfg.get("showAssessment", False))
        block_status_code: int = int(req_cfg.get("blockStatusCode", 400))
        blocked_codes = _blocked_codes(req_cfg.get("categories", {}))

        try:
            body_data = json.loads(ctx.body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH_REQUEST

        user_text = _resolve_jsonpath(body_data, json_path)
        if not user_text or not isinstance(user_text, str):
            return _PASSTHROUGH_REQUEST

        try:
            unsafe, category_codes = _call_nemoguard(
                self._endpoint, self._api_key, self._model, self._timeout,
                messages=[{"role": "user", "content": user_text}],
                check_phase="request",
            )
        except Exception as exc:
            logger.warning(
                "nemoguard request error (request_id=%s): %s",
                execution_ctx.request_id,
                exc,
            )
            if passthrough_on_error:
                return _PASSTHROUGH_REQUEST
            return ImmediateResponse(
                status_code=503,
                headers={"content-type": "application/json"},
                body=json.dumps({
                    "type": "NEMOGUARD_CONTENT_SAFETY",
                    "message": {"action": "SERVICE_UNAVAILABLE", "actionReason": "Content safety service unavailable."},
                }).encode(),
            )

        if unsafe:
            if blocked_codes is not None and not any(c in blocked_codes for c in category_codes):
                return _PASSTHROUGH_REQUEST
            msg: dict = {
                "action": "GUARDRAIL_INTERVENED",
                "interveningGuardrail": "NeMo Guard Content Safety",
                "actionReason": "Unsafe content detected.",
                "direction": "REQUEST",
            }
            if show_assessment and category_codes:
                msg["assessments"] = {"categories": category_codes}
            return ImmediateResponse(
                status_code=block_status_code,
                headers={"content-type": "application/json"},
                body=json.dumps({"type": "NEMOGUARD_CONTENT_SAFETY", "message": msg}).encode(),
            )

        return _PASSTHROUGH_REQUEST

    def _handle_response_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: ResponseContext,
        params: dict,
    ) -> ImmediateResponse | DownstreamResponseModifications | None:
        res_cfg = params.get("response", {}) if isinstance(params.get("response"), dict) else {}
        if not res_cfg.get("enabled", False):
            return _PASSTHROUGH_RESPONSE

        if not (ctx.response_body and ctx.response_body.present and ctx.response_body.content):
            return _PASSTHROUGH_RESPONSE

        json_path: str = res_cfg.get("jsonPath", "$.choices[0].message.content")
        passthrough_on_error: bool = bool(res_cfg.get("passthroughOnError", False))
        show_assessment: bool = bool(res_cfg.get("showAssessment", False))
        blocked_codes = _blocked_codes(res_cfg.get("categories", {}))

        messages: list[dict] = []

        if ctx.request_body and ctx.request_body.present and ctx.request_body.content:
            req_json_path: str = (
                params.get("request", {}).get("jsonPath", "$.messages[-1].content")
                if isinstance(params.get("request"), dict)
                else "$.messages[-1].content"
            )
            try:
                req_data = json.loads(ctx.request_body.content)
                user_text = _resolve_jsonpath(req_data, req_json_path)
                if user_text and isinstance(user_text, str):
                    messages.append({"role": "user", "content": user_text})
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        try:
            res_data = json.loads(ctx.response_body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _PASSTHROUGH_RESPONSE

        assistant_text = _resolve_jsonpath(res_data, json_path)
        if not assistant_text or not isinstance(assistant_text, str):
            return _PASSTHROUGH_RESPONSE

        messages.append({"role": "assistant", "content": assistant_text})

        try:
            unsafe, category_codes = _call_nemoguard(
                self._endpoint, self._api_key, self._model, self._timeout,
                messages=messages,
                check_phase="response",
            )
        except Exception as exc:
            logger.warning(
                "nemoguard response error (request_id=%s): %s",
                execution_ctx.request_id,
                exc,
            )
            if passthrough_on_error:
                return _PASSTHROUGH_RESPONSE
            return ImmediateResponse(
                status_code=503,
                headers={"content-type": "application/json"},
                body=json.dumps({
                    "type": "NEMOGUARD_CONTENT_SAFETY",
                    "message": {"action": "SERVICE_UNAVAILABLE", "actionReason": "Content safety service unavailable."},
                }).encode(),
            )

        if unsafe:
            if blocked_codes is not None and not any(c in blocked_codes for c in category_codes):
                return _PASSTHROUGH_RESPONSE
            msg: dict = {
                "action": "GUARDRAIL_INTERVENED",
                "interveningGuardrail": "NeMo Guard Content Safety",
                "actionReason": "Unsafe content detected.",
                "direction": "RESPONSE",
            }
            if show_assessment and category_codes:
                msg["assessments"] = {"categories": category_codes}
            return ImmediateResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps({"type": "NEMOGUARD_CONTENT_SAFETY", "message": msg}).encode(),
            )

        return _PASSTHROUGH_RESPONSE


class NemoGuardRequestOnlyPolicy(_NemoGuardBase, RequestPolicy):
    """Request-phase only variant — used when response.enabled=false."""

    def mode(self) -> ProcessingMode:
        return ProcessingMode(
            request_header_mode=HeaderProcessingMode.SKIP,
            request_body_mode=(
                BodyProcessingMode.BUFFER if self._check_request else BodyProcessingMode.SKIP
            ),
            response_header_mode=HeaderProcessingMode.SKIP,
            response_body_mode=BodyProcessingMode.SKIP,
        )

    def on_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict,
    ) -> ImmediateResponse | UpstreamRequestModifications | None:
        return self._handle_request_body(execution_ctx, ctx, params)


class NemoGuardFullPolicy(_NemoGuardBase, RequestPolicy, ResponsePolicy):
    """Request + response variant — used when response.enabled=true."""

    def mode(self) -> ProcessingMode:
        return ProcessingMode(
            request_header_mode=HeaderProcessingMode.SKIP,
            request_body_mode=(
                BodyProcessingMode.BUFFER if self._check_request else BodyProcessingMode.SKIP
            ),
            response_header_mode=HeaderProcessingMode.SKIP,
            response_body_mode=BodyProcessingMode.BUFFER,
        )

    def on_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict,
    ) -> ImmediateResponse | UpstreamRequestModifications | None:
        return self._handle_request_body(execution_ctx, ctx, params)

    def on_response_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: ResponseContext,
        params: dict,
    ) -> ImmediateResponse | DownstreamResponseModifications | None:
        return self._handle_response_body(execution_ctx, ctx, params)


def get_policy(
    metadata: PolicyMetadata, params: dict
) -> NemoGuardRequestOnlyPolicy | NemoGuardFullPolicy:
    res_cfg = params.get("response", {}) if isinstance(params.get("response"), dict) else {}
    if bool(res_cfg.get("enabled", False)):
        return NemoGuardFullPolicy(metadata, params)
    return NemoGuardRequestOnlyPolicy(metadata, params)
