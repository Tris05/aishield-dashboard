from __future__ import annotations

import json

import logging

import re

from pathlib import Path

from fastapi import HTTPException

from google import genai

from google.genai import types

from ..config import settings

from .patching import normalize_hunk_counts, validate_diff

logger = logging.getLogger(__name__)

POLICY_DIR = Path(__file__).resolve().parents[2] / "policies"

POLICY_NAMES = (

    "constitution.md",

    "secure-coding.md",

    "ai-model-security.md",

    "llm-security.md",

    "patch-policy.md",

)

# ---------------------------------------------------------------------

# REDACTION

# ---------------------------------------------------------------------

def redact(text: str) -> str:

    """

    Redact common secrets before sending source code to Gemini.

    This is a precautionary filter, not a guarantee that every secret

    format will be detected.

    """

    patterns = [

        # Private keys

        (

            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?"

            r"-----END [A-Z ]*PRIVATE KEY-----",

            "[REDACTED_PRIVATE_KEY]",

        ),

        # API keys and tokens

        (

            r"(?i)(api[\_-]?key|access[\_-]?token|auth[\_-]?token|"

            r"secret[\_-]?key|client[\_-]?secret|password)"

            r"(\s*[:=]\s*)"

            r"""([\'"])[^\'"]{6,}([\'"])""",

            r"\1\2\3[REDACTED]\4",

        ),

        # AWS access keys

        (

            r"\bAKIA[0-9A-Z]{16}\b",

            "[REDACTED_AWS_ACCESS_KEY]",

        ),

        # GitHub tokens

        (

            r"\bgh[pousr]\_[A-Za-z0-9\_]{20,}\b",

            "[REDACTED_GITHUB_TOKEN]",

        ),

        # Generic bearer tokens

        (

            r"(?i)(Bearer\s+)[A-Za-z0-9.\_\~+/-]+=*",

            r"\1[REDACTED]",

        ),

        # Common connection strings

        (

            r"(?i)(mongodb(?:\+srv)?://)[^/\s:@]+:[^@\s]+@",

            r"\1[REDACTED]@",

        ),

        (

            r"(?i)(postgres(?:ql)?://)[^/\s:@]+:[^@\s]+@",

            r"\1[REDACTED]@",

        ),

    ]

    result = text

    for pattern, replacement in patterns:

        result = re.sub(pattern, replacement, result)

    return result

# ---------------------------------------------------------------------

# POLICY LOADING

# ---------------------------------------------------------------------

def load_security_policies() -> str:

    """Load the configured AIShield security policy documents."""

    documents = []

    for name in POLICY_NAMES:

        path = POLICY_DIR / name

        if not path.is_file():

            logger.warning(

                "AIShield policy file not found: %s",

                name,

            )

            continue

        try:

            content = path.read_text(encoding="utf-8")

        except OSError:

            logger.exception(

                "Could not read AIShield policy file: %s",

                name,

            )

            continue

        documents.append(

            f"\n\n===== POLICY: {name} =====\n\n{content}"

        )

    return "\n".join(documents)

# ---------------------------------------------------------------------

# RESPONSE NORMALIZATION

# ---------------------------------------------------------------------

def normalize_patch_response(response_text: str) -> str:

    """

    Normalize Gemini output into a plain unified Git diff.

    Handles:

    - Leading whitespace

    - UTF-8 BOM

    - Markdown diff fences

    - Trailing whitespace

    """

    patch = (response_text or "").strip()

    # Remove UTF-8 BOM and leading whitespace/newlines.

    patch = patch.lstrip("\ufeff\r\n\t ")

    # Remove opening Markdown code fence.

    if patch.startswith("```"):

        patch = re.sub(

            r"^```(?:diff|patch)?[ \t]*\r?\n?",

            "",

            patch,

            count=1,

            flags=re.IGNORECASE,

        )

        # Remove closing Markdown code fence.

        patch = re.sub(

            r"\r?\n?```[ \t]*$",

            "",

            patch,

            count=1,

        )

    # Normalize once more after removing fences.

    patch = patch.lstrip("\ufeff\r\n\t ")

    patch = patch.rstrip()

    return patch

# ---------------------------------------------------------------------

# GEMINI PATCH GENERATION

# ---------------------------------------------------------------------

def generate_patch(

    finding: dict,

    source: str,

) -> tuple[str, str]:

    """

    Generate a unified Git diff for a single security finding.

    The generated patch is structurally validated here.

    Git applicability must still be checked against the exact scanned

    commit before applying or pushing the patch.

    """

    if not settings.gemini_api_key:

        raise HTTPException(

            status_code=503,

            detail="Gemini API key is not configured.",

        )

    if not isinstance(source, str) or not source:

        raise HTTPException(

            status_code=400,

            detail="Source code is unavailable for this finding.",

        )

    # -------------------------------------------------------------

    # Target path

    # -------------------------------------------------------------

    target_path = str(

        finding.get("path") or ""

    ).replace("\\\\", "/").strip()

    if not target_path:

        raise HTTPException(

            status_code=400,

            detail="Finding does not contain a target file path.",

        )

    if target_path.startswith("/") or "\x00" in target_path:

        raise HTTPException(

            status_code=400,

            detail="Invalid finding target path.",

        )

    # -------------------------------------------------------------

    # Load policies

    # -------------------------------------------------------------

    policies = load_security_policies()

    # -------------------------------------------------------------

    # Extract source context

    # -------------------------------------------------------------

    lines = source.splitlines()

    try:

        finding_line = int(finding.get("line") or 1)

    except (TypeError, ValueError):

        finding_line = 1

    finding_line = max(1, finding_line)

    # Keep the context bounded.

    context_radius = 35

    start = max(1, finding_line - context_radius)

    end = min(

        len(lines),

        finding_line + context_radius,

    )

    # IMPORTANT:

    # Do not prefix source lines with artificial line numbers.

    # Git needs the original source text as patch context.

    snippet = "\n".join(lines[start - 1:end])

    redacted_source = redact(snippet)

    source_was_redacted = redacted_source != snippet

    # -------------------------------------------------------------

    # Build Gemini payload

    # -------------------------------------------------------------

    payload = {

        "target_file": target_path,

        "finding_id": finding.get("id"),

        "finding_title": finding.get("title")

        or finding.get("name")

        or finding.get("rule_id"),

        "finding_category": finding.get("category"),

        "finding_severity": finding.get("severity"),

        "finding_description": finding.get("description"),

        "finding_evidence": finding.get("evidence"),

        "finding_recommendation": finding.get("recommendation"),

        "finding_line": finding_line,

        "source_context_start_line": start,

        "source_context_end_line": end,

        "redacted_source_context": redacted_source,

        "source_context_redacted": source_was_redacted,

        "security_policies": policies,

    }

    # -------------------------------------------------------------

    # System instruction

    # -------------------------------------------------------------

    system_instruction = """

You are AIShield, an application security remediation engineer.

Your task is to generate a safe, minimal, technically correct fix

for the supplied security finding.

SECURITY REQUIREMENTS:

1. Follow all supplied AIShield security policies.

2. Fix only the supplied finding.

3. Preserve existing application behavior wherever possible.

4. Do not introduce new dependencies unless absolutely necessary.

5. Do not disable security checks, authentication, authorization,

   validation, logging, or other existing safeguards.

6. Do not introduce hardcoded credentials, secrets, tokens,

   passwords, or private keys.

7. Do not make unrelated refactoring changes.

8. Do not modify any file other than the supplied target file.

9. If the finding cannot be fixed safely with the available context,

   return an empty response.

10. Do not invent source code or surrounding context.

DIFF FORMAT REQUIREMENTS:

Return exactly one unified Git diff.

The output MUST begin with:

diff --git a/<target_file> b/<target_file>

It MUST contain these file headers:

--- a/<target_file>

+++ b/<target_file>

It MUST contain valid unified diff hunk headers, for example:

@@ -10,5 +10,6 @@

Additional requirements:

- Use the exact target file path supplied in the payload.

- Include sufficient unchanged source context in each hunk.
- Every context line must begin with exactly one leading space.
- Every added line must begin with + and every deleted line with -.
- Hunk header counts must exactly match the hunk body:
  context lines count toward both old and new; deleted lines count only
  toward old; added lines count only toward new.
- Do not include bare, unprefixed source lines inside a hunk.
- Every context line must begin with exactly one leading space.
- Every added line must begin with + and every deleted line with -.
- Hunk header counts must exactly match the hunk body:
  context lines count toward both old and new; deleted lines count only
  toward old; added lines count only toward new.
- Do not include bare, unprefixed source lines inside a hunk.
- Do not use [REDACTED] placeholders as unchanged diff context.

- Preserve original source text exactly in unchanged context lines.

- Do not include artificial line numbers.

- Do not use [REDACTED] placeholders as unchanged diff context.

- Do not include Markdown code fences.

- Do not include explanations, comments outside the diff,

  summaries, or any other text.

- Do not generate file creation, deletion, rename, or copy operations.

- Do not change multiple files.

If a safe, applicable patch cannot be generated, return an empty response.

""".strip()

    # -------------------------------------------------------------

    # Call Gemini

    # -------------------------------------------------------------

    model = settings.gemini_model or "gemini-2.5-flash"

    try:

        client = genai.Client(

            api_key=settings.gemini_api_key

        )

        response = client.models.generate_content(

            model=model,

            contents=json.dumps(

                payload,

                ensure_ascii=False,

            ),

            config=types.GenerateContentConfig(

                system_instruction=system_instruction,

                temperature=0.0,

                max_output_tokens=8192,

            ),

        )

    except Exception as exc:

        logger.exception(

            "Gemini API request failed | model=%s | finding_id=%s | "

            "exception=%s",

            model,

            finding.get("id"),

            type(exc).__name__,

        )

        raise HTTPException(

            status_code=502,

            detail=(

                "Gemini patch generation failed "

                f"({type(exc).__name__}). Check backend logs."

            ),

        ) from exc

    # -------------------------------------------------------------

    # Extract response

    # -------------------------------------------------------------

    try:

        response_text = response.text or ""

    except Exception as exc:

        logger.exception(

            "Could not extract Gemini response text | "

            "finding_id=%s | exception=%s",

            finding.get("id"),

            type(exc).__name__,

        )

        raise HTTPException(

            status_code=502,

            detail="Could not read Gemini's patch response.",

        ) from exc

    if not response_text.strip():

        logger.warning(

            "Gemini returned an empty response | model=%s | "

            "finding_id=%s",

            model,

            finding.get("id"),

        )

        raise HTTPException(

            status_code=422,

            detail=(

                "Gemini could not generate a safe patch for this finding. "

                "Review the finding and source context."

            ),

        )

    # -------------------------------------------------------------

    # Normalize response

    # -------------------------------------------------------------

    patch = normalize_patch_response(response_text)

    if not patch:

        raise HTTPException(

            status_code=422,

            detail="Gemini returned an empty patch.",

        )

    # -------------------------------------------------------------

    # Normalize unified-diff hunk counts

    # -------------------------------------------------------------

    patch, hunk_error = normalize_hunk_counts(patch)

    if hunk_error:

        logger.warning(

            "Gemini generated a malformed diff hunk | "

            "finding_id=%s | path=%s | reason=%s | preview=%r",

            finding.get("id"),

            target_path,

            hunk_error,

            patch[:500],

        )

        raise HTTPException(

            status_code=422,

            detail=f"Gemini generated a malformed unified diff: {hunk_error}",

        )

    # -------------------------------------------------------------

    # Validate patch structure

    # -------------------------------------------------------------

    valid, message = validate_diff(

        patch,

        target_path,

    )

    if not valid:

        logger.warning(

            "Gemini generated an invalid diff | "

            "finding_id=%s | path=%s | reason=%s | preview=%r",

            finding.get("id"),

            target_path,

            message,

            patch[:500],

        )

        raise HTTPException(

            status_code=422,

            detail=(

                f"Gemini generated an invalid unified diff: {message}"

            ),

        )

    logger.info(

        "Gemini generated a structurally valid patch | "

        "finding_id=%s | path=%s | model=%s",

        finding.get("id"),

        target_path,

        model,

    )

    return (

        patch,

        "AI-generated patch passed structural validation. "

        "Git applicability will be checked against the original scanned commit.",

    )
