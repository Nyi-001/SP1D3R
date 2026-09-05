"""Evidence-oriented analysis for bounded active web checks."""

from __future__ import annotations

import html
import re
from difflib import SequenceMatcher
from typing import Any, Iterable


class VerificationEngine:
    """Evaluate already-collected probe responses without sending requests."""

    def compare_responses(
        self,
        baseline: str,
        positive: str,
        negative: str,
        baseline_status: int | None = None,
        positive_status: int | None = None,
        negative_status: int | None = None,
    ) -> dict[str, Any]:
        positive_delta = round(1 - SequenceMatcher(None, baseline, positive).ratio(), 3)
        negative_delta = round(1 - SequenceMatcher(None, baseline, negative).ratio(), 3)
        pair_similarity = round(SequenceMatcher(None, positive, negative).ratio(), 3)
        positive_negative_statuses = {positive_status, negative_status} - {None}
        status_changed = len(positive_negative_statuses) > 1
        baseline_status_changed = len({baseline_status, positive_status, negative_status} - {None}) > 1
        # A baseline-only difference is not sufficient evidence. Redirects,
        # authentication gates, and error pages often make both injected
        # requests look different from the original while remaining identical
        # to each other. Boolean SQLi requires a true/false divergence.
        different_response = (
            max(positive_delta, negative_delta) >= 0.25
            and pair_similarity < 0.92
        ) or status_changed
        return {
            "baseline_length": len(baseline),
            "positive_length": len(positive),
            "negative_length": len(negative),
            "positive_delta": positive_delta,
            "negative_delta": negative_delta,
            "positive_negative_similarity": pair_similarity,
            "status_changed": status_changed,
            "baseline_status_changed": baseline_status_changed,
            "different_response": different_response,
            "confidence": "medium" if different_response else "low",
        }

    def compare_sql_responses(
        self,
        baseline: str,
        positive: str,
        negative: str,
        baseline_status: int | None = None,
        positive_status: int | None = None,
        negative_status: int | None = None,
    ) -> dict[str, Any]:
        """Compare boolean SQL probes without requiring a large page delta.

        Database-backed pages often differ only by a result table or a short
        "no results" message.  The general comparison threshold is
        intentionally conservative for dynamic pages, so SQL checks use a
        small, explicit length/similarity signal in addition to status changes.
        """
        result = self.compare_responses(
            baseline, positive, negative,
            baseline_status, positive_status, negative_status,
        )
        positive_negative_length_delta = abs(len(positive) - len(negative))
        relative_length_delta = positive_negative_length_delta / max(len(positive), len(negative), 1)
        small_sql_difference = (
            result["positive_negative_similarity"] < 0.985
            and positive_negative_length_delta >= 40
            and relative_length_delta >= 0.02
        )
        result.update({
            "positive_negative_length_delta": positive_negative_length_delta,
            "positive_negative_relative_length_delta": round(relative_length_delta, 3),
            "different_response": result["different_response"] or small_sql_difference,
            "confidence": "medium" if result["different_response"] or small_sql_difference else "low",
        })
        return result

    def verify_reflection(self, payload: str, response_text: str) -> dict[str, Any]:
        raw_reflection = payload in response_text
        encoded_reflection = html.escape(payload, quote=True) in response_text
        unescaped_markup = raw_reflection and ("<" in payload or ">" in payload) and not encoded_reflection
        return {
            "payload_reflected": raw_reflection,
            "encoded_reflection": encoded_reflection,
            "unescaped_markup": unescaped_markup,
            "context": self._reflection_context(payload, response_text) if raw_reflection else "not reflected",
            "confidence": "high" if unescaped_markup else ("medium" if raw_reflection else "low"),
            "state": "verified" if raw_reflection else "not-verified",
        }

    def verify_file_disclosure(self, response_text: str, markers: Iterable[str]) -> dict[str, Any]:
        """Verify that a response contains distinctive local-file content.

        Short strings such as ``127.0.0.1`` and ``[extensions]`` are not
        sufficient evidence on their own: normal application pages, error
        pages, and source snippets can contain them.  Only accept those
        markers when they appear in the structure of a hosts file.  The Unix
        passwd marker is likewise required at the beginning of a passwd
        record, rather than anywhere in an HTML document.
        """
        matched = None
        matched_context = ""
        for marker in markers:
            match = self._distinctive_file_marker(response_text, str(marker))
            if match:
                matched = str(marker)
                matched_context = match.group(0).strip()[:180]
                break
        return {
            "marker_found": matched is not None,
            "matched_marker": matched or "",
            "matched_context": matched_context,
            "confidence": "high" if matched else "low",
            "state": "confirmed" if matched else "not-verified",
        }

    @staticmethod
    def _distinctive_file_marker(response_text: str, marker: str) -> re.Match[str] | None:
        """Return a match only for a marker in a recognizable file format."""
        normalized = marker.strip().lower()
        if normalized.startswith("root:x:0:0:"):
            return re.search(r"(?m)^root:[^:\r\n]*:0:0:[^\r\n]*$", response_text)

        if normalized == "127.0.0.1":
            return re.search(
                r"(?im)^\s*127\.0\.0\.1\s+(?:localhost(?:\.localdomain)?|localdomain)\s*(?:#.*)?$",
                response_text,
            )

        if normalized == "[extensions]":
            # A Windows hosts file may contain this section header, but the
            # header alone is common in copied documentation. Require a
            # neighboring hosts-style localhost record as well.
            section = re.search(r"(?ims)^\s*\[extensions\]\s*$.*?(?=^\s*\[|\Z)", response_text)
            if section and re.search(
                r"(?im)^\s*(?:127\.0\.0\.1|::1)\s+(?:localhost|localhost\.localdomain)\b",
                response_text,
            ):
                return section
            return None

        # Custom markers remain supported, but must be meaningfully longer
        # than a generic token before they can be considered file evidence.
        if len(marker.strip()) < 8:
            return None
        return re.search(re.escape(marker), response_text, re.IGNORECASE)

    def verify_sql_error(self, response_text: str, patterns: Iterable[str]) -> dict[str, Any]:
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return {
                    "error_signature_found": True,
                    "matched_signature": match.group(0)[:180],
                    "confidence": "high",
                    "state": "verified",
                }
        return {"error_signature_found": False, "matched_signature": "", "confidence": "low", "state": "not-verified"}

    @staticmethod
    def _reflection_context(payload: str, response_text: str) -> str:
        position = response_text.find(payload)
        before = response_text[max(0, position - 120):position].lower()
        after = response_text[position + len(payload):position + len(payload) + 120].lower()
        if "<script" in before or "</script" in after:
            return "script context"
        if "=" in before[-30:] and '"' in before[-80:]:
            return "attribute context"
        return "HTML/text context"
