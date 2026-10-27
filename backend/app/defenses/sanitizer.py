"""Input sanitizer: normalise, decode-and-rescan, then apply heuristic rules.

Pipeline for each input:
 1. NFKC-normalise and strip invisible "format" characters (zero-width space, joiners, BOM ...) -
    this defeats zero-width-split keywords and full-width / compatibility-character tricks.
 2. Build *scan variants*: the cleaned text, with look-alike letters folded to Latin (homoglyphs), de-leeted (4->a, 3->e ...),
    ROT13 and reversed copies, and anything that decodes from base64 / hex blobs.
 3. Run keyword/regex rules on every variant. Scores combine with a noisy-OR:
    score = 1 - prod(1 - weight_i) over distinct rules that fired.
 4. Block when the score reaches the threshold.
This is a transparent heuristic baseline: cheap, explainable, and (as the evaluation shows) bypassable
by paraphrase - which is exactly why a learned detector is needed.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

from app.defenses.base import Action, Decision, Defense, DefenseContext, Timer

# Cyrillic / Greek look-alikes -> Latin, used for SCANNING only (we do not rewrite genuine non-Latin text).
_FOLD = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
         "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Т": "T", "Н": "H", "В": "B", "М": "M",
         "ο": "o", "ν": "v", "α": "a", "ε": "e", "ι": "i"}
_FOLD_TABLE = str.maketrans(_FOLD)
_UNLEET_TABLE = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"})

_RULES: list[tuple[str, float, re.Pattern[str]]] = [(n, w, re.compile(p, re.IGNORECASE | re.DOTALL)) for n, w, p in [
    ("ignore_previous", 0.9, r"\b(ignore|disregard|forget|overlook|set aside)\b.{0,30}\b(previous|prior|earlier|above|preceding|all)\b.{0,30}\b(instructions?|rules?|guidelines?|directions?|prompts?|everything)\b"),
    ("forget_everything", 0.8, r"\bforget (everything|all)\b"),
    ("reveal_secrets", 0.8, r"\b(reveal|print|show|output|repeat|dump|disclose|display|write out|tell me|state|read out)\b.{0,50}\b(system prompt|your (initial |hidden |original )?instructions|configuration|secrets?|confidential|api key|credentials|initiali[sz]ation|startup)"),
    ("extract_prompt", 0.7, r"\b(repeat|quote|translate|summari[sz]e|export)\b.{0,40}\b(text above|your (initial )?instructions|system prompt|initial instructions)"),
    ("persona_switch", 0.75, r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|you will be)\b.{0,60}\b(no (rules|restrictions|limits|confidentiality)|unrestricted|jailbr|dan\b|debug|without (rules|restrictions))"),
    ("jailbreak_terms", 0.7, r"\b(jailbreak|developer mode|debug(ging)? mode|dan mode|audit mode|test mode)\b"),
    ("override_banner", 0.8, r"(system override|override:|new instructions?|\[system\]|<\s*system\s*>|### ?(new )?instructions)"),
    ("fake_authority", 0.55, r"\b(administrator|admin|ciso|cfo|developer|security team)\b.{0,50}\b(authori[sz]ed|approved|granted|pre-approved|orders?)\b"),
    ("forbidden_tool_name", 0.85, r"\b(transfer_credits|delete_record)\b"),
    ("tool_call_markup", 0.8, r"<\s*tool_call\s*>"),
    ("note_to_assistant", 0.8, r"\b(note to (the )?(ai )?assistant|assistant:|instruction for the assistant|ai assistant reading this|message from the \w+ to the ai)\b"),
    ("decode_and_obey", 0.6, r"\b(decode|decipher)\b.{0,40}\b(follow|obey|do|carry out|execute)\b"),
    ("backwards_obey", 0.5, r"\b(read (this )?backwards?|reversed?)\b.{0,30}\b(obey|follow|do)\b"),
    ("multilingual_ignore", 0.85, r"(ignor(e|a|iere)\s+(toutes?|todas?|alle)\b.{0,40}(instructions?|instrucciones|anweisungen)|ignoriere? .{0,30}anweisungen)"),
    ("exfiltrate_to_external", 0.7, r"\b(send|email|e-mail|forward)\b.{0,80}\b(to|at)\b.{0,40}@[\w.-]+\.(example|com|org|net)\b.{0,100}\b(code|key|credential|secret|content of)"),
]]
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")


def normalize(text: str) -> str:
    """NFKC + drop Unicode category Cf (format) and Cc controls except newline/tab."""
    t = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in t if unicodedata.category(ch) != "Cf" and (unicodedata.category(ch) != "Cc" or ch in "\n\t\r"))


def _printable_ratio(s: str) -> float:
    return sum(ch.isprintable() or ch.isspace() for ch in s) / len(s) if s else 0.0


def decode_candidates(text: str) -> list[str]:
    """Return plausible decoded payloads found inside ``text`` (base64 / hex blobs, ROT13, reversed)."""
    out: list[str] = []
    for tok in _B64.findall(text):
        try:
            dec = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        if len(dec) >= 8 and _printable_ratio(dec) > 0.95:
            out.append(dec)
    for tok in _HEX.findall(text):
        try:
            dec = bytes.fromhex(tok).decode("utf-8")
        except ValueError:
            continue
        if _printable_ratio(dec) > 0.95:
            out.append(dec)
    out.append(codecs.encode(text, "rot13"))
    out.append(text[::-1])
    return out


def rule_hits(text: str) -> dict[str, float]:
    return {name: w for name, w, rx in _RULES if rx.search(text)}


class Sanitizer(Defense):
    name = "sanitizer"

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold

    def inspect_input(self, text: str, source: str = "user", ctx: DefenseContext | None = None) -> Decision:
        with Timer() as t:
            clean = normalize(text)
            folded = clean.translate(_FOLD_TABLE)
            variants = [clean, folded, folded.translate(_UNLEET_TABLE)]
            hits: dict[str, float] = {}
            for v in variants:
                hits.update(rule_hits(v))
            decoded_hits: dict[str, float] = {}
            for dec in decode_candidates(clean.translate(_FOLD_TABLE)):
                for name, w in rule_hits(normalize(dec)).items():
                    decoded_hits[f"decoded:{name}"] = w
            hits.update(decoded_hits)
            keep = 1.0
            for w in hits.values():
                keep *= 1.0 - w
            score = 1.0 - keep
        action = Action.block if score >= self.threshold else Action.allow
        reason = ("rules fired: " + ", ".join(sorted(hits))) if hits else "no rule fired"
        return Decision(action, score, reason, t.ms, self.name, text=clean, extra={"rules": sorted(hits), "changed": clean != text})
