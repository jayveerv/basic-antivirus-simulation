"""A small YARA-like rule engine written in pure Python (no yara-python needed).

Supported syntax::

    rule Name {
        meta:
            description = "text"
            severity = "high"          # low | medium | high
            mitre = "T1059.001"
        strings:
            $a = "text" nocase wide     # text string, optional nocase / wide / ascii
            $b = { 4D 5A ?? 00 }        # hex string, ?? = any byte
            $c = /regex/i               # regular expression (i = ignore case)
        condition:
            any of them | all of them | 2 of them | $a and ($b or not $c)
            | $b at 0 | filesize < 1000000 | #a >= 3
    }
"""

import re

SEVERITIES = ("low", "medium", "high")

_RULE_RE = re.compile(r"rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\n\}", re.S)
_SECTION_RE = re.compile(r"(meta|strings|condition)\s*:", re.S)
_META_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')
_STRING_RE = re.compile(r'^\s*(\$[A-Za-z0-9_]*)\s*=\s*(.+?)\s*$')


class RuleError(ValueError):
    pass


def _unescape(text):
    return bytes(text, "utf-8").decode("unicode_escape").encode("latin-1")


class Pattern:
    def __init__(self, ident, raw):
        self.ident = ident
        self.raw = raw
        raw = raw.strip()
        if raw.startswith('"'):
            end = raw.rfind('"')
            if end <= 0:
                raise RuleError(f"unterminated string in {ident}")
            text = _unescape(raw[1:end])
            mods = raw[end + 1:].split()
            for m in mods:
                if m not in ("nocase", "wide", "ascii"):
                    raise RuleError(f"unknown modifier {m!r} in {ident}")
            flags = re.I if "nocase" in mods else 0
            variants = []
            if "wide" not in mods or "ascii" in mods:
                variants.append(re.escape(text))
            if "wide" in mods:
                variants.append(re.escape(b"".join(bytes([c, 0]) for c in text)))
            self.regex = re.compile(b"|".join(variants), flags)
            self.kind = "text"
        elif raw.startswith("{"):
            if not raw.endswith("}"):
                raise RuleError(f"unterminated hex string in {ident}")
            parts = raw[1:-1].split()
            out = []
            for p in parts:
                if p == "??":
                    out.append(b".")
                elif re.fullmatch(r"[0-9A-Fa-f]{2}", p):
                    out.append(re.escape(bytes([int(p, 16)])))
                else:
                    raise RuleError(f"bad hex byte {p!r} in {ident}")
            self.regex = re.compile(b"".join(out), re.S)
            self.kind = "hex"
        elif raw.startswith("/"):
            end = raw.rfind("/")
            if end <= 0:
                raise RuleError(f"unterminated regex in {ident}")
            flags = re.S | (re.I if "i" in raw[end + 1:] else 0)
            self.regex = re.compile(raw[1:end].encode("latin-1"), flags)
            self.kind = "regex"
        else:
            raise RuleError(f"cannot parse string {ident}: {raw}")

    def find(self, data):
        return [m.start() for m in self.regex.finditer(data)]


class Rule:
    def __init__(self, name, meta, patterns, condition):
        self.name = name
        self.meta = meta
        self.patterns = patterns
        self.condition = condition.strip()
        self.severity = meta.get("severity", "medium").lower()
        if self.severity not in SEVERITIES:
            raise RuleError(f"rule {name}: severity must be one of {SEVERITIES}")
        self.mitre = meta.get("mitre", "")
        self.description = meta.get("description", "")
        self._compile_condition()

    def _compile_condition(self):
        ids = {p.ident for p in self.patterns}
        tokens = re.findall(r"#[A-Za-z0-9_]+|\$[A-Za-z0-9_]*|\d+|0x[0-9A-Fa-f]+|==|!=|<=|>=|<|>|\(|\)|[A-Za-z_]+", self.condition)
        joined = "".join(tokens)
        if joined != re.sub(r"\s+", "", self.condition):
            raise RuleError(f"rule {self.name}: unsupported characters in condition")
        allowed_words = {"and", "or", "not", "any", "all", "of", "them", "at", "filesize"}
        for t in tokens:
            if t.startswith("$") and t not in ids:
                raise RuleError(f"rule {self.name}: unknown string {t}")
            if t.startswith("#") and "$" + t[1:] not in ids:
                raise RuleError(f"rule {self.name}: unknown string count {t}")
            if re.fullmatch(r"[A-Za-z_]+", t) and t not in allowed_words:
                raise RuleError(f"rule {self.name}: unknown word {t!r}")
        self._tokens = tokens

    def _expression(self, hits, size):
        """Turn the token list into a safe Python expression."""
        t, out, i = self._tokens, [], 0
        n_total = len(self.patterns)
        while i < len(t):
            tok = t[i]
            if tok in ("any", "all") or re.fullmatch(r"\d+", tok) and i + 2 < len(t) and t[i + 1] == "of":
                if i + 2 >= len(t) or t[i + 1] != "of" or t[i + 2] != "them":
                    raise RuleError(f"rule {self.name}: expected '<n> of them'")
                found = sum(1 for p in self.patterns if hits[p.ident])
                need = 1 if tok == "any" else n_total if tok == "all" else int(tok)
                out.append(str(found >= need))
                i += 3
                continue
            if tok.startswith("$"):
                if i + 2 < len(t) and t[i + 1] == "at":
                    off = int(t[i + 2], 0)
                    out.append(str(off in hits[tok]))
                    i += 3
                    continue
                out.append(str(bool(hits[tok])))
            elif tok.startswith("#"):
                out.append(str(len(hits["$" + tok[1:]])))
            elif tok == "filesize":
                out.append(str(size))
            elif tok.startswith("0x"):
                out.append(str(int(tok, 16)))
            else:
                out.append(tok)
            i += 1
        return " ".join(out)

    def evaluate(self, data):
        hits = {p.ident: p.find(data) for p in self.patterns}
        expr = self._expression(hits, len(data))
        try:
            ok = bool(eval(expr, {"__builtins__": {}}, {}))  # expression is built only from whitelisted tokens
        except Exception as exc:  # pragma: no cover - defensive
            raise RuleError(f"rule {self.name}: bad condition ({exc})")
        if not ok:
            return None
        matched = []
        for p in self.patterns:
            if hits[p.ident]:
                m = p.regex.search(data)
                sample = m.group(0)[:60] if m else b""
                matched.append({"id": p.ident, "count": len(hits[p.ident]), "offset": hits[p.ident][0],
                                "sample": sample.decode("latin-1", "replace")})
        return {"rule": self.name, "severity": self.severity, "mitre": self.mitre,
                "description": self.description, "matched": matched}


def parse_rules(text):
    text = re.sub(r"//[^\n]*", "", text)
    rules = []
    for name, body in _RULE_RE.findall(text):
        parts = _SECTION_RE.split(body)
        sections = {}
        for k in range(1, len(parts), 2):
            sections[parts[k]] = parts[k + 1]
        if "condition" not in sections:
            raise RuleError(f"rule {name} has no condition")
        meta = {}
        for line in sections.get("meta", "").splitlines():
            if line.strip():
                m = _META_RE.match(line)
                if not m:
                    raise RuleError(f"rule {name}: bad meta line {line.strip()!r}")
                meta[m.group(1)] = m.group(2)
        patterns = []
        for line in sections.get("strings", "").splitlines():
            if line.strip():
                m = _STRING_RE.match(line)
                if not m:
                    raise RuleError(f"rule {name}: bad string line {line.strip()!r}")
                patterns.append(Pattern(m.group(1), m.group(2)))
        rules.append(Rule(name, meta, patterns, " ".join(sections["condition"].split())))
    if not rules:
        raise RuleError("no rules found")
    return rules


class RuleSet:
    def __init__(self, rules):
        self.rules = rules

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls(parse_rules(fh.read()))

    def __len__(self):
        return len(self.rules)

    def scan(self, data):
        return [r for r in (rule.evaluate(data) for rule in self.rules) if r]
