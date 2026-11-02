# -*- coding: utf-8 -*-
"""Sanity check for the generated QL files: brace/paren balance and forbidden patterns."""
import re

FILES = [
    "libraries/MySources.qll",
    "libraries/MySinks.qll",
    "libraries/MySanitizers.qll",
    "libraries/MySummaries.qll",
    "queries/Pass5_SQLInjection.ql",
]

STR_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
BLOCK_RE = re.compile(r'/\*.*?\*/', re.S)
LINE_RE = re.compile(r'//[^\n]*')

for f in FILES:
    s = open(f, encoding="utf-8").read()
    s2 = BLOCK_RE.sub("", s)
    s2 = LINE_RE.sub("", s2)
    s2 = STR_RE.sub('""', s2)
    bal = {"{": 0, "(": 0}
    pairs = {"}": "{", ")": "("}
    ok = True
    for ch in s2:
        if ch in bal:
            bal[ch] += 1
        elif ch in pairs:
            bal[pairs[ch]] -= 1
            if bal[pairs[ch]] < 0:
                ok = False
    status = "OK" if ok and all(v == 0 for v in bal.values()) else "MISMATCH"
    print("%-32s braces=%d parens=%d %s" % (f, bal["{"], bal["("], status))
    for pat, msg in [(r"StrConst", "deprecated StrConst"),
                     (r"\bDecorator\b", "Decorator class"),
                     (r"\bAstNode\.getFile\b", "AstNode.getFile (does not exist)")]:
        if re.search(pat, s):
            print("    WARN:", msg)
print("done")
