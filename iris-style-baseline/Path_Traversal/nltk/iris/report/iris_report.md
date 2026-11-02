# Augur IRIS Report

Generated at: `2026-10-22T12:37:47.987736+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 46 | 128 | 0 | 92 | 71 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 38 | 0 | 38 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `nltk/sem/chat80.py:431` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/twitter/common.py:143` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/twitter/common.py:145` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/twitter/common.py:149` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/twitter/common.py:151` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/crubadan.py:83` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/crubadan.py:85` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/crubadan.py:104` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/crubadan.py:106` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/data.py:345` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/data.py:482` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/data.py:484` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/data.py:506` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/data.py:506` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/data.py:732` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:704` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:708` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:710` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:710` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:718` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:923` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:2221` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:2275` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:2283` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:2255` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/downloader.py:2290` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/ipipan.py:203` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/lin.py:44` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/tag/perceptron.py:111` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/parse/transitionparser.py:542` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/parse/transitionparser.py:556` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/twitter/twitterclient.py:497` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/util.py:218` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/util.py:221` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/twitter/util.py:91` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/twitter/util.py:138` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/app/wordnet_app.py:122` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `nltk/corpus/reader/xmldocs.py:173` `py/augur/nltk/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
