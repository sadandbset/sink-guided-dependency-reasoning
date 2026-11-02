# Augur IRIS Report

Generated at: `2026-10-19T07:30:48.856233+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 81 | 18 | 0 | 19 | 62 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 16 | 0 | 16 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `yt_dlp/utils/_utils.py:4459` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/extractor/common.py:1311` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/cookies.py:931` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/postprocessor/embedthumbnail.py:161` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:143` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:192` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:193` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:287` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:372` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:395` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:478` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/external.py:625` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/rtmp.py:23` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/rtmp.py:27` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/downloader/rtsp.py:27` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `yt_dlp/postprocessor/sponskrub.py:87` `py/augur/yt-dlp/pass2-command-injection`: Command injection: untrusted input (remote content, file input or CLI/config value) flows into a process execution API (shell command string or child-process argv) without quoting or validation.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
