# Augur IRIS Report

Generated at: `2026-10-22T08:33:00.983702+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 17 | 12 | 2 | 8 | 963 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 11 | 0 | 11 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `ganga/GangaCore/GPIDev/Persistency/__init__.py:85` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:665` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:670` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:671` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:676` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:949` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:955` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:969` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:974` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:975` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `ganga/GangaGUI/gui/routes.py:980` `py/augur/ganga/pass1-path-traversal`: Tainted request-derived path data ([this request path value](1)) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
