# Pass 1 (Path Traversal) Label Statistics

- Project: py7zr (~0.20.0+ unreleased, py7zr_vuln source tree) (`py7zr_vuln` tree)
- Model: glm-5.3 (Claude Code CLI agent, single session, no external LLM API)
- Generated: 2026-10-23T00:57:09.790567+00:00
- Candidates: 66 source rows + 125 sink rows = 191 total; all labeled, 0 skipped, 0 rows merged or dropped
- Deduplication: 32 moduleHint-twin pairs (26 source + 6 sink) share file+line+callable+node and differ only in the moduleHint column ('py7zr' vs 'py7zr.py7zr'); both rows retained with identical decisions; Phase 2 signature rendering must dedup module-agnostically

## Role x classification (combined)

| role | classification | count |
| --- | --- | --- |
| source | tp | 10 |
| source | candidate | 33 |
| sink | tp | 11 |
| sink | candidate | 1 |
| summary | tp | 12 |
| summary | candidate | 3 |
| none | fp | 121 |

## Source candidates (66 rows)

| role | classification | count |
| --- | --- | --- |
| source | tp | 10 |
| source | candidate | 33 |
| none | fp | 23 |

## Sink candidates (125 rows)

| role | classification | count |
| --- | --- | --- |
| sink | tp | 11 |
| sink | candidate | 1 |
| summary | tp | 12 |
| summary | candidate | 3 |
| none | fp | 98 |

## Batches

| batch | description | source rows | sink rows |
| --- | --- | --- | --- |
| B1 | Archive header entry-name decode boundary (archiveinfo.py) | 2 | 1 |
| B2 | CLI boundary and dev tooling (cli.py, utils/bench_result.py) | 12 | 15 |
| B3 | SevenZipFile read/extract pipeline and public read-side APIs (py7zr.py:318-669, 920-990, 1140-1185) | 36 | 37 |
| B4 | Worker extraction core: path materialization, link/junction creation, file write (py7zr.py:1186-1510) | 12 | 26 |
| B5 | Write-side and archive-metadata paths (py7zr.py:671-919, 1012-1139) | 4 | 31 |
| B6 | Cross-platform compat helpers (helpers.py, win32compat.py) | 0 | 15 |

## Confirmed entries (role != none): 70

- `p1-src-001` source/tp conf=0.95 — archiveinfo.py:757 read_utf16
- `p1-src-002` source/tp conf=0.95 — archiveinfo.py:757 filename
- `p1-src-003` source/candidate conf=0.50 — cli.py:95 run
- `p1-src-004` source/candidate conf=0.55 — cli.py:96 parse_args
- `p1-src-005` source/candidate conf=0.50 — cli.py:200 arcfile
- `p1-src-007` source/candidate conf=0.50 — cli.py:297 arcfile
- `p1-src-008` source/candidate conf=0.50 — cli.py:322 arcfile
- `p1-src-009` source/candidate conf=0.50 — cli.py:355 odir
- `p1-src-010` source/candidate conf=0.50 — cli.py:356 odir
- `p1-src-011` source/candidate conf=0.45 — cli.py:390 arcfile
- `p1-src-012` source/candidate conf=0.45 — cli.py:391 filenames
- `p1-src-013` source/candidate conf=0.45 — cli.py:434 arcfile
- `p1-src-014` source/candidate conf=0.45 — cli.py:435 filenames
- `p1-src-015` source/candidate conf=0.50 — py7zr.py:320 __init__
- `p1-src-016` source/candidate conf=0.50 — py7zr.py:320 __init__
- `p1-src-017` source/candidate conf=0.50 — py7zr.py:526 _extract
- `p1-src-018` source/candidate conf=0.50 — py7zr.py:526 _extract
- `p1-src-023` source/tp conf=0.95 — py7zr.py:561 filename
- `p1-src-024` source/tp conf=0.95 — py7zr.py:561 filename
- `p1-src-025` source/tp conf=0.90 — py7zr.py:565 filename
- `p1-src-026` source/tp conf=0.90 — py7zr.py:565 filename
- `p1-src-033` source/candidate conf=0.55 — py7zr.py:974 extractall
- `p1-src-034` source/candidate conf=0.55 — py7zr.py:974 extractall
- `p1-src-037` source/candidate conf=0.55 — py7zr.py:986 extract
- `p1-src-038` source/candidate conf=0.55 — py7zr.py:986 extract
- `p1-src-041` source/candidate conf=0.45 — py7zr.py:1012 writeall
- `p1-src-042` source/candidate conf=0.45 — py7zr.py:1012 writeall
- `p1-src-043` source/candidate conf=0.45 — py7zr.py:1023 write
- `p1-src-044` source/candidate conf=0.45 — py7zr.py:1023 write
- `p1-src-045` source/candidate conf=0.45 — py7zr.py:1144 is_7zfile
- `p1-src-046` source/candidate conf=0.45 — py7zr.py:1144 is_7zfile
- `p1-src-047` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive
- `p1-src-048` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive
- `p1-src-049` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive
- `p1-src-050` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive
- `p1-src-051` source/candidate conf=0.45 — py7zr.py:1176 pack_7zarchive
- `p1-src-052` source/candidate conf=0.45 — py7zr.py:1176 pack_7zarchive
- `p1-src-053` source/candidate conf=0.50 — py7zr.py:1176 pack_7zarchive
- `p1-src-054` source/candidate conf=0.50 — py7zr.py:1176 pack_7zarchive
- `p1-src-057` source/tp conf=0.95 — py7zr.py:1333 read
- `p1-src-058` source/tp conf=0.95 — py7zr.py:1333 read
- `p1-src-059` source/tp conf=0.95 — py7zr.py:1343 read
- `p1-src-060` source/tp conf=0.95 — py7zr.py:1343 read
- `p1-sink-001` summary/tp conf=0.90 — archiveinfo.py:757 replace
- `p1-sink-022` summary/candidate conf=0.40 — helpers.py:299 Path
- `p1-sink-026` summary/tp conf=0.90 — helpers.py:424 remove_relative_path_marker
- `p1-sink-037` summary/tp conf=0.60 — py7zr.py:542 Path
- `p1-sink-039` sink/candidate conf=0.60 — py7zr.py:545 mkdir
- `p1-sink-042` summary/tp conf=0.90 — py7zr.py:577 joinpath
- `p1-sink-044` summary/tp conf=0.90 — py7zr.py:577 remove_relative_path_marker
- `p1-sink-045` summary/tp conf=0.90 — py7zr.py:580 Path
- `p1-sink-046` summary/tp conf=0.90 — py7zr.py:580 remove_relative_path_marker
- `p1-sink-047` summary/tp conf=0.90 — py7zr.py:582 joinpath
- `p1-sink-048` summary/tp conf=0.90 — py7zr.py:582 remove_relative_path_marker
- `p1-sink-050` summary/candidate conf=0.50 — py7zr.py:597 WindowsPath
- `p1-sink-052` sink/tp conf=0.90 — py7zr.py:625 mkdir
- `p1-sink-055` sink/tp conf=0.80 — py7zr.py:659 utime
- `p1-sink-056` sink/tp conf=0.80 — py7zr.py:663 chmod
- `p1-sink-057` sink/tp conf=0.75 — py7zr.py:668 chmod
- `p1-sink-101` sink/tp conf=0.95 — py7zr.py:1328 mkdir
- `p1-sink-103` sink/tp conf=0.90 — py7zr.py:1336 unlink
- `p1-sink-104` sink/tp conf=0.95 — py7zr.py:1338 CreateJunction
- `p1-sink-105` summary/tp conf=0.90 — py7zr.py:1343 Path
- `p1-sink-107` sink/tp conf=0.90 — py7zr.py:1346 unlink
- `p1-sink-108` sink/tp conf=0.95 — py7zr.py:1347 symlink_to
- `p1-sink-109` sink/tp conf=0.97 — py7zr.py:1349 open
- `p1-sink-110` sink/tp conf=0.90 — py7zr.py:1357 touch
- `p1-sink-119` summary/tp conf=0.90 — py7zr.py:1500 register_filelike
- `p1-sink-120` summary/tp conf=0.90 — py7zr.py:1500 register_filelike
- `p1-sink-125` summary/candidate conf=0.40 — win32compat.py:198 WindowsPath

## Human-review queue (37 entries: classification candidate/unknown or confidence < 0.55)

- `p1-src-003` source/candidate conf=0.50 — cli.py:95 run — Cli.run(arg) is the argparse boundary of the py7zr console command (arg=None -> sys.argv, dispatched via py7zr.__main__:main). A real process-input boundary, but local-operator trust: the invoking use…
- `p1-src-004` source/candidate conf=0.55 — cli.py:96 parse_args — self.parser.parse_args(arg) materializes the argparse Namespace (args.arcfile / args.odir / args.filenames) from argv. Same local-operator trust analysis as the Cli.run arg row; kept as candidate for …
- `p1-src-005` source/candidate conf=0.50 — cli.py:200 arcfile — args.arcfile attribute read: operator-specified archive path (pathlib.Path typed). Feeds is_7zfile/SevenZipFile archive opening (read) or archive creation (write). The path is operator-authorized loca…
- `p1-src-007` source/candidate conf=0.50 — cli.py:297 arcfile — args.arcfile attribute read: operator-specified archive path (pathlib.Path typed). Feeds is_7zfile/SevenZipFile archive opening (read) or archive creation (write). The path is operator-authorized loca…
- `p1-src-008` source/candidate conf=0.50 — cli.py:322 arcfile — args.arcfile attribute read: operator-specified archive path (pathlib.Path typed). Feeds is_7zfile/SevenZipFile archive opening (read) or archive creation (write). The path is operator-authorized loca…
- `p1-src-009` source/candidate conf=0.50 — cli.py:355 odir — args.odir attribute read: the extraction output directory passed as a.extractall(path=args.odir) (cli.py:356). Operator-authorized by construction -- a CLI user extracting into a directory they chose …
- `p1-src-010` source/candidate conf=0.50 — cli.py:356 odir — args.odir attribute read: the extraction output directory passed as a.extractall(path=args.odir) (cli.py:356). Operator-authorized by construction -- a CLI user extracting into a directory they chose …
- `p1-src-011` source/candidate conf=0.45 — cli.py:390 arcfile — args.arcfile on the create/append side: operator-specified OUTPUT archive path (string, '.7z' suffix enforced at cli.py:397/:436). Write-side, operator-authorized local CLI usage; candidate only for f…
- `p1-src-012` source/candidate conf=0.45 — cli.py:391 filenames — args.filenames attribute read: operator-specified local source paths to add to the archive (write side; szf.writeall(src)/szf.write(src)). Operator-authorized; a tainted value would let the archive re…
- `p1-src-013` source/candidate conf=0.45 — cli.py:434 arcfile — args.arcfile on the create/append side: operator-specified OUTPUT archive path (string, '.7z' suffix enforced at cli.py:397/:436). Write-side, operator-authorized local CLI usage; candidate only for f…
- `p1-src-014` source/candidate conf=0.45 — cli.py:435 filenames — args.filenames attribute read: operator-specified local source paths to add to the archive (write side; szf.writeall(src)/szf.write(src)). Operator-authorized; a tainted value would let the archive re…
- `p1-src-015` source/candidate conf=0.50 — py7zr.py:320 __init__ — SevenZipFile.__init__ 'file' parameter (str / pathlib.Path / BinaryIO / MultiVolume) is the public library API path of the archive itself, opened directly at py7zr.py:344-364. Semi-trusted: the embedd…
- `p1-src-016` source/candidate conf=0.50 — py7zr.py:320 __init__ — SevenZipFile.__init__ 'file' parameter (str / pathlib.Path / BinaryIO / MultiVolume) is the public library API path of the archive itself, opened directly at py7zr.py:344-364. Semi-trusted: the embedd…
- `p1-src-017` source/candidate conf=0.50 — py7zr.py:526 _extract — SevenZipFile._extract 'path' parameter: the caller-supplied output base directory; converted at :542 (str -> pathlib.Path), mkdir'd at :545 and used as the joinpath base at :582. Caller-authorized out…
- `p1-src-018` source/candidate conf=0.50 — py7zr.py:526 _extract — SevenZipFile._extract 'path' parameter: the caller-supplied output base directory; converted at :542 (str -> pathlib.Path), mkdir'd at :545 and used as the joinpath base at :582. Caller-authorized out…
- `p1-src-033` source/candidate conf=0.55 — py7zr.py:974 extractall — SevenZipFile.extractall 'path' parameter -- the public extraction API's output directory, forwarded to _extract (also the destination used by the unpack_7zarchive shutil hook). Caller-authorized locat…
- `p1-src-034` source/candidate conf=0.55 — py7zr.py:974 extractall — SevenZipFile.extractall 'path' parameter -- the public extraction API's output directory, forwarded to _extract (also the destination used by the unpack_7zarchive shutil hook). Caller-authorized locat…
- `p1-src-037` source/candidate conf=0.55 — py7zr.py:986 extract — SevenZipFile.extract 'path' parameter -- public extraction API output directory, same trust analysis as extractall path. Caller-authorized; candidate for embedding scenarios.
- `p1-src-038` source/candidate conf=0.55 — py7zr.py:986 extract — SevenZipFile.extract 'path' parameter -- public extraction API output directory, same trust analysis as extractall path. Caller-authorized; candidate for embedding scenarios.
- `p1-src-041` source/candidate conf=0.45 — py7zr.py:1012 writeall — SevenZipFile.writeall 'path' parameter: the write-side walk root (operator-supplied in the CLI). A tainted value would make py7zr read arbitrary local files into the archive (information disclosure), …
- `p1-src-042` source/candidate conf=0.45 — py7zr.py:1012 writeall — SevenZipFile.writeall 'path' parameter: the write-side walk root (operator-supplied in the CLI). A tainted value would make py7zr read arbitrary local files into the archive (information disclosure), …
- `p1-src-043` source/candidate conf=0.45 — py7zr.py:1023 write — SevenZipFile.write 'file' parameter: single local file to archive (write side). Same operator-trust analysis as writeall path; candidate only.
- `p1-src-044` source/candidate conf=0.45 — py7zr.py:1023 write — SevenZipFile.write 'file' parameter: single local file to archive (write side). Same operator-trust analysis as writeall path; candidate only.
- `p1-src-045` source/candidate conf=0.45 — py7zr.py:1144 is_7zfile — is_7zfile 'file' parameter: public helper that opens the given path read-only for a magic-number check (:1155/:1158). Caller-supplied path; candidate source for applications passing user-influenced pa…
- `p1-src-046` source/candidate conf=0.45 — py7zr.py:1144 is_7zfile — is_7zfile 'file' parameter: public helper that opens the given path read-only for a magic-number check (:1155/:1158). Caller-supplied path; candidate source for applications passing user-influenced pa…
- `p1-src-047` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive — unpack_7zarchive 'archive' parameter: this function is the registration target of shutil.register_unpack_format(), so any application calling shutil.unpack_archive() with a 7z hands the archive path s…
- `p1-src-048` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive — unpack_7zarchive 'archive' parameter: this function is the registration target of shutil.register_unpack_format(), so any application calling shutil.unpack_archive() with a 7z hands the archive path s…
- `p1-src-049` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive — unpack_7zarchive 'path' parameter: the extraction destination of the shutil.register_unpack_format() hook -- shutil.unpack_archive(filename, extract_dir) forwards the caller's extract_dir here. Servic…
- `p1-src-050` source/candidate conf=0.60 — py7zr.py:1167 unpack_7zarchive — unpack_7zarchive 'path' parameter: the extraction destination of the shutil.register_unpack_format() hook -- shutil.unpack_archive(filename, extract_dir) forwards the caller's extract_dir here. Servic…
- `p1-src-051` source/candidate conf=0.45 — py7zr.py:1176 pack_7zarchive — pack_7zarchive 'base_name' parameter: the shutil.register_archive_format() hook's output archive name; target_name = '{}.7z'.format(base_name) is opened for writing. Write-side, application-supplied; …
- `p1-src-052` source/candidate conf=0.45 — py7zr.py:1176 pack_7zarchive — pack_7zarchive 'base_name' parameter: the shutil.register_archive_format() hook's output archive name; target_name = '{}.7z'.format(base_name) is opened for writing. Write-side, application-supplied; …
- `p1-src-053` source/candidate conf=0.50 — py7zr.py:1176 pack_7zarchive — pack_7zarchive 'base_dir' parameter: the directory walked by archive.writeall(path=base_dir) in the shutil.register_archive_format() hook. Same write-side trust analysis as writeall path; candidate.
- `p1-src-054` source/candidate conf=0.50 — py7zr.py:1176 pack_7zarchive — pack_7zarchive 'base_dir' parameter: the directory walked by archive.writeall(path=base_dir) in the shutil.register_archive_format() hook. Same write-side trust analysis as writeall path; candidate.
- `p1-sink-022` summary/candidate conf=0.40 — helpers.py:299 Path — pathlib.Path(res) converts the readlink result string back to a Path inside the compat wrapper (helpers.py:298-299). Taint-preserving str->Path conversion, but every in-tree use is on the write side w…
- `p1-sink-039` sink/candidate conf=0.60 — py7zr.py:545 mkdir — path.mkdir(parents=True) creates the caller-supplied output directory. Genuine filesystem-mutation sink, but every in-tree feeder is a caller param (extractall/extract path, CLI args.odir) that the op…
- `p1-sink-050` summary/candidate conf=0.50 — py7zr.py:597 WindowsPath — Windows long-path prefixing: pathlib.WindowsPath('\\?\' + str(outfilename)) when is_windows_native_python() and outfilename.is_absolute() and not a UNC path. Taint-preserving rewrite of an (entry-name…
- `p1-sink-125` summary/candidate conf=0.40 — win32compat.py:198 WindowsPath — pathlib.WindowsPath(rpath) at win32compat.py:198 converts the decoded reparse-point target back to a Path. Taint-preserving str->Path conversion, but write-side-only usage in-tree; low-confidence summ…

## Schema validation

- jsonschema 4.26.0 (Draft 2020-12) against `C:\Users\lzh\Desktop\github\PyVul-main\iris_tools\augur-0.3.0\assets\labels_schema.json`: **VALID** (0 errors)
- arg_index bound check: OK (all `argument` flow-kind entries carry a non-negative integer arg_index; `receiver`/`field`/`return` entries carry null; `param` entries carry the CSV-contract position including the self slot)
- Entry id uniqueness: OK (191 unique ids)
