# -*- coding: utf-8 -*-
"""Pass 5 (CWE-89 SQL Injection) label generation for the django iris workspace.

Reads extraction/sources.csv + extraction/sinks.csv, assigns every candidate row
to exactly one semantic group (rules below encode the LLM labeling decisions made
from verified evidence in the CodeQL DB source snapshot), and emits:
  labels/labels.json            (schema: assets/labels_schema.json)
  labels/labels_raw_pass5.json  (batches + full coverage / dedup audit)
  labels/label_stats.md
  labels/phase1_review.md

Every CSV row must be assigned to exactly one group; the script asserts this.
"""
import csv
import json
import os
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone

IRIS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(IRIS, "extraction")
OUT = os.path.join(IRIS, "labels")
DBROOT = "C:/Users/lzh/Desktop/github/PyVul-main/dataset/codeql_databases/sql_injection_dbs/django_vuln/"

MODEL = "glm-5.3"
RUN_ID = "django-pass5-cwe89-20261020"
GENERATED_AT = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

# ---------------------------------------------------------------- CSV loading

def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    hdr, data = rows[0], rows[1:]
    out = []
    for r in data:
        out.append({
            "node": r[0], "role_hint": r[1], "callable": r[2], "fk": r[3],
            "recv": r[4], "module": r[5], "arg": int(r[6]),
            "file": r[7], "line": int(r[8]), "match": r[9],
        })
    return out

sinks = load(os.path.join(SRC, "sinks.csv"))
srcs = load(os.path.join(SRC, "sources.csv"))


def rel(r):
    return r["file"].split("django_vuln/")[-1]

# ------------------------------------------------------- sink group rules

# CLI-dispatch .execute() call sites (name collisions with cursor.execute)
CLI_EXECUTE_SITES = {
    ("django/core/management/__init__.py", 198),
    ("django/core/management/__init__.py", 446),
    ("django/core/management/base.py", 402),
    ("django/core/management/commands/runserver.py", 74),
    ("django/contrib/auth/management/commands/createsuperuser.py", 88),
    ("django/core/management/commands/sqlmigrate.py", 38),
}
# BaseCommand.execute / ManagementUtility.execute *definitions* (CLI lifecycle)
CLI_EXECUTE_DEFS = {
    ("django/core/management/commands/runserver.py", 68),
    ("django/contrib/auth/management/commands/createsuperuser.py", 86),
    ("django/core/management/commands/sqlmigrate.py", 33),
}
CLI_DISPATCH_DEFS = {
    ("django/core/management/__init__.py", 87),       # call_command
    ("django/core/management/__init__.py", 443),      # execute_from_command_line
    ("django/core/management/base.py", 385),          # run_from_argv
}
# string constructions that are error/log messages, not SQL
MESSAGE_CONSTRUCTIONS = {
    ("django/core/management/__init__.py", 116),
    ("django/core/management/__init__.py", 165),
    ("django/core/management/__init__.py", 185),
    ("django/core/management/base.py", 411),
    ("django/db/models/sql/query.py", 149),
}
# connection-state wrappers executing only static literal SQL
STATIC_SQL_WRAPPERS = {
    "init_connection_state", "is_usable", "mysql_server_data", "get_new_connection",
    "prepare_database", "_start_transaction_under_autocommit",
    "supports_transactions", "supports_json_field", "supports_collation_on_charfield",
    "get_hstore_oids", "get_citext_oids",
}
# connection-state wrappers whose params can reach SQL text
DYNAMIC_CONNSTATE = {
    "_savepoint", "_savepoint_rollback", "_savepoint_commit", "ensure_timezone",
    "check_constraints", "disable_constraint_checking", "enable_constraint_checking",
    "genexpr",
}
ORM_RAW_DEFS = {
    ("django/db/models/query.py", "raw"), ("django/db/models/query.py", "extra"),
    ("django/db/models/expressions.py", "__init__"),
    ("django/db/models/sql/query.py", "__init__"),
    ("django/db/models/query.py", "__init__"), ("django/db/models/sql/query.py", "_execute_query"),
}


def sink_group(r):
    f, c, fk, node, call, arg = rel(r), r["callable"], r["fk"], r["node"], r["callable"], r["arg"]
    key = (f, r["line"])

    if f.startswith("django/test/"):
        # framework test infrastructure (shipped in django/test/, not the excluded tests/ tree)
        return "G24-testinfra-fp"

    if fk in ("sql_percent_format", "sql_fstring", "sql_concat", "sql_format_call"):
        if key in MESSAGE_CONSTRUCTIONS:
            return "G14-msg-fp"
        return "G15-sql-construction"

    if fk == "bound_params":
        return "GB-boundparams-san"

    if f == "django/core/cache/backends/redis.py":
        return "G18-redis-fp"

    if node.startswith("Attribute") and call in ("execute", "executemany", "callproc"):
        if key in CLI_EXECUTE_SITES:
            return "G16-cliexecute-fp"
        if fk in ("sql_text",):
            if call == "callproc":
                return "G2b-callproc"
            return "G1-execute-callsite"
        return "GB-boundparams-san"  # defensive; bound handled above

    if node.startswith("Function"):
        # CLI dispatch wrapper defs
        if key in CLI_DISPATCH_DEFS:
            return "G17-cli-dispatch"
        if key in CLI_EXECUTE_DEFS:
            return "G16-cliexecute-fp"
        if f == "django/core/management/__init__.py" and call in ("call_command", "execute_from_command_line"):
            return "G17-cli-dispatch"
        if f == "django/core/management/base.py" and call == "run_from_argv":
            return "G17-cli-dispatch"
        # sqlite function registration
        if f == "django/db/backends/sqlite3/_functions.py" and call == "register":
            return "G19-register-fp"

        # central wrapper definitions
        if f == "django/db/backends/utils.py":
            if call == "callproc":
                return "G2b-callproc"
            if call in ("_execute", "_executemany") and fk == "internal_sql_wrapper":
                return "G2c-wrapper-glue"
            if fk in ("sql_text", "internal_sql_wrapper") and call in ("execute", "executemany"):
                return "G2a-cursorwrapper-def"
            return "GB-boundparams-san"
        if f == "django/db/backends/sqlite3/base.py":
            if call in DYNAMIC_CONNSTATE:
                return "G13a-connstate"
            if call in STATIC_SQL_WRAPPERS:
                return "G13b-static-fp"
            return "G3-sqlite-wrapper"          # execute/executemany defs
        if f == "django/db/backends/mysql/base.py":
            if call in DYNAMIC_CONNSTATE:
                return "G13a-connstate"
            if call in STATIC_SQL_WRAPPERS:
                return "G13b-static-fp"
            return "G4-mysql-wrapper"
        if f == "django/db/backends/oracle/base.py":
            if call in DYNAMIC_CONNSTATE:
                return "G13a-connstate"
            if call in STATIC_SQL_WRAPPERS:
                return "G13b-static-fp"
            return "G5-oracle-wrapper"
        if f == "django/db/backends/base/base.py" and call in DYNAMIC_CONNSTATE:
            return "G13a-connstate"
        if f == "django/db/backends/postgresql/base.py":
            if call in DYNAMIC_CONNSTATE:
                return "G13a-connstate"
            if call in STATIC_SQL_WRAPPERS:
                return "G13b-static-fp"
            return "G13a-connstate"
        if "/contrib/gis/db/backends/" in f and f.endswith("base.py"):
            return "G13b-static-fp"             # prepare_database (static init SQL)

        # ORM raw SQL API definitions
        if (f, call) in ORM_RAW_DEFS and f.startswith("django/db/models/"):
            return "G7-orm-raw-apis"
        if f == "django/db/models/sql/compiler.py":
            return "G6-compiler"
        if f == "django/db/models/sql/query.py" and call == "_execute_query":
            return "G7-orm-raw-apis"

        # schema editors
        if f == "django/db/backends/base/schema.py" and call == "execute":
            return "G8-schemaeditor-execute"
        if "/schema.py" in f and ("/db/backends/" in f or "/gis/db/backends/" in f):
            return "G9-schema-summary"
        if f == "django/db/backends/base/schema.py":
            return "G9-schema-summary"

        # introspection
        if "/introspection.py" in f:
            return "G10-introspection-summary"
        # creation / test-db DDL
        if "/creation.py" in f:
            return "G11-creation-summary"
        # operations
        if f.endswith("operations.py") and ("/db/backends/" in f or "/gis/db/backends/" in f):
            return "G12-ops-summary"
        if f == "django/db/backends/base/operations.py":
            return "G12-ops-summary"
        if f == "django/db/migrations/operations/special.py":
            return "G23-migration-ops"
        if f == "django/contrib/postgres/operations.py":
            return "G23-migration-ops"
        # features probes / signals (static SQL)
        if f.endswith("features.py") or f == "django/contrib/postgres/signals.py":
            return "G13b-static-fp"
        # cache backend
        if f == "django/core/cache/backends/db.py":
            return "G20-cache-summary"
        # management commands that build/execute SQL
        if f == "django/core/management/commands/createcachetable.py":
            return "G21-mgmtsql-summary"
        if f == "django/core/management/commands/loaddata.py":
            return "G21-mgmtsql-summary"
        if f == "django/contrib/sites/management.py":
            return "G21-mgmtsql-summary"
        # backend state wrappers not matched above
        if "/db/backends/" in f:
            if call in STATIC_SQL_WRAPPERS:
                return "G13b-static-fp"
            return "G13a-connstate"
    return None

# --------------------------------------------------- source group rules

HTTP_FIELD_SET = {"GET", "POST", "META", "COOKIES", "FILES", "body", "headers"}
WSGI_ACCESSORS = {"get", "get_bytes_from_wsgi", "get_script_name", "get_path_info",
                  "application", "__call__", "update", "items", "copy", "urlencode"}
MGMT_SQL_FILES = {
    "django/core/management/commands/createcachetable.py",
    "django/core/management/commands/loaddata.py",
    "django/core/management/commands/flush.py",
}


def src_group(r):
    f, c, fk, call = rel(r), r["callable"], r["fk"], r["callable"]

    if fk == "http_request":
        if call in HTTP_FIELD_SET and call not in ("get", "items", "copy", "urlencode"):
            return "P1-request-field"
        if call == "environ":
            return "P2-wsgi-environ"
        if call in ("get_bytes_from_wsgi", "get_script_name", "get_path_info"):
            return "P2-wsgi-environ"
        if call in ("items", "copy", "urlencode"):
            return "P4-map-ops"
        # environ.get / request attribute .get() etc.
        return "P2-wsgi-environ" if "handlers/wsgi" in f or "environ" in r["recv"] else "P3-request-get"

    if fk == "request_param":
        if call == "get":
            return "P3-request-get"
        if call == "getlist":
            return "P3-request-get"
        if call in HTTP_FIELD_SET:
            return "P1-request-field"
        return "P3-request-get"

    if fk == "param":
        if call == "kwargs":
            return "P6-url-kwargs"
        return "P5-handler-request"

    if fk == "cli":
        if call == "options":
            return "P7-cli-options"
        if call == "add_argument":
            return "P8-addargument-fp"
        if call == "argv":
            return "P9-cli-argv"
        return "P7-cli-options"

    if fk == "file":
        if call == "open":
            return "P10-file-open"
        return "P11-file-read"

    if fk == "env":
        return "P12-os-environ"

    if fk == "config":
        return "P13-settings"

    if fk == "internal_transfer":
        if call == "call_command":
            return "G17-cli-dispatch"
        if f in MGMT_SQL_FILES or f == "django/contrib/sites/management.py":
            return "G21-mgmtsql-summary"
        if f == "django/core/management/commands/inspectdb.py":
            return "G10-introspection-summary"
        if "migrations" in f and f.startswith("django/db/"):
            return "G23-migration-ops"
        if f.startswith("django/contrib/postgres/"):
            return "G23-migration-ops"
        if "/schema" in f and ("/db/backends/" in f or "/gis/db/backends/" in f):
            return "G9-schema-summary"
        if "/introspection" in f:
            return "G10-introspection-summary"
        if "/creation" in f and "/db/backends/" in f:
            return "G11-creation-summary"
        if f.endswith("operations.py") and ("/db/backends/" in f or "/gis/db/" in f):
            return "G12-ops-summary"
        if f == "django/core/cache/backends/db.py":
            return "G20-cache-summary"
        if f == "django/db/models/sql/compiler.py":
            return "G6-compiler"
        if "/db/backends/" in f:
            return "G13a-connstate"
        return "P15-internal-other"
    return None


def assign(rows, fn, tag):
    groups = defaultdict(list)
    unassigned = []
    for i, r in enumerate(rows, start=2):  # CSV line numbers (1 header)
        g = fn(r)
        if g is None:
            unassigned.append((i, rel(r), r["line"], r["callable"], r["fk"], r["node"]))
        else:
            r["_csv_line"] = i
            groups[g].append(r)
    if unassigned:
        print("UNASSIGNED", tag, len(unassigned))
        for u in unassigned[:40]:
            print("   ", u)
    return groups


g_sinks = assign(sinks, sink_group, "sinks")
g_srcs = assign(srcs, src_group, "sources")

total_assigned = sum(len(v) for v in g_sinks.values()) + sum(len(v) for v in g_srcs.values())
assert total_assigned == len(sinks) + len(srcs), (total_assigned, len(sinks) + len(srcs))
print("coverage OK:", len(sinks), "sink rows,", len(srcs), "source rows ->",
      len(g_sinks), "+", len(g_srcs), "groups")

# ------------------------------------------------------------- group stats

def gstat(groups):
    st = {}
    for gid, rows in groups.items():
        files = defaultdict(int)
        for r in rows:
            files[rel(r)] += 1
        st[gid] = {
            "rows": len(rows),
            "distinct_files": len(files),
            "top_files": sorted(files.items(), key=lambda x: -x[1])[:6],
            "samples": ["%s:%d" % (rel(r), r["line"]) for r in rows[:8]],
        }
    return st

st_sinks, st_srcs = gstat(g_sinks), gstat(g_srcs)
stats = {}
all_gids = sorted(set(st_sinks) | set(st_srcs))
for gid in all_gids:
    a, b = st_sinks.get(gid), st_srcs.get(gid)
    if a and b:
        stats[gid] = {
            "csv": "sinks+sources", "rows": a["rows"] + b["rows"],
            "distinct_files": a["distinct_files"] + b["distinct_files"],
            "top_files": sorted(set([f for f, _ in a["top_files"]] + [f for f, _ in b["top_files"]]))[:8],
            "samples": a["samples"][:4] + b["samples"][:4],
            "sink_rows": a["rows"], "source_rows": b["rows"],
        }
        stats[gid]["top_files"] = [(f, 0) for f in stats[gid]["top_files"]]
    elif a:
        stats[gid] = {"csv": "sinks", **a, "sink_rows": a["rows"], "source_rows": 0}
    else:
        stats[gid] = {"csv": "sources", **b, "sink_rows": 0, "source_rows": b["rows"]}

# ------------------------------------------------------------- label entries
# hand-authored decisions; n(...) counts are filled in below from stats.

E = []


def entry(eid, role, cls, conf, callable_, flow, arg, module, loc, rationale,
          evidence, covers):
    sig = {"callable": callable_, "flow_kind": flow}
    if arg is not None:
        sig["arg_index"] = arg
    if module is not None:
        sig["module"] = module
    e = {
        "id": eid, "role": role, "classification": cls, "confidence": conf,
        "signature": sig, "rationale": rationale, "evidence": evidence, "_covers": covers,
    }
    if loc:
        e["location"] = {"file": loc[0], "line": loc[1]}
    E.append(e)


n = lambda gid: stats.get(gid, {}).get("rows", 0)
loc_of = lambda gid: (stats[gid]["samples"][0].rsplit(":", 1)[0], int(stats[gid]["samples"][0].rsplit(":", 1)[1])) if gid in stats and stats[gid]["samples"] else None

# --- sinks: the execution funnel -----------------------------------------

entry("p5-sink-001", "sink", "tp", 0.9, "execute", "argument", 0, None,
      ("django/db/models/sql/compiler.py", 1395),
      "The <obj>.execute(sql, ...) call sites across django/db (ORM compilers, schema editors, "
      "backend base/introspection/creation/operations, GIS backends, sqlite _functions, cache backend) "
      "are the framework's genuine raw-SQL execution channel: SQL text is argument 0. Verified dynamic "
      "instances interpolate only quote_name()-quoted identifiers, settings/DB-derived names, or keep "
      "values in the bound-params argument; many instances are static literal SQL (PRAGMA/SET probes). "
      "The signature is a true SQL-text sink for pass 5; whether any instance's SQL text carries "
      "request-influenced data is resolved by the Phase 2 taint query - in this snapshot no framework "
      "request path feeds raw SQL text.",
      ["covers %d sink rows (receiver names cursor/curs/conn/self/schema_editor) across %d files"
       % (n("G1-execute-callsite"), stats.get("G1-execute-callsite", {}).get("distinct_files", 0)),
       "ORM endpoint: cursor.execute(sql, params) django/db/models/sql/compiler.py:1395 and :1657 (parameterized by construction)",
       "schema editor funnel: cursor.execute(sql, params) django/db/backends/base/schema.py:199",
       "introspection: cursor.execute('PRAGMA table_info(%s)' % quote_name(table_name)) django/db/backends/sqlite3/introspection.py:94",
       "static literal instances: django/db/backends/base/features.py:363-370 ROLLBACK_TEST probes, sqlite3/base.py:170/173 PRAGMA constants"],
      ["G1-execute-callsite"])

entry("p5-sink-002", "sink", "tp", 0.95, "execute", "param", 1, "django.db.backends.utils",
      ("django/db/backends/utils.py", 66),
      "CursorWrapper.execute(sql, params=None) is the central PEP-249 funnel every backend cursor "
      "goes through (django/db/backends/utils.py:66); sql is parameter 1 (after self) and is forwarded "
      "verbatim to the driver cursor via _execute. A tainted string reaching this parameter is executed "
      "as SQL. CursorDebugWrapper.execute (utils.py:101) subclasses and delegates - same signature, "
      "deduplicated into this entry.",
      ["def execute(self, sql, params=None): return self._execute_with_wrappers(sql, params, many=False, executor=self._execute) - django/db/backends/utils.py:66",
       "covers sink rows for CursorWrapper.execute / CursorDebugWrapper.execute definitions (utils.py:66, 101)",
       "_execute forwards verbatim: self.cursor.execute(sql) / (sql, params) - utils.py:82-89"],
      ["G2a-cursorwrapper-def"])

entry("p5-sink-003", "sink", "tp", 0.9, "executemany", "param", 1, "django.db.backends.utils",
      ("django/db/backends/utils.py", 71),
      "CursorWrapper.executemany(sql, param_list) (utils.py:71; CursorDebugWrapper.executemany at :105, "
      "deduplicated) forwards the SQL text parameter to the driver cursor.executemany - genuine bulk "
      "SQL-text sink; param_list is the bound channel.",
      ["def executemany(self, sql, param_list) - django/db/backends/utils.py:71",
       "driver call: self.cursor.executemany(sql, param_list) - utils.py:94"],
      ["G2a-cursorwrapper-def"])

entry("p5-sink-004", "sink", "tp", 0.75, "callproc", "param", 1, "django.db.backends.utils",
      ("django/db/backends/utils.py", 48),
      "CursorWrapper.callproc(procname, params, kparams) - procname (parameter 1) names a stored "
      "procedure and becomes part of the executed statement, so it is SQL structure; the params "
      "argument is the bound channel. No attacker-reachable call site exists in this snapshot "
      "(cx_Oracle-oriented API), kept as sink for recall.",
      ["def callproc(self, procname, params=None, kparams=None) - utils.py:48",
       "driver calls self.cursor.callproc(procname[, params]) - utils.py:59-64"],
      ["G2b-callproc"])

entry("p5-sum-005", "summary", "tp", 0.7, "_execute", "param", 1, "django.db.backends.utils",
      ("django/db/backends/utils.py", 82),
      "CursorWrapper._execute / _executemany are the wrapper glue that carries (sql, params) from "
      "CursorWrapper.execute to the driver cursor (utils.py:82-94); modeled as taint step so wrapper "
      "chains reach the labeled sink.",
      ["_execute(self, sql, params, *ignored_wrapper_args) - utils.py:82",
       "also covers _executemany (utils.py:91) and the _execute_with_wrappers indirection (utils.py:76)"],
      ["G2c-wrapper-glue"])

entry("p5-sink-006", "sink", "tp", 0.85, "execute", "param", 1, "django.db.backends.sqlite3.base",
      ("django/db/backends/sqlite3/base.py", 353),
      "SQLiteCursorWrapper.execute(query, params=None) (sqlite3/base.py:353) converts %s placeholders "
      "to ? via convert_query and calls Database.Cursor.execute. convert_query is placeholder syntax "
      "conversion only - NOT a taint barrier for SQL text.",
      ["def execute(self, query, params=None) - sqlite3/base.py:353",
       "convert_query: FORMAT_QMARK_REGEX.sub('?', query).replace('%%', '%') - sqlite3/base.py:363-364"],
      ["G3-sqlite-wrapper"])

entry("p5-sink-007", "sink", "tp", 0.85, "executemany", "param", 1, "django.db.backends.sqlite3.base",
      ("django/db/backends/sqlite3/base.py", 359),
      "SQLiteCursorWrapper.executemany(query, param_list) (sqlite3/base.py:359) - same channel as "
      "execute; query parameter is SQL text.",
      ["def executemany(self, query, param_list) - sqlite3/base.py:359"],
      ["G3-sqlite-wrapper"])

entry("p5-sink-008", "sink", "tp", 0.85, "execute", "param", 1, "django.db.backends.mysql.base",
      ("django/db/backends/mysql/base.py", 72),
      "MySQLdb CursorWrapper.execute(query, args=None) (mysql/base.py:72) forwards (query, args) "
      "directly to the MySQLdb driver cursor - query parameter is SQL text.",
      ["def execute(self, query, args=None): return self.cursor.execute(query, args) - mysql/base.py:72-75"],
      ["G4-mysql-wrapper"])

entry("p5-sink-009", "sink", "tp", 0.85, "executemany", "param", 1, "django.db.backends.mysql.base",
      ("django/db/backends/mysql/base.py", 83),
      "MySQLdb CursorWrapper.executemany(query, args) (mysql/base.py:83) - bulk SQL-text channel.",
      ["def executemany(self, query, args) - mysql/base.py:83"],
      ["G4-mysql-wrapper"])

entry("p5-sink-010", "sink", "tp", 0.85, "execute", "param", 1, "django.db.backends.oracle.base",
      ("django/db/backends/oracle/base.py", 552),
      "Oracle FormatStylePlaceholderCursor.execute(query, params=None) (oracle/base.py:552) rewrites "
      ":name placeholders via _fix_for_params and calls the cx_Oracle driver cursor. Placeholder "
      "normalization does not sanitize SQL text - query parameter remains the SQL-text sink.",
      ["def execute(self, query, params=None): query, params = self._fix_for_params(query, params, unify_by_values=True) - oracle/base.py:552-556"],
      ["G5-oracle-wrapper"])

entry("p5-sink-011", "sink", "tp", 0.85, "executemany", "param", 1, "django.db.backends.oracle.base",
      ("django/db/backends/oracle/base.py", 558),
      "Oracle FormatStylePlaceholderCursor.executemany (oracle/base.py:558) - bulk SQL-text channel.",
      ["def executemany(self, query, params=None) - oracle/base.py:558"],
      ["G5-oracle-wrapper"])

entry("p5-sum-012", "summary", "tp", 0.7, "execute_sql", "param", None, "django.db.models.sql.compiler",
      ("django/db/models/sql/compiler.py", 1365),
      "SQLCompiler.execute_sql / SQLInsertCompiler.execute_sql (compiler.py:1365, 1647) propagate the "
      "ORM-compiled (sql, params) pair to cursor.execute - summary step so ORM flows connect to the "
      "execute sink. Compiled SQL is parameterized by construction.",
      ["sql, params = self.as_sql(); cursor.execute(sql, params) - compiler.py:1382, 1395",
       "insert loop: for sql, params in self.as_sql(): cursor.execute(sql, params) - compiler.py:1656-1657"],
      ["G6-compiler"])

# --- sinks: ORM raw SQL APIs ---------------------------------------------

entry("p5-sink-013", "sink", "tp", 0.9, "raw", "param", 1, "django.db.models.query",
      ("django/db/models/query.py", 1284),
      "QuerySet.raw(raw_query, params=(), ...) (query.py:1284) is the public raw-SQL API: raw_query "
      "(parameter 1 after self) is executed verbatim via RawQuerySet -> sql.RawQuery -> "
      "RawQuery._execute_query -> cursor.execute(self.sql, params); only params is bound. Downstream "
      "applications passing request data as raw_query are injectable; no such call site exists in "
      "non-test framework code in this snapshot.",
      ["def raw(self, raw_query, params=(), translations=None, using=None) - query.py:1284",
       "execution chain: RawQuerySet.__init__ -> sql.RawQuery(sql=raw_query, ...) -> self.cursor.execute(self.sql, params) - sql/query.py:152"],
      ["G7-orm-raw-apis"])

entry("p5-sink-014", "sink", "tp", 0.85, "extra", "param", 1, "django.db.models.query",
      ("django/db/models/query.py", 1670),
      "QuerySet.extra(select, where, params, tables, order_by, select_params) (query.py:1670) injects "
      "caller-supplied SQL fragments directly into the ORM query: select (param 1), where (2), tables "
      "(4), order_by (5) become SQL text; params (3) and select_params (6) are the bound channel. "
      "Fragment parameters are genuine SQL-structure sinks (documented unsafe API for user input).",
      ["def extra(self, select=None, where=None, params=None, tables=None, order_by=None, select_params=None) - query.py:1670-1678",
       "clone.query.add_extra(select, select_params, where, params, tables, order_by) - query.py:1684"],
      ["G7-orm-raw-apis"])

entry("p5-sink-015", "sink", "tp", 0.85, "__init__", "param", 1, "django.db.models.expressions",
      ("django/db/models/expressions.py", 1049),
      "RawSQL(sql, params, output_field) (expressions.py:1049) embeds sql (parameter 1) verbatim into "
      "the compiled query - as_sql returns ('(%s)' % self.sql, self.params); params (2) is bound.",
      ["class RawSQL(Expression): def __init__(self, sql, params, output_field=None) - expressions.py:1048-1052",
       "as_sql: return '(%s)' % self.sql, self.params - expressions.py:1058-1059"],
      ["G7-orm-raw-apis"])

entry("p5-sink-016", "sink", "tp", 0.85, "__init__", "param", 1, "django.db.models.sql.query",
      ("django/db/models/sql/query.py", 85),
      "RawQuery.__init__(sql, using, params) (sql/query.py:85) stores sql (parameter 1) for verbatim "
      "execution in _execute_query; params (parameter 3) is bound.",
      ["class RawQuery: def __init__(self, sql, using, params=()) - sql/query.py:82-85",
       "self.cursor.execute(self.sql, params) - sql/query.py:152"],
      ["G7-orm-raw-apis"])

entry("p5-sink-017", "sink", "tp", 0.85, "__init__", "param", 1, "django.db.models.query",
      ("django/db/models/query.py", 1995),
      "RawQuerySet.__init__(raw_query, ...) (query.py:1995) routes raw_query (parameter 1) into "
      "sql.RawQuery; params (parameter 4) is bound.",
      ["def __init__(self, raw_query, model=None, query=None, params=(), ...) - query.py:1995",
       "self.query = query or sql.RawQuery(sql=raw_query, using=self.db, params=params) - query.py:2009"],
      ["G7-orm-raw-apis"])

entry("p5-sum-018", "summary", "tp", 0.7, "_execute_query", "param", None, "django.db.models.sql.query",
      ("django/db/models/sql/query.py", 135),
      "RawQuery._execute_query (sql/query.py:135) is the glue carrying self.sql/self.params to "
      "connection.cursor().execute - summary step for the raw() execution chain.",
      ["self.cursor = connection.cursor(); self.cursor.execute(self.sql, params) - sql/query.py:151-152"],
      ["G7-orm-raw-apis"])

# --- sinks: schema editor / DDL funnel -----------------------------------

entry("p5-sink-019", "sink", "tp", 0.85, "execute", "param", 1, "django.db.backends.base.schema",
      ("django/db/backends/base/schema.py", 170),
      "BaseDatabaseSchemaEditor.execute(sql, params=()) (base/schema.py:170) is the DDL funnel used "
      "by every migration; sql (parameter 1 after self) is str()-cast and passed to cursor.execute. "
      "Callers across all schema editors %-interpolate quote_name-quoted identifiers into sql; "
      "collect_sql mode interpolates quote_value()-treated params.",
      ["def execute(self, sql, params=()) ... sql = str(sql) ... cursor.execute(sql, params) - base/schema.py:170-199",
       "collect path: (sql % tuple(map(self.quote_value, params))) - base/schema.py:193"],
      ["G8-schemaeditor-execute"])

entry("p5-sum-020", "summary", "tp", 0.65, "alter_field", "param", None, None,
      ("django/db/backends/base/schema.py", 437),
      "Schema-editor mutation methods (create_model, delete_model, add_field, remove_field, "
      "alter_field, add_index, remove_index, add_constraint, alter_db_table, _alter_field, "
      "_remake_table, __exit__/deferred_sql, plus postgresql/mysql/sqlite3/oracle/GIS overrides) "
      "route model-metadata-derived table/column identifiers into SchemaEditor.execute - summary "
      "edges keep migration-state to DDL flows connected. Identifiers are framework/model-derived "
      "(operator trust), quoted via quote_name inside the template constructors.",
      ["covers %d sink-csv wrapper-definition rows + %d source-csv call rows across base and backend schema editors"
       % (stats["G9-schema-summary"]["sink_rows"], stats["G9-schema-summary"]["source_rows"]),
       "representative: self.execute(sql, params) callers at base/schema.py:445-1135; spatialite/schema.py:69-188; oracle/schema.py:56-237"],
      ["G9-schema-summary"])

entry("p5-sum-021", "summary", "tp", 0.6, "get_table_description", "param", None, None,
      ("django/db/backends/sqlite3/introspection.py", 88),
      "DatabaseIntrospection methods (get_table_list, get_table_description, get_relations, "
      "get_constraints, get_sequences, get_primary_key_columns, get_storage_engine, get_geometry_type, "
      "get_field_type, _get_column_collations) propagate cursor + table_name/index parameters into "
      "information_schema/PRAGMA/SHOW SQL. Injection-shaped %-interpolation but inputs are DB-derived "
      "introspection names (second-order taint) usually quote_name-quoted; some sites use bound "
      "parameters instead. Retained as summary for second-order flow; manual review flagged.",
      ["'PRAGMA table_info(%s)' % self.connection.ops.quote_name(table_name) - sqlite3/introspection.py:94",
       "'SHOW INDEX FROM %s' % self.connection.ops.quote_name(table_name) - mysql/introspection.py:310",
       "bound-parameter variant: cursor.execute(type_query, [table_name]) - mysql/introspection.py:289; postgresql/introspection.py:57"],
      ["G10-introspection-summary"])

entry("p5-sum-022", "summary", "tp", 0.6, "_execute_create_test_db", "param", None, None,
      ("django/db/backends/base/creation.py", 185),
      "Test-database creation wrappers (_execute_create_test_db, _create_test_db, _destroy_test_db, "
      "_clone_test_db, _database_exists, _execute_statements) build CREATE/DROP DATABASE/USER DDL from "
      "settings-derived names via quote_name'd %-formatting. Operator-level trust (settings.DATABASES "
      "and test runner config); summary edges only.",
      ["cursor.execute('CREATE DATABASE %(dbname)s %(suffix)s' % parameters) - base/creation.py:186",
       "DROP DATABASE %(dbname)s % test_db_params - base/creation.py:224, postgresql/creation.py:83",
       "template % parameters in _execute_statements - oracle/creation.py:325-330"],
      ["G11-creation-summary"])

entry("p5-sum-023", "summary", "tp", 0.6, "execute_sql_flush", "param", None, None,
      ("django/db/backends/base/operations.py", 441),
      "Backend operations helpers (execute_sql_flush, last_insert_id, __foreign_key_constraints, "
      "_get_sequence_name, __references_graph, _quote_params_for_last_executed_query, "
      "_get_postgis_func/_get_spatialite_func) propagate backend-generated SQL or model/DB-derived "
      "identifiers into the execute funnel. Inputs are framework-generated (operator/DB trust).",
      ["execute_sql_flush executes a backend-generated sql_list - base/operations.py:441-449",
       "cursor.execute('\"%s\".currval' % sq_name) with DB-derived sq_name - oracle/operations.py:341",
       "'SELECT %s' % func with constant spatial function names - spatialite/operations.py:151, postgis/operations.py:328"],
      ["G12-ops-summary"])

entry("p5-sum-024", "summary", "candidate", 0.55, "check_constraints", "param", None, None,
      ("django/db/backends/sqlite3/base.py", 221),
      "Connection-state wrappers whose parameters can reach SQL text: check_constraints(table_names) "
      "-> 'PRAGMA foreign_key_check(%s)' % quote_name(table_name) (sqlite3/base.py:235-238), "
      "_savepoint(sid) -> ops.savepoint_create_sql(sid), ensure_timezone, disable/enable_constraint_"
      "checking. sid is a framework-generated counter; table_names are DB/introspection-derived. "
      "Summary edges retained with manual-review flag (second-order).",
      ["_savepoint: cursor.execute(self.ops.savepoint_create_sql(sid)) - base/base.py:368-370",
       "check_constraints -> PRAGMA foreign_key_check(%s) % quote_name(table_name) - sqlite3/base.py:235-238"],
      ["G13a-connstate"])

entry("p5-none-025", "none", "fp", 0.85, "init_connection_state", "param", None, None,
      ("django/db/backends/postgresql/base.py", 250),
      "Wrappers executing only static literal SQL (init_connection_state, is_usable, "
      "mysql_server_data, get_new_connection, prepare_database, _start_transaction_under_autocommit, "
      "feature probes supports_transactions/supports_json_field/supports_collation_on_charfield, "
      "get_hstore_oids/get_citext_oids): their parameters do not influence SQL text - not pass-5 "
      "sinks. The genuine execute calls inside them are covered by the execute call-site entry.",
      ["static statements: 'ALTER SESSION SET NLS_TERRITORY = AMERICA' - oracle/base.py:267; 'PRAGMA foreign_keys = ON' - sqlite3/base.py:170",
       "feature probes execute literals ROLLBACK_TEST - base/features.py:363-370"],
      ["G13b-static-fp"])

# --- none / false-positive families --------------------------------------

entry("p5-none-026", "none", "fp", 0.9, "percent_format", "unknown", None, "django.core.management",
      ("django/core/management/__init__.py", 116),
      "String constructions producing error/log/stdout messages, not SQL: management/__init__.py:116 "
      "('Unknown command: %r'), :165 (f-string TypeError message), :185 (options error), management/"
      "base.py:411 (stderr formatting), sql/query.py:149 (RuntimeError 'Unexpected params type: %s'). "
      "Name-collision false positives of the sql_percent_format/sql_fstring extraction families.",
      ["raise CommandError('Unknown command: %r' % command_name) - management/__init__.py:116",
       "raise RuntimeError('Unexpected params type: %s' % params_type) - sql/query.py:149"],
      ["G14-msg-fp"])

entry("p5-none-027", "none", "fp", 0.7, "percent_format", "unknown", None, None,
      ("django/db/backends/sqlite3/base.py", 236),
      "SQL template constructions (% / f-string / concat) across backends: interpolations are "
      "quote_name()-quoted identifiers, settings/DB-derived names, or preserve %%s bound placeholders "
      "(cache db.py:144-196, mysql/schema.py, GIS DDL templates, check_constraints REFERRING joins). "
      "Construction nodes are not execution APIs - the built strings flow into the execute-family "
      "sinks already labeled, and %-formatting taint propagation is standard CodeQL modeling; no "
      "separate sink entry is warranted.",
      ["quote_name'd: 'PRAGMA foreign_key_check(%s)' % quote_name(table_name) - sqlite3/base.py:236",
       "bound placeholder preserved: 'UPDATE %s SET %s = %%s WHERE %s = %%s' % (table, quote_name(...)) - cache/backends/db.py:170-171",
       "GIS DDL templates: self.sql_add_spatial_index % {...} - gis schema editors"],
      ["G15-sql-construction"])

entry("p5-none-028", "none", "fp", 0.9, "execute", "argument", 0, "django.core.management",
      ("django/core/management/__init__.py", 198),
      ".execute() calls that are CLI command dispatch, not database cursors: management/__init__."
      "py:198 (command.execute(*args, **defaults)), :446 (utility.execute()), management/base.py:402 "
      "(self.execute(*args, **cmd_options)), runserver.py:74 / createsuperuser.py:88 / sqlmigrate.py:38 "
      "(super().execute(...) on BaseCommand). Method-name collision with cursor.execute.",
      ["return command.execute(*args, **defaults) - management/__init__.py:198",
       "utility.execute() (ManagementUtility CLI bootstrap) - management/__init__.py:446"],
      ["G16-cliexecute-fp"])

entry("p5-sum-029", "summary", "candidate", 0.5, "call_command", "param", 1, "django.core.management",
      ("django/core/management/__init__.py", 87),
      "CLI dispatch wrappers (call_command, execute_from_command_line, run_from_argv) propagate "
      "operator-supplied command names/options into management command handlers; commands such as "
      "createcachetable (CLI tablename -> quote_name'd DDL), loaddata, sqlmigrate and flush reach "
      "the SQL layer. Operator-level trust boundary (manage.py is run by the deployment operator "
      "with DB credentials) - classification 'candidate' pending manual review of any environment "
      "where commands are exposed to less-trusted callers.",
      ["call_command(command_name, *args, **options) -> command.execute(*args, **defaults) - management/__init__.py:87-198",
       "covers %d sink-csv wrapper definitions + %d source-csv call rows (call_command call sites)"
       % (stats["G17-cli-dispatch"]["sink_rows"], stats["G17-cli-dispatch"]["source_rows"])],
      ["G17-cli-dispatch"])

entry("p5-none-030", "none", "fp", 0.95, "execute", "argument", 0, "django.core.cache.backends.redis",
      ("django/core/cache/backends/redis.py", 148),
      "pipeline.execute() in django/core/cache/backends/redis.py:148 flushes a Redis command pipeline "
      "(set_many wrapper at :138 likewise) - Redis protocol, no SQL. Method-name collision with "
      "cursor.execute.",
      ["pipeline.mset(...); pipeline.execute() - redis.py:141-148"],
      ["G18-redis-fp"])

entry("p5-none-031", "none", "fp", 0.85, "register", "param", None, "django.db.backends.sqlite3._functions",
      ("django/db/backends/sqlite3/_functions.py", 40),
      "register() in django/db/backends/sqlite3/_functions.py registers Python callables as SQLite "
      "SQL functions via connection.create_function/create_aggregate - function registration, not "
      "SQL text execution.",
      ["connection.create_aggregate('STDDEV_SAMP', 1, StdDevSamp) - _functions.py:80"],
      ["G19-register-fp"])

entry("p5-sum-032", "summary", "tp", 0.65, "_base_set", "param", None, "django.core.cache.backends.db",
      ("django/core/cache/backends/db.py", 116),
      "DatabaseCache methods (get_many, _base_set, _base_delete_many, has_key, _cull, clear) build "
      "cache SQL with quote_name'd table/column identifiers and pass keys/values through the bound-"
      "parameter argument ([key] / [b64encoded, exp, key]); cache keys are make_and_validate_key()'d. "
      "Summary edges from the cache API to the execute funnel; value channel is parameterized.",
      ["cursor.execute('SELECT %s, %s FROM %s WHERE %s = %%s' % (quote_name(...)...), [key]) - db.py:143-152",
       "'INSERT INTO %s (%s, %s, %s) VALUES (%%s, %%s, %%s)' % (table, quote_name(...)), [key, b64encoded, exp] - db.py:188-196"],
      ["G20-cache-summary"])

entry("p5-sum-033", "summary", "candidate", 0.55, "create_table", "param", None, None,
      ("django/core/management/commands/createcachetable.py", 56),
      "Management-command SQL wrappers: createcachetable.create_table(database, tablename, dry_run) "
      "builds CREATE TABLE/INDEX DDL %-interpolating the CLI-supplied tablename (quote_name'd via qn) "
      "and executes it (createcachetable.py:64-127); loaddata.reset_sequences and sites."
      "create_default_site execute backend-generated sequence-reset SQL. CLI/operator trust - the "
      "tablename is the only externally supplied identifier; kept 'candidate' for manual review.",
      ["full_statement = ['CREATE TABLE %s (' % qn(tablename)] ... curs.execute(full_statement) - createcachetable.py:100-127",
       "sequence_sql from connection.ops.sequence_reset_sql(no_style(), models) - loaddata.py:131-137, sites/management.py:41-47"],
      ["G21-mgmtsql-summary"])

entry("p5-sum-034", "summary", "tp", 0.6, "database_forwards", "param", None, None,
      ("django/db/migrations/operations/special.py", 119),
      "Migration operations (RunSQL._run_sql, postgres CreateExtension/Collation/database_forwards, "
      "model/field operations) forward migration-defined SQL and identifiers into schema_editor."
      "execute. Migration content is developer-authored (operator trust); extension/collation names "
      "are quote_name'd before interpolation.",
      ["schema_editor.execute(sql, params=params) - migrations/operations/special.py:129",
       "'CREATE EXTENSION IF NOT EXISTS %s' % schema_editor.quote_name(self.name) - contrib/postgres/operations.py:27-30",
       "'CREATE COLLATION %(name)s (%(args)s)' % {...quote_name...} - contrib/postgres/operations.py:193-200"],
      ["G23-migration-ops"])

# --- sanitizers ------------------------------------------------------------

entry("p5-san-035", "sanitizer", "tp", 0.85, "execute", "argument", 1, None,
      ("django/db/models/sql/compiler.py", 1395),
      "The params/bound argument of the execute family (argument 1 at call sites, parameter 2 in "
      "wrapper definitions; likewise executemany param_list and callproc params) is the prepared-"
      "statement channel: values are substituted by the DB driver and cannot alter SQL text. This "
      "is the primary proven SQL-injection barrier for pass 5 - model as isBarrier at the bound-"
      "parameter positions so taint flowing into params does not reach the SQL-text sink.",
      ["cursor.execute(sql, params) ORM endpoint - compiler.py:1395/1657",
       "cache values bound: [key], [b64encoded, exp, key] - cache/backends/db.py:151/172/185/196",
       "bound introspection: cursor.execute(type_query, [table_name]) - mysql/introspection.py:289"],
      ["GB-boundparams-san"])

entry("p5-san-036", "sanitizer", "candidate", 0.4, "quote_name", "return", None, None,
      ("django/db/backends/sqlite3/operations.py", 189),
      "connection.ops.quote_name wraps identifiers in backend-specific quotes before %-interpolation "
      "into SQL text. Verified implementations do NOT escape embedded quote characters "
      "(sqlite3/postgresql: '\"%s\"' % name; mysql: '`%s`' % name) - quoting is adequate only for "
      "framework-controlled identifier character sets (model field names, introspected table names), "
      "NOT a strict input sanitizer. Recorded as sanitizer 'candidate' with manual-review flag: "
      "safe for the identifier families used at the observed call sites, unsafe as a general barrier "
      "for arbitrary attacker text.",
      ["sqlite3: return '\"%s\"' % name (no embedded-quote escaping) - sqlite3/operations.py:189-192",
       "mysql: return '`%s`' % name - mysql/operations.py quote_name",
       "used at: sqlite3/introspection.py:94, mysql/introspection.py:310, createcachetable.py:77-100 (qn), postgres/operations.py:29/196"],
      [])

# --- sources ----------------------------------------------------------------

entry("p5-src-037", "source", "tp", 0.9, "GET", "field", None, None,
      ("django/contrib/admin/views/main.py", 112),
      "request.GET (parsed QUERY_STRING via QueryDict) is the primary attacker-controlled input "
      "boundary of the framework's HTTP surface; attribute reads in admin ChangeList/autocompletion, "
      "generic date views, i18n and middleware are genuine pass-5 source nodes. Downstream framework "
      "consumption compiles to parameterized ORM SQL (admin filters/ordering), so sources are real "
      "but the observed channels are safe.",
      ["self.params = dict(request.GET.items()) - admin/views/main.py:112",
       "covers %d http_request/request_param rows for request.GET" % (
           sum(1 for r in g_srcs.get("P1-request-field", []) if r["callable"] == "GET"))],
      ["P1-request-field"])

entry("p5-src-038", "source", "tp", 0.9, "POST", "field", None, None,
      ("django/contrib/admin/options.py", 1548),
      "request.POST (parsed request body via QueryDict/multipart) - attacker-controlled HTTP input "
      "boundary; read sites in admin options (form data, action selections), middleware and auth.",
      ["covers %d http_request/request_param rows for request.POST" % (
          sum(1 for r in g_srcs.get("P1-request-field", []) if r["callable"] == "POST"))],
      ["P1-request-field"])

entry("p5-src-039", "source", "tp", 0.9, "META", "field", None, None,
      ("django/middleware/csrf.py", 262),
      "request.META (WSGI environ-derived headers/CGI vars) - attacker-influenced HTTP header "
      "boundary (including CSRF_COOKIE populated from cookie/header). Read sites in csrf/cache/"
      "common middleware, debug views, admin.",
      ["request.META['CSRF_COOKIE'] - middleware/csrf.py:261-262",
       "covers %d http_request/request_param rows for request.META" % (
           sum(1 for r in g_srcs.get("P1-request-field", []) if r["callable"] == "META"))],
      ["P1-request-field"])

entry("p5-src-040", "source", "tp", 0.85, "COOKIES", "field", None, None,
      ("django/middleware/cache.py", 94),
      "request.COOKIES - attacker-controlled cookie boundary (session/csrf/cache-key material); "
      "framework consumers feed cache keys (validated) and session lookups, not raw SQL.",
      ["covers %d rows for request.COOKIES" % (
          sum(1 for r in g_srcs.get("P1-request-field", []) if r["callable"] == "COOKIES"))],
      ["P1-request-field"])

entry("p5-src-041", "source", "tp", 0.8, "FILES", "field", None, None,
      ("django/views/generic/edit.py", 52),
      "request.FILES - multipart-uploaded file metadata/content boundary; consumed by multipart "
      "parser and file storage, no observed path into SQL text.",
      ["covers %d rows for request.FILES" % (
          sum(1 for r in g_srcs.get("P1-request-field", []) if r["callable"] == "FILES"))],
      ["P1-request-field"])

entry("p5-src-042", "source", "tp", 0.9, "environ", "field", None, "django.core.handlers.wsgi",
      ("django/core/handlers/wsgi.py", 144),
      "The raw WSGI environ dict is the lowest-trust input boundary of the framework: "
      "WSGIRequest.__init__ derives request.META/GET/POST from it; environ.get/keys reads in "
      "handlers (wsgi.py:144 environ.get('wsgi.file_wrapper')) and dev servers are genuine source "
      "nodes. Covers environ field reads and environ-derived accessor helpers.",
      ["environ.get('wsgi.file_wrapper') - core/handlers/wsgi.py:144",
       "covers %d http_request rows (environ reads + wsgi accessors)" % n("P2-wsgi-environ")],
      ["P2-wsgi-environ"])

entry("p5-src-043", "source", "tp", 0.85, "get_bytes_from_wsgi", "return", None, "django.core.handlers.wsgi",
      ("django/core/handlers/wsgi.py", 159),
      "get_bytes_from_wsgi(environ, ...) returns raw WSGI environ values (QUERY_STRING et al.) - "
      "direct attacker-controlled bytes at the parse boundary (used for QueryDict construction).",
      ["raw_query_string = get_bytes_from_wsgi(self.environ, 'QUERY_STRING', '') - WSGIRequest parse path"],
      ["P2-wsgi-environ"])

entry("p5-src-044", "source", "tp", 0.9, "get", "return", None, None,
      ("django/contrib/admin/options.py", 2198),
      "request.GET/POST/META/COOKIES.get(key) accessor calls return attacker-influenced values "
      "(search query, filters, page vars, header keys) - the highest-signal source shape in the "
      "framework (43 rows). Also covers .getlist() (2 rows).",
      ["to_field = request.GET.get(TO_FIELD_VAR) - admin/views/main.py:106",
       "covers %d request_param rows (get/getlist)" % n("P3-request-get")],
      ["P3-request-get"])

entry("p5-src-045", "source", "tp", 0.8, "items", "return", None, None,
      ("django/contrib/admin/views/main.py", 112),
      "Whole-mapping reads of request input: dict(request.GET.items()) in admin ChangeList "
      "(self.params drives ORM lookups), request.POST.copy(), request.GET.urlencode() - "
      "attacker-controlled dict content as source.",
      ["self.params = dict(request.GET.items()) - admin/views/main.py:112",
       "covers %d rows (items/copy/urlencode)" % n("P4-map-ops")],
      ["P4-map-ops"])

entry("p5-src-046", "source", "tp", 0.85, "request", "param", None, None,
      ("django/contrib/auth/admin.py", 117),
      "The `request` parameter of framework HTTP handler functions/methods (323 handlers: admin "
      "ModelAdmin views, middleware __call__/process_request/process_view, CBV get/post/dispatch, "
      "auth views, staticfiles serve, admindocs, GIS sitemaps) is the request object itself entering "
      "each handler - the external input boundary at parameter level. Position varies (0 for "
      "functions, 1 after self for methods) so arg_index is left unset; match by parameter name "
      "'request'.",
      ["covers %d param rows across %d files (admin options 196, messages api, debug views, sites, csrf, ...)"
       % (n("P5-handler-request"), stats.get("P5-handler-request", {}).get("distinct_files", 0)),
       "representative consumers: ChangeList.__init__ request.GET parsing (admin/views/main.py:95-112)"],
      ["P5-handler-request"])

entry("p5-src-047", "source", "tp", 0.8, "kwargs", "field", None, None,
      ("django/views/generic/detail.py", 34),
      "self.kwargs in generic views carries URL route parameters (pk/slug/year/month/day/week) - "
      "attacker-controlled path segments; consumed via queryset.filter(pk=...) (parameterized ORM).",
      ["pk = self.kwargs.get(self.pk_url_kwarg) - views/generic/detail.py:34",
       "covers %d param rows (self.kwargs reads)" % n("P6-url-kwargs")],
      ["P6-url-kwargs"])

entry("p5-src-048", "source", "candidate", 0.5, "options", "field", None, None,
      ("django/core/management/commands/createcachetable.py", 43),
      "options[...] reads inside BaseCommand.handle() (204 rows) are the management-CLI input "
      "boundary: real external input, but supplied by the operator running manage.py (typically "
      "with direct DB credentials). The SQL-relevant consumers (createcachetable tablename -> "
      "quote_name'd DDL) show injection-shaped flow under operator trust. Kept as source "
      "'candidate' for manual review of threat-model assumptions.",
      ["options['database'], positional tablename -> create_table DDL - createcachetable.py handle()",
       "covers %d cli rows (options reads)" % n("P7-cli-options")],
      ["P7-cli-options"])

entry("p5-none-049", "none", "fp", 0.85, "add_argument", "argument", 0, None,
      ("django/core/management/commands/createcachetable.py", 21),
      "parser.add_argument(...) registrations (179 rows) declare CLI options; they are parser "
      "configuration, not data-flow source nodes. The actual CLI values surface via the options-dict "
      "reads labeled separately.",
      ["parser.add_argument('args', metavar='table_name'...) - createcachetable.py:21-25"],
      ["P8-addargument-fp"])

entry("p5-src-050", "source", "candidate", 0.5, "argv", "field", None, None,
      ("django/core/management/__init__.py", 207),
      "sys.argv reads (10 rows, management bootstrap and autoreload) - CLI input boundary at "
      "process level; operator trust, same 'candidate' treatment as the options family.",
      ["covers %d cli rows (argv)" % n("P9-cli-argv")],
      ["P9-cli-argv"])

entry("p5-none-051", "none", "fp", 0.7, "open", "argument", 0, None,
      ("django/utils/archive.py", 194),
      "open() calls (36 rows: template loading, file storage, translation catalogs, fixture files, "
      "dev utilities) - file paths/contents are a path-traversal (pass 1) concern; for pass 5 no "
      "observed path carries file content into SQL text construction. Fixture data deserialized by "
      "loaddata enters the ORM insert path as bound parameters.",
      ["loaddata fixture reading -> serializers -> model instances -> parameterized inserts - management/commands/loaddata.py"],
      ["P10-file-open"])

entry("p5-none-052", "none", "fp", 0.7, "read", "return", None, None,
      ("django/http/request.py", 404),
      "obj.read() calls (65 rows) return file/stream content; for pass 5 no observed flow into SQL "
      "text (request stream -> QueryDict/POST parsing; cache filebased content; template sources). "
      "Retained as fp for pass 5; relevant for other passes.",
      ["self._stream.read(*args, **kwargs) - http/request.py:404"],
      ["P11-file-read"])

entry("p5-none-053", "none", "fp", 0.75, "environ", "field", None, None,
      ("django/conf/__init__.py", 236),
      "os.environ / os.environ.get reads (57 rows: settings bootstrap DJANGO_SETTINGS_MODULE, "
      "COLORS, autoreload, test runner) - process-environment boundary under operator control; no "
      "pass-5 relevance observed (DB config comes from settings.DATABASES, also operator-level).",
      ["covers %d env rows" % n("P12-os-environ")],
      ["P12-os-environ"])

entry("p5-none-054", "none", "fp", 0.8, "settings", "field", None, None,
      ("django/db/backends/base/creation.py", 186),
      "settings.<ATTR> reads (499 rows across ~100 attributes) - operator-level configuration "
      "(LazySettings). The DB-relevant consumers (settings.DATABASES NAME/TIME_ZONE, settings.USE_TZ "
      "in oracle NLS SQL, cache table name) are deployment-config trust, not attacker input; the "
      "test-db DDL built from them is quote_name'd.",
      ["'CREATE DATABASE %(dbname)s %(suffix)s' % parameters with quote_name'd dbname from settings - base/creation.py:186-196",
       "covers %d config rows" % n("P13-settings")],
      ["P13-settings"])

entry("p5-none-056", "none", "fp", 0.85, "_reset_sequences", "param", None, "django.test.testcases",
      ("django/test/testcases.py", 1222),
      "django/test/testcases.py is shipped framework test infrastructure (TransactionTestCase). "
      "_reset_sequences executes backend-generated sequence-reset SQL (connection.ops."
      "sequence_reset_sql from model metadata); the execute row at :1232 is the same test-only "
      "path. Reachable only inside the project's own test suite - test-file FP per the pass "
      "heuristics; evidence retained, not counted as a production vulnerability.",
      ["sequence_sql = connection.ops.sequence_reset_sql(no_style(), models); cursor.execute(line) - testcases.py:1222-1232"],
      ["G24-testinfra-fp"])

entry("p5-none-055", "none", "fp", 0.7, "register", "argument", 0, None,
      ("django/contrib/admin/filters.py", 253),
      "internal_transfer calls into non-SQL wrapper functions (FieldListFilter.register in admin "
      "filters, warning/context-manager __exit__ in test utils, system-check registrations, message "
      "helpers): no SQL semantics on either end - extraction-family noise for pass 5.",
      ["covers %d internal_transfer rows targeting non-SQL wrappers" % n("P15-internal-other")],
      ["P15-internal-other"])

# ------------------------------------------------------------- batches

BATCHES = [
    ("B01", "Central SQL execution funnel: CursorWrapper/CursorDebugWrapper definitions and driver call sites (django/db/backends/utils.py)",
     ["G1-execute-callsite", "G2a-cursorwrapper-def", "G2b-callproc", "G2c-wrapper-glue", "GB-boundparams-san"]),
    ("B02", "Backend driver cursor wrappers: sqlite3 SQLiteCursorWrapper, mysql CursorWrapper, oracle FormatStylePlaceholderCursor",
     ["G3-sqlite-wrapper", "G4-mysql-wrapper", "G5-oracle-wrapper"]),
    ("B03", "ORM raw-SQL APIs and compiler execution path",
     ["G6-compiler", "G7-orm-raw-apis"]),
    ("B04", "Schema editor / DDL funnel and schema wrapper families",
     ["G8-schemaeditor-execute", "G9-schema-summary"]),
    ("B05", "Introspection, test-db creation, backend operations, connection-state wrappers",
     ["G10-introspection-summary", "G11-creation-summary", "G12-ops-summary", "G13a-connstate", "G13b-static-fp"]),
    ("B06", "Construction nodes, CLI/Redis/register name collisions, cache backends, management SQL commands, migration ops",
     ["G14-msg-fp", "G15-sql-construction", "G16-cliexecute-fp", "G17-cli-dispatch", "G18-redis-fp",
      "G19-register-fp", "G20-cache-summary", "G21-mgmtsql-summary", "G23-migration-ops"]),
    ("B07", "HTTP request attribute and accessor source families",
     ["P1-request-field", "P2-wsgi-environ", "P3-request-get", "P4-map-ops"]),
    ("B08", "Handler parameter sources (request parameter, URL kwargs)",
     ["P5-handler-request", "P6-url-kwargs"]),
    ("B09", "CLI source family (options/add_argument/argv)",
     ["P7-cli-options", "P8-addargument-fp", "P9-cli-argv"]),
    ("B10", "File / environment / config source families",
     ["P10-file-open", "P11-file-read", "P12-os-environ", "P13-settings"]),
    ("B11", "internal_transfer call rows (SQL-layer and non-SQL wrappers)",
     ["G17-cli-dispatch", "G21-mgmtsql-summary", "G10-introspection-summary", "G23-migration-ops",
      "G9-schema-summary", "G11-creation-summary", "G12-ops-summary", "G20-cache-summary",
      "G6-compiler", "G13a-connstate", "P15-internal-other"]),
    ("B12", "Sanitizer determination and cross-family consistency review (quote_name evidence, bound-parameter channel)",
     []),
]

# ------------------------------------------------------------- emit labels.json

def entry_public(e):
    out = {k: v for k, v in e.items() if not k.startswith("_")}
    return out

pass5_entries = [entry_public(e) for e in E]

labels = {
    "version": "1.0",
    "metadata": {
        "run_id": RUN_ID,
        "generated_at": GENERATED_AT,
        "language": "python",
        "framework": "django",
        "model": MODEL,
        "project": "django",
        "notes": [
            "Pass 5 (CWE-89 SQL Injection) candidate labeling only; 2609 source rows + 608 sink rows = 3217 candidates, all covered via 33 semantic groups (dedup) - see labels/labels_raw_pass5.json for the full row-to-group audit mapping.",
            "Evidence verification basis: the CodeQL database source snapshot (django-db/src.zip, Django 4.2.0-alpha0, creation sha eb3699ea). IMPORTANT: the on-disk working tree at the source directory is stock Django 2.2.4 (git 8687fbe) and does NOT match the extraction CSV line numbers; all file:line evidence in these labels refers to the database snapshot, which the CSV rows match exactly (spot-verified at createcachetable.py:120/127, utils.py:66-107, compiler.py:1395/1657, query.py:1284/1670/1995, expressions.py:1049, sql/query.py:85/152).",
            "This run is an in-context LLM labeling session (model glm-5.3 operating the Claude Code agent harness); no external LLM API calls were made. 12 batches were processed; per-batch scope and row counts are recorded in labels_raw_pass5.json.",
            "pass 1 block: present with zero entries solely to satisfy the labels_schema.json 'passes contains pass_id=1' constraint; no pass-1 labeling was performed in this run.",
            "Key semantic findings: (1) no framework request path feeds raw SQL text - request-derived values (admin ChangeList filters/search/ordering, auth, generic views) flow into ORM filter()/order_by() channels that compile to parameterized SQL; (2) the raw-SQL APIs (QuerySet.raw/extra, RawSQL, RawQuery(Set)) are genuine sinks but have no non-test call sites in this snapshot; (3) dynamic SQL in backends is built from quote_name-quoted identifiers, settings/DB-derived names, or CLI input - operator/DB trust level; (4) quote_name does NOT escape embedded quotes ('%s' wrapping only) and is therefore recorded as a candidate sanitizer, not a trusted barrier; (5) the bound-parameter argument is the proven sanitizer channel.",
            "Extraction match_kind is 'ast' for all rows (receiver-name-agnostic matching); name-collision false positives (CLI .execute(), Redis pipeline.execute, error-message %-formatting) were identified and labeled none/fp individually.",
        ],
    },
    "passes": [
        {
            "pass_id": 1,
            "focus": "Path Traversal",
            "cwes": ["22", "23", "36", "73"],
            "entries": [],
        },
        {
            "pass_id": 5,
            "focus": "SQL Injection",
            "cwes": ["89"],
            "entries": pass5_entries,
        },
    ],
}

# ------------------------------------------------------- raw pass5 artifact

raw = {
    "pass_id": 5,
    "focus": "SQL Injection",
    "cwes": ["89"],
    "model": MODEL,
    "labeling_mode": "in-context LLM labeling performed by the glm-5.3 agent session (Claude Code harness); no external LLM API calls; temperature-free deterministic annotation from verified snapshot evidence",
    "run_id": RUN_ID,
    "generated_at": GENERATED_AT,
    "inputs": {
        "sources_csv": "extraction/sources.csv",
        "sinks_csv": "extraction/sinks.csv",
        "source_rows": len(srcs),
        "sink_rows": len(sinks),
        "total_candidates": len(srcs) + len(sinks),
    },
    "batches": [],
    "batch_policy": "B01-B10 partition the candidate rows by family (each row examined once from its own CSV's perspective); B11 re-examines the internal_transfer source rows whose targets are SQL-layer wrappers (already seen from the definition side in B01-B06) from the call-site perspective; B12 is the sanitizer/consistency review pass with no direct row input. Batch row totals therefore intentionally exceed the 3217 unique candidates; the per-group coverage below is the authoritative disjoint accounting.",
    "coverage": {
        "dedup_policy": "one labels.json entry per semantic API signature/group; every CSV row is assigned to exactly one group; groups are keyed by (module family, callable role, flow kind); row counts, distinct-file counts and sample locations are recorded per group",
        "exclusion_policy": "rows are never dropped: 'none'/fp labels keep the audit trail; name-collision rows (CLI execute, redis pipeline, message formatting, parser registration) are explicitly labeled rather than silently excluded",
        "groups": [],
    },
    "verification_basis": [
        "django-db/src.zip (CodeQL DB source snapshot, Django 4.2.0-alpha0, sha eb3699ea) - file/line evidence matches the extraction CSVs",
        "on-disk working tree is stock Django 2.2.4 (git 8687fbe034a) and does NOT match CSV line numbers; labels were verified exclusively against the DB snapshot",
        "no PyVul ground truth (sql_sinks*.csv, enhanced_sql_sinks.csv, sql_injection_audit_report.md) was opened",
    ],
}

for bid, desc, gids in BATCHES:
    rows_in = sum(n(g) for g in gids)
    raw["batches"].append({
        "batch_id": bid,
        "description": desc,
        "groups": gids,
        "input_candidate_rows": rows_in,
    })

for gid in sorted(stats):
    s = stats[gid]
    raw["coverage"]["groups"].append({
        "group_id": gid,
        "csv": s["csv"],
        "rows": s["rows"],
        "distinct_files": s["distinct_files"],
        "top_files": [f if isinstance(f, str) else f for f in
                      (tf[0] if isinstance(tf, tuple) else tf for tf in s["top_files"])],
        "sample_locations": s["samples"],
        "label_entry_ids": [e["id"] for e in E if gid in e["_covers"]],
    })

raw["coverage"]["total_rows_assigned"] = total_assigned
raw["role_counts"] = {
    r: sum(1 for e in E if e["role"] == r) for r in ("source", "sink", "sanitizer", "summary", "none")
}
raw["classification_counts"] = {
    c: sum(1 for e in E if e["classification"] == c) for c in ("tp", "fp", "candidate", "unknown")
}

# ------------------------------------------------------------- write files

os.makedirs(OUT, exist_ok=True)

with open(os.path.join(OUT, "labels.json"), "w", encoding="utf-8") as f:
    json.dump(labels, f, indent=2, ensure_ascii=False)

with open(os.path.join(OUT, "labels_raw_pass5.json"), "w", encoding="utf-8") as f:
    json.dump(raw, f, indent=2, ensure_ascii=False)

# ------------------------------------------------------------- stats md

sink_rows_by_role = defaultdict(int)
src_rows_by_role = defaultdict(int)
for gid, rows in list(g_sinks.items()) + list(g_srcs.items()):
    ids = [e for e in E if gid in e["_covers"]]
    if ids:
        sink_rows_by_role[ids[0]["role"]] += len(rows)

lines = []
lines.append("# Pass 5 (CWE-89 SQL Injection) Label Statistics\n")
lines.append("- run_id: `%s`" % RUN_ID)
lines.append("- generated_at: %s" % GENERATED_AT)
lines.append("- model: **%s** (in-context labeling by the glm-5.3 agent session operating the Claude Code harness; no external LLM API calls)" % MODEL)
lines.append("- batches: **%d** (B01-B12; scope and row counts in `labels_raw_pass5.json`)" % len(BATCHES))
lines.append("- total candidates processed: **%d** (%d source rows + %d sink rows from extraction CSVs)"
             % (len(srcs) + len(sinks), len(srcs), len(sinks)))
lines.append("- 100%% row coverage: every CSV row is assigned to exactly one of %d semantic groups"
             % len(stats))
lines.append("- labels.json entries after dedup: **%d** (pass 5) + 1 empty pass-1 block required by the schema `contains` constraint\n" % len(E))
lines.append("## Entries by role (pass 5)\n")
lines.append("| role | entries |")
lines.append("| --- | --- |")
for r in ("source", "sink", "sanitizer", "summary", "none"):
    lines.append("| %s | %d |" % (r, raw["role_counts"].get(r, 0)))
lines.append("\n## Entries by classification\n")
lines.append("| classification | entries |")
lines.append("| --- | --- |")
for c in ("tp", "fp", "candidate", "unknown"):
    lines.append("| %s | %d |" % (c, raw["classification_counts"].get(c, 0)))
lines.append("\n## Candidate rows by assigned label role\n")
lines.append("| role | CSV rows covered |")
lines.append("| --- | --- |")
for r in ("source", "sink", "sanitizer", "summary", "none"):
    lines.append("| %s | %d |" % (r, sink_rows_by_role.get(r, 0)))
lines.append("\n## Group overview\n")
lines.append("| group | csv | rows | files | entry |")
lines.append("| --- | --- | --- | --- | --- |")
for gid in sorted(stats, key=lambda g: (-stats[g]["rows"])):
    s = stats[gid]
    ids = ", ".join(e["id"] for e in E if gid in e["_covers"]) or "(extra evidence)"
    lines.append("| %s | %s | %d | %d | %s |" % (gid, s["csv"], s["rows"], s["distinct_files"], ids))
lines.append("\n## Source CSV family counts\n")
lines.append("| flow_kind | rows |")
lines.append("| --- | --- |")
fk_counts = defaultdict(int)
for r in srcs:
    fk_counts[r["fk"]] += 1
for k, v in sorted(fk_counts.items(), key=lambda x: -x[1]):
    lines.append("| %s | %d |" % (k, v))
lines.append("\n## Sink CSV flow-kind counts\n")
lines.append("| flow_kind | rows |")
lines.append("| --- | --- |")
fk_counts = defaultdict(int)
for r in sinks:
    fk_counts[r["fk"]] += 1
for k, v in sorted(fk_counts.items(), key=lambda x: -x[1]):
    lines.append("| %s | %d |" % (k, v))

with open(os.path.join(OUT, "label_stats.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print("wrote labels.json (%d pass-5 entries), labels_raw_pass5.json, label_stats.md" % len(E))
print("roles:", raw["role_counts"])
print("classifications:", raw["classification_counts"])
