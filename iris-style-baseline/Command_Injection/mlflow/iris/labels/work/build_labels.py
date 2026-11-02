"""Build labels.json for mlflow pass 2 (CWE-78) from extraction CSVs.

Every classification rule below was derived from manual review of the
mlflow_vuln source tree (MLflow 2.5.1.dev0, sha 330bf0b). The script only
formats the decisions; it does not invent sites. Sites are deduplicated by
(file, line) merging api/ast and Attribute/Attribute() duplicate rows.

Conventions (documented in labels.json metadata notes):
- arg_index is 0-based, following this run's extraction columnContract
  ("arg_index (0-based positional argument index, -1 when not applicable");
  for method wrappers the index excludes self/cls.
- classification=tp means "genuine source/sink/sanitizer API for CWE-78",
  NOT a final vulnerability ground-truth TP.
"""

import csv
import json
import os
import re
from collections import OrderedDict

IRIS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_ROOT = r"C:\Users\lzh\Desktop\github\PyVul-main\dataset\codeql_databases\mlflow_vuln"
PREFIX = "C:/Users/lzh/Desktop/github/PyVul-main/dataset/codeql_databases/mlflow_vuln/"

CALL_FORMS = {"get", "get_json", "to_dict", "loads", "load", "safe_load", "pop", "getenv",
              "read", "decode"}
DECORATORS = {"command", "option", "group", "argument", "version_option"}

FLAVOR_PREFIXES = (
    "mlflow/fastai/", "mlflow/paddle/", "mlflow/openai/", "mlflow/xgboost/",
    "mlflow/tensorflow/", "mlflow/pytorch/", "mlflow/sklearn/", "mlflow/gluon/",
    "mlflow/pyspark/", "mlflow/langchain/", "mlflow/pyfunc/", "mlflow/mleap/",
)
FLAVOR_FILES = (
    "mlflow/h2o.py", "mlflow/lightgbm.py", "mlflow/onnx.py", "mlflow/pmdarima.py",
    "mlflow/prophet.py", "mlflow/shap.py", "mlflow/spacy.py", "mlflow/statsmodels.py",
    "mlflow/diviner.py", "mlflow/johnsnowlabs.py", "mlflow/transformers.py",
    "mlflow/catboost.py", "mlflow/spark.py",
)

REMOTE_PREFIXES = (
    "mlflow/store/", "mlflow/tracking/", "mlflow/data/",
)
REMOTE_FILES = (
    "mlflow/gateway/client.py", "mlflow/gateway/utils.py", "mlflow/utils/rest_utils.py",
    "mlflow/sagemaker/__init__.py", "mlflow/openai/utils.py", "mlflow/types/schema.py",
    "mlflow/utils/search_utils.py", "mlflow/utils/proto_json_utils.py",
    "mlflow/pyfunc/stdin_server.py", "mlflow/utils/download_cloud_file_chunk.py",
)

INTERNAL_PREFIXES = ("mlflow/recipes/", "mlflow/models/evaluation/")
INTERNAL_FILES = (
    "mlflow/utils/file_utils.py", "mlflow/utils/_capture_modules.py",
    "mlflow/utils/_capture_transformers_modules.py", "mlflow/utils/model_utils.py",
    "mlflow/utils/request_utils.py",
)

# ---------------------------------------------------------------------------
# Sink site table: (file, line) -> verdict
# role, classification, confidence, flow_kind, arg_index, rationale, evidence
# S = sink, M = summary (wrapper), N = none (rejected)
# ---------------------------------------------------------------------------
SINK_TABLE = {
    # --- mlflow/utils/process.py: the central command wrapper ---
    ("mlflow/utils/process.py", 31): ("summary", "tp", 0.95, "param", 0,
        "Central command-execution wrapper: _exec_cmd(cmd, **kwargs) forwards its cmd argument (string or argv list) directly to subprocess.Popen (process.py:95); callers include conda.py, environment.py, virtualenv.py and projects/docker.py, and virtualenv.py:137 forwards shell=not _IS_UNIX through **kwargs, so string commands can reach a real shell.",
        ["mlflow/utils/process.py:95 'process = subprocess.Popen(cmd, env=env, text=True, **kwargs)'",
         "mlflow/utils/virtualenv.py:133-137 '_exec_cmd([...], shell=not _IS_UNIX)' (Windows shell=True)",
         "callers: mlflow/utils/conda.py:125/140, mlflow/utils/environment.py:615, mlflow/utils/virtualenv.py:101/143, mlflow/projects/docker.py:38"]),
    ("mlflow/utils/process.py", 62): ("none", "fp", 0.95, "unknown", None,
        "f-string is a ValueError message ('`kwargs` cannot contain ...'), not a command string; no OS command execution at this site.",
        ["mlflow/utils/process.py:62 'raise ValueError(f\"`kwargs` cannot contain {list(illegal_kwargs)}\")'"]),
    ("mlflow/utils/process.py", 95): ("sink", "tp", 0.95, "argument", 0,
        "Primary subprocess sink: Popen(cmd, env=env, text=True, **kwargs) with cmd as argument 0; cmd may be a plain string (shell interpretation possible when shell=True is forwarded via **kwargs from virtualenv.py:137) or an argv list built by callers from model/project artifacts.",
        ["mlflow/utils/process.py:95-100 'process = subprocess.Popen(cmd, env=env, text=True, **kwargs)'",
         "shell is not fixed here: virtualenv.py:137 passes shell=not _IS_UNIX"]),
    ("mlflow/utils/process.py", 121): ("summary", "tp", 0.8, "param", 0,
        "Command-joining wrapper: _join_commands(*commands) joins command strings with ' && '/' & ' and wraps them in ['bash','-c', ...] / ['cmd','/c', ...]; the returned argv list is executed by callers via Popen.",
        ["mlflow/utils/process.py:121-124 'entry_point = [\"bash\", \"-c\"] if _IS_UNIX else [\"cmd\", \"/c\"]; return [*entry_point, sep.join(map(str, commands))]'"]),
    ("mlflow/utils/process.py", 122): ("summary", "tp", 0.75, "unknown", None,
        "Construction of the shell argv list ['bash','-c', joined_commands] inside _join_commands; the command strings originate from caller arguments (model serving commands) and are executed unescaped at the caller's Popen site.",
        ["mlflow/utils/process.py:122-124 (return value of _join_commands)"]),

    # --- mlflow/sagemaker/__init__.py ---
    ("mlflow/sagemaker/__init__.py", 110): ("summary", "tp", 0.85, "param", 0,
        "push_image_to_ecr(image) interpolates its image parameter (plus AWS account/region) into a ';'/&&-joined docker login/tag/push command string that is executed by os.system at line 158.",
        ["mlflow/sagemaker/__init__.py:126 '_full_template.format(account=..., image=image, ...)'",
         "mlflow/sagemaker/__init__.py:152-155 docker tag/push f-strings joined with os_command_separator",
         "mlflow/sagemaker/__init__.py:158 'os.system(cmd)'"]),
    ("mlflow/sagemaker/__init__.py", 126): ("none", "fp", 0.9, "unknown", None,
        "str.format on the _full_template ECR repository-name template: command-string construction only, no execution here; the result flows into the os.system sink at sagemaker/__init__.py:158.",
        ["mlflow/sagemaker/__init__.py:126-128"]),
    ("mlflow/sagemaker/__init__.py", 142): ("none", "fp", 0.9, "unknown", None,
        "f-string builds the 'aws ecr get-login-password | docker login ...' command fragment; construction only, executed later via os.system at line 158.",
        ["mlflow/sagemaker/__init__.py:141-146"]),
    ("mlflow/sagemaker/__init__.py", 152): ("none", "fp", 0.9, "unknown", None,
        "f-string 'docker tag {image} {fullname}' command fragment; construction only, executed via os.system at line 158.",
        ["mlflow/sagemaker/__init__.py:152"]),
    ("mlflow/sagemaker/__init__.py", 153): ("none", "fp", 0.9, "unknown", None,
        "f-string 'docker push {fullname}' command fragment; construction only, executed via os.system at line 158.",
        ["mlflow/sagemaker/__init__.py:153"]),
    ("mlflow/sagemaker/__init__.py", 158): ("sink", "tp", 0.95, "argument", 0,
        "Confirmed OS command execution sink: os.system(cmd) with a single string command assembled from docker login/tag/push fragments joined by ';'/'&&'; the shell parses the whole string, and image (function parameter, caller/deployment-config supplied) and AWS account/region are interpolated without quoting.",
        ["mlflow/sagemaker/__init__.py:148-158 'cmd = os_command_separator.join([docker_login_cmd, docker_tag_cmd, docker_push_cmd])' then 'os.system(cmd)'"]),
    ("mlflow/sagemaker/__init__.py", 1048): ("summary", "candidate", 0.6, "param", 1,
        "run_local(name, model_uri, ...) builds an argv list ['docker','run','-v',f'{model_path}:/opt/ml/model/','-p',...] with -e entries from the deployment config (which includes http_proxy env values) and the caller-supplied image name; executed by Popen at line 1132 without a shell, so only argument-level (not shell) injection is possible.",
        ["mlflow/sagemaker/__init__.py:1127-1132 cmd construction and 'Popen(cmd, stdout=sys.stdout, ...)'",
         "mlflow/sagemaker/__init__.py:1314-1321 proxy env values flow into deployment_config -> '-e' argv entries"]),
    ("mlflow/sagemaker/__init__.py", 1127): ("none", "fp", 0.85, "unknown", None,
        "argv-list element construction (docker run -v/-p flags); no shell involved at the consuming Popen (line 1132), so this is not a shell command string sink.",
        ["mlflow/sagemaker/__init__.py:1127"]),
    ("mlflow/sagemaker/__init__.py", 1129): ("none", "fp", 0.85, "unknown", None,
        "argv-list element construction (-e KEY=VALUE env entries); no shell at the consuming Popen (line 1132).",
        ["mlflow/sagemaker/__init__.py:1128-1129"]),
    ("mlflow/sagemaker/__init__.py", 1132): ("sink", "candidate", 0.6, "argument", 0,
        "Popen(cmd) with a fixed-program argv list ('docker','run',...) and no shell: shell metacharacters in model_path/image/config values cannot inject commands here; only argument injection into docker itself is conceivable, hence candidate rather than tp.",
        ["mlflow/sagemaker/__init__.py:1132 'proc = Popen(cmd, stdout=sys.stdout, stderr=sys.stderr, text=True)'"]),

    # --- mlflow/models/container/__init__.py (container serving entrypoint) ---
    ("mlflow/models/container/__init__.py", 87): ("summary", "tp", 0.85, "param", 0,
        "Container dependency installer: _install_pyfunc_deps(model_path, ...) copies the model's conda env file (path taken from MLmodel flavor config) and runs it through Popen(['bash','-c', conda_create_model_env]) at line 114 and joined activate/install commands at lines 130/139.",
        ["mlflow/models/container/__init__.py:97-98 'model = Model.load(model_config_path)' (untrusted MLmodel)",
         "mlflow/models/container/__init__.py:111 'shutil.copyfile(os.path.join(MODEL_PATH, env), env_path_dst)' (env file name from model config)"]),
    ("mlflow/models/container/__init__.py", 113): ("none", "fp", 0.85, "unknown", None,
        "f-string 'conda env create -n custom_env -f {env_path_dst}' is command construction; execution happens at the bash -c Popen on line 114.",
        ["mlflow/models/container/__init__.py:113-114"]),
    ("mlflow/models/container/__init__.py", 114): ("sink", "tp", 0.9, "argument", 2,
        "Confirmed shell sink: Popen(['bash','-c', conda_create_model_env]) - argument 2 is a shell command string whose env file path is derived from the untrusted model artifact's MLmodel/conda.yaml metadata (env file name), interpolated unescaped.",
        ["mlflow/models/container/__init__.py:113-114 'conda_create_model_env = f\"conda env create -n custom_env -f {env_path_dst}\"; Popen([\"bash\", \"-c\", conda_create_model_env])'"]),
    ("mlflow/models/container/__init__.py", 129): ("none", "fp", 0.85, "unknown", None,
        "f-string 'pip install ...' fragment; construction only, executed via bash -c Popen at line 130.",
        ["mlflow/models/container/__init__.py:129-130"]),
    ("mlflow/models/container/__init__.py", 130): ("sink", "tp", 0.85, "argument", 2,
        "Shell sink: Popen(['bash','-c', ' && '.join(activate_cmd + install_server_deps)]) - argument 2 is a joined shell command whose activate_cmd part is the virtualenv activation path returned by _get_or_create_virtualenv(model_path) (model-derived path), unescaped.",
        ["mlflow/models/container/__init__.py:117-130"]),
    ("mlflow/models/container/__init__.py", 137): ("none", "fp", 0.85, "unknown", None,
        "f-string 'pip install mlflow=={MLFLOW_VERSION}' fragment; construction only, executed via bash -c Popen at line 139.",
        ["mlflow/models/container/__init__.py:134-139"]),
    ("mlflow/models/container/__init__.py", 139): ("sink", "tp", 0.8, "argument", 2,
        "Shell sink: Popen(['bash','-c', ' && '.join(activate_cmd + install_mlflow_cmd)]) - argument 2 joins the model-derived virtualenv activation command with a pip install command; the pip fragment itself is fixed (mlflow version literal).",
        ["mlflow/models/container/__init__.py:133-139"]),
    ("mlflow/models/container/__init__.py", 144): ("summary", "tp", 0.9, "param", 0,
        "Container pyfunc serving dispatcher: _serve_pyfunc(model, env_manager) obtains the scoring server command via inference_server.get_cmd(model_uri=MODEL_PATH, ...) (scoring_server/__init__.py:326-363, f-string gunicorn/waitress-serve command) and executes it through Popen(['/bin/bash','-c',' && '.join(bash_cmds)]) at line 203.",
        ["mlflow/models/container/__init__.py:200-203 'cmd, cmd_env = inference_server.get_cmd(...); bash_cmds.append(cmd); Popen([\"/bin/bash\", \"-c\", \" && \".join(bash_cmds)], env=cmd_env)'",
         "mlflow/pyfunc/scoring_server/__init__.py:343-346 gunicorn command f-string"]),
    ("mlflow/models/container/__init__.py", 175): ("sink", "fp", 0.85, "argument", 0,
        "Popen(['nginx','-c', nginx_conf]) with an argv list and no shell; nginx_conf comes from pkg_resources.resource_filename (mlflow's own packaged nginx.conf), i.e. fixed - not attacker-influenced.",
        ["mlflow/models/container/__init__.py:171-175"]),
    ("mlflow/models/container/__init__.py", 180): ("sink", "fp", 0.9, "argument", 0,
        "check_call(['ln','-sf','/dev/stdout',...]) - completely fixed argv literals, no shell, no dynamic data.",
        ["mlflow/models/container/__init__.py:180"]),
    ("mlflow/models/container/__init__.py", 181): ("sink", "fp", 0.9, "argument", 0,
        "check_call(['ln','-sf','/dev/stderr',...]) - completely fixed argv literals, no shell, no dynamic data.",
        ["mlflow/models/container/__init__.py:181"]),
    ("mlflow/models/container/__init__.py", 203): ("sink", "tp", 0.95, "argument", 2,
        "Confirmed shell sink: Popen(['/bin/bash','-c',' && '.join(bash_cmds)]) - argument 2 is the joined shell script containing the inference server command returned by scoring_server.get_cmd (f-string with model path, host/port/timeout options) plus env activation commands; model/deployment-derived values are interpolated unescaped.",
        ["mlflow/models/container/__init__.py:200-203",
         "mlflow/pyfunc/scoring_server/__init__.py:343-358 command f-strings (gunicorn / waitress-serve)"]),
    ("mlflow/models/container/__init__.py", 212): ("summary", "tp", 0.7, "field", None,
        "MLeap serving wrapper: _serve_mleap() joins fixed literals (java -cp '/opt/java/jars/*' ... MODEL_PATH) into a single string and executes it with Popen(shell=True) at line 224; all components are constants.",
        ["mlflow/models/container/__init__.py:212-224"]),
    ("mlflow/models/container/__init__.py", 224): ("sink", "fp", 0.8, "argument", 0,
        "Popen(serve_cmd, shell=True) executes a string through the shell, but serve_cmd is assembled entirely from fixed literals (java, jar path constant '/opt/java/jars/*', org.mlflow.sagemaker.ScoringServer, MODEL_PATH='/opt/ml/model', fixed port); no attacker-influenced component.",
        ["mlflow/models/container/__init__.py:213-224"]),

    # --- mlflow/pyfunc/backend.py ---
    ("mlflow/pyfunc/backend.py", 163): ("summary", "tp", 0.9, "param", 0,
        "PyFuncBackend.serve(model_uri, port, host, ...) downloads the model artifact, obtains the scoring server command string from server_implementation.get_cmd(local_path, port, host, ...) and either executes it via Environment.execute (bash -c/cmd /c, environment.py:611-613) or, for the local env manager, via Popen(['bash','-c', command]) at line 243.",
        ["mlflow/pyfunc/backend.py:177-182 'command, command_env = server_implementation.get_cmd(local_path, port, host, timeout, self._nworkers)'",
         "mlflow/pyfunc/backend.py:226 'command = \"exec \" + command'",
         "mlflow/pyfunc/backend.py:240-243 'command = [\"bash\", \"-c\", command]; child_proc = subprocess.Popen(command, ...)'"]),
    ("mlflow/pyfunc/backend.py", 241): ("sink", "tp", 0.9, "argument", 2,
        "Shell sink (list construction): ['bash','-c', command] where command is the scoring-server command string returned by get_cmd (f-string with model path, host, port, timeout); executed by Popen on line 243. Argument 2 is the unescaped shell command string.",
        ["mlflow/pyfunc/backend.py:240-243",
         "mlflow/pyfunc/scoring_server/__init__.py:343-346"]),
    ("mlflow/pyfunc/backend.py", 243): ("sink", "tp", 0.9, "argument", 0,
        "Shell sink: subprocess.Popen(command) where command is ['bash','-c', <scoring server command string>] (dangerous element index 2) - the command embeds the downloaded model path and serving options without shell escaping.",
        ["mlflow/pyfunc/backend.py:240-249"]),
    ("mlflow/pyfunc/backend.py", 255): ("none", "fp", 0.95, "unknown", None,
        "f-string is an exception message (\"Command '{command}' returned non zero return code\"), not a command; no execution here.",
        ["mlflow/pyfunc/backend.py:253-256"]),
    ("mlflow/pyfunc/backend.py", 276): ("none", "fp", 0.9, "unknown", None,
        "can_score_model() only probes the conda installation with a fixed argv command; no untrusted data reaches execution.",
        ["mlflow/pyfunc/backend.py:280-286"]),
    ("mlflow/pyfunc/backend.py", 282): ("sink", "fp", 0.7, "argument", 0,
        "Popen([conda_path, '--version']) argv list without shell; conda_path derives from MLFLOW_CONDA_HOME/CONDA_EXE environment variables (operator-controlled configuration, not request data) - argument injection would require control of the operator's environment.",
        ["mlflow/pyfunc/backend.py:280-284 'conda_path = get_conda_bin_executable(\"conda\")'",
         "mlflow/utils/conda.py:54-60 conda home from os.environ.get(MLFLOW_CONDA_HOME) / CONDA_EXE"]),

    # --- mlflow/rfunc/backend.py ---
    ("mlflow/rfunc/backend.py", 84): ("none", "fp", 0.9, "unknown", None,
        "RFuncBackend.can_score_model() probes Rscript with a fixed argv command; no untrusted data.",
        ["mlflow/rfunc/backend.py:84-100"]),
    ("mlflow/rfunc/backend.py", 86): ("sink", "fp", 0.9, "argument", 0,
        "Popen(['Rscript','--version']) - fixed argv literals, no shell.",
        ["mlflow/rfunc/backend.py:86-91"]),
    ("mlflow/rfunc/backend.py", 103): ("summary", "tp", 0.85, "param", 0,
        "R execution wrapper: _execute(command) passes its command string as argument 2 of Popen(['Rscript','-e',command]) at line 106; Rscript -e evaluates the string as R code, so this is a code-evaluation channel. The command is built in serve() from quote(model_path), port and host (host/port interpolated unquoted).",
        ["mlflow/rfunc/backend.py:79-82 'command = \"mlflow::mlflow_rfunc_serve('{}', port = {}, host = '{}')\".format(quote(model_path), port, host)'"]),
    ("mlflow/rfunc/backend.py", 106): ("sink", "tp", 0.85, "argument", 2,
        "Code-evaluation sink: Popen(['Rscript','-e',command]) - argument 2 is evaluated as R code; model_path is shell-quoted via mlflow.utils.string_utils.quote but host/port are interpolated raw into the R expression.",
        ["mlflow/rfunc/backend.py:103-115"]),

    # --- dev/ maintenance scripts ---
    ("dev/create_release_branch.py", 17): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling (not shipped product code): subprocess.check_output of fixed git argv commands; --new-version/--remote click options are developer-supplied.",
        ["dev/create_release_branch.py:13-43"]),
    ("dev/create_release_branch.py", 26): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: fixed git argv command, no shell, no product attack surface.",
        ["dev/create_release_branch.py:26"]),
    ("dev/create_release_branch.py", 29): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: fixed git argv command.",
        ["dev/create_release_branch.py:29"]),
    ("dev/create_release_branch.py", 34): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: fixed git argv command.",
        ["dev/create_release_branch.py:34"]),
    ("dev/create_release_branch.py", 37): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: fixed git argv command.",
        ["dev/create_release_branch.py:37"]),
    ("dev/create_release_branch.py", 39): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: fixed git argv command.",
        ["dev/create_release_branch.py:39"]),
    ("dev/create_release_branch.py", 43): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: fixed git argv command.",
        ["dev/create_release_branch.py:43"]),
    ("dev/create_release_tag.py", 42): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: subprocess.run of fixed git argv commands.",
        ["dev/create_release_tag.py:42"]),
    ("dev/create_release_tag.py", 43): ("none", "fp", 0.9, "unknown", None,
        "Developer release tooling: fixed git argv command.",
        ["dev/create_release_tag.py:43"]),
    ("dev/show_package_release_dates.py", 9): ("none", "fp", 0.9, "unknown", None,
        "Developer tooling: subprocess.run of a fixed argv command.",
        ["dev/show_package_release_dates.py:9"]),
    ("dev/update_changelog.py", 77): ("none", "fp", 0.9, "unknown", None,
        "Developer tooling: subprocess.check_output of fixed git argv commands.",
        ["dev/update_changelog.py:77"]),
    ("dev/update_changelog.py", 98): ("none", "fp", 0.9, "unknown", None,
        "Developer tooling: fixed git argv command.",
        ["dev/update_changelog.py:98"]),
    ("dev/update_changelog.py", 100): ("none", "fp", 0.9, "unknown", None,
        "Developer tooling: fixed git argv command.",
        ["dev/update_changelog.py:100"]),
    ("dev/update_changelog.py", 106): ("none", "fp", 0.9, "unknown", None,
        "Developer tooling: fixed git argv command.",
        ["dev/update_changelog.py:106"]),
    ("dev/update_changelog.py", 107): ("none", "fp", 0.9, "unknown", None,
        "Developer tooling: fixed git argv command.",
        ["dev/update_changelog.py:107"]),
    ("dev/update_changelog.py", 108): ("none", "fp", 0.9, "unknown", None,
        "Developer tooling: fixed git argv command.",
        ["dev/update_changelog.py:108"]),

    # --- mlflow/projects/databricks.py ---
    ("mlflow/projects/databricks.py", 343): ("summary", "tp", 0.85, "param", 0,
        "Databricks run command builder: _get_databricks_run_cmd(dbfs_fuse_tar_uri, ...) f-strings a multi-line bash script (export PATH, mkdir, rsync, tar, mv, mlflow run) and returns ['bash','-c', shell_command]; the tar URI/path components derive from the project archive path and the mlflow sub-command quotes its elements via quote().",
        ["mlflow/projects/databricks.py:361 'mlflow_run_cmd = \" \".join([quote(elem) for elem in mlflow_run_arr])'",
         "mlflow/projects/databricks.py:362-379 shell_command f-string and 'return [\"bash\", \"-c\", shell_command]'"]),
    ("mlflow/projects/databricks.py", 363): ("none", "fp", 0.85, "unknown", None,
        "f-string shell script construction (dedent template with tar/rsync/mv commands); execution happens at the ['bash','-c',...] return consumed by the Databricks run API - construction site only.",
        ["mlflow/projects/databricks.py:362-378"]),
    ("mlflow/projects/databricks.py", 379): ("sink", "tp", 0.85, "argument", 2,
        "Shell sink: returns ['bash','-c', shell_command] - argument 2 is a bash script whose dbfs_fuse_tar_uri/container_tar_path components derive from the project tarball path (project-supplied artifact); the mlflow sub-command itself is quote()-wrapped.",
        ["mlflow/projects/databricks.py:361-379"]),

    # --- mlflow/utils/databricks_utils.py ---
    ("mlflow/utils/databricks_utils.py", 174): ("none", "fp", 0.9, "unknown", None,
        "is_dbfs_fuse_available() probes with a fixed argv command; no untrusted data.",
        ["mlflow/utils/databricks_utils.py:174-184"]),
    ("mlflow/utils/databricks_utils.py", 178): ("sink", "fp", 0.9, "argument", 0,
        "subprocess.call(['mountpoint','/dbfs']) - fixed argv literals, no shell.",
        ["mlflow/utils/databricks_utils.py:178-181"]),

    # --- mlflow/models/docker_utils.py ---
    ("mlflow/models/docker_utils.py", 227): ("summary", "candidate", 0.6, "param", 1,
        "Docker image build wrapper: _build_image_from_context(context_dir, image_name) runs Popen(['docker','build','-t',image_name,'-f','Dockerfile',...]) with image_name supplied by callers (mlflow models build-docker --name); argv list without shell limits injection to docker arguments.",
        ["mlflow/models/docker_utils.py:235-245"]),
    ("mlflow/models/docker_utils.py", 245): ("sink", "candidate", 0.6, "argument", 0,
        "Popen(commands) with fixed-program argv list ('docker','build','-t',image_name,...) and no shell; image_name (CLI-supplied) and context_dir are the only dynamic parts - argument-level injection into docker only, hence candidate.",
        ["mlflow/models/docker_utils.py:235-245"]),

    # --- mlflow/utils/environment.py ---
    ("mlflow/utils/environment.py", 587): ("summary", "tp", 0.9, "param", 0,
        "Central environment execution wrapper: Environment.execute(command, ...) joins self._activate_cmd + command with ' && '/' & ', wraps the result in ['bash','-c', ...] (line 611) or ['cmd','/c', ...] (line 613) and executes it via _exec_cmd (process.py:95). command is a plain string (e.g. the scoring server gunicorn command) executed unescaped through the shell.",
        ["mlflow/utils/environment.py:601-615 'command = separator.join(map(str, self._activate_cmd + command)); command = [\"bash\", \"-c\", command] ... return _exec_cmd(command, ...)'"]),
    ("mlflow/utils/environment.py", 611): ("sink", "tp", 0.9, "argument", 2,
        "Shell sink (list construction): ['bash','-c', command] where command joins the env activation command with the caller's command string (scoring server command with model path/host/port); executed via _exec_cmd -> subprocess.Popen.",
        ["mlflow/utils/environment.py:609-615"]),
    ("mlflow/utils/environment.py", 613): ("sink", "tp", 0.85, "argument", 2,
        "Windows shell variant: ['cmd','/c', command] - argument 2 is the joined command string executed through cmd.exe via _exec_cmd.",
        ["mlflow/utils/environment.py:609-615"]),

    # --- mlflow/projects/backend/local.py: project execution engine ---
    ("mlflow/projects/backend/local.py", 242): ("summary", "tp", 0.85, "param", 0,
        "mlflow run subprocess launcher: _run_mlflow_run_cmd(mlflow_run_arr, env_map) executes the argv list built by _get_mlflow_run_cmd (local.py:229-239) whose elements include the project URI, --docker-args entries and '-P key=value' user parameters; executed via Popen without shell (lines 252/259), so parameter values are argv elements re-parsed by the child mlflow run process (which quote()s them in _project_spec).",
        ["mlflow/projects/backend/local.py:229-239 argv construction incl. f\"{key}={value}\" parameter elements",
         "mlflow/projects/_project_spec.py:232-241 compute_command + _sanitize_param_dict (quote barrier)"]),
    ("mlflow/projects/backend/local.py", 252): ("sink", "fp", 0.7, "argument", 0,
        "Popen(mlflow_run_arr) argv list without shell (Windows branch): user parameters appear as separate argv elements ('-P', 'key=value') so no shell metacharacter interpretation occurs at this site; the child `mlflow run` re-quotes parameters before bash -c (see local.py:277).",
        ["mlflow/projects/backend/local.py:251-259"]),
    ("mlflow/projects/backend/local.py", 259): ("sink", "fp", 0.7, "argument", 0,
        "Popen(mlflow_run_arr) argv list without shell (POSIX branch, preexec_fn=os.setsid): same fixed-program argv form as the Windows branch - no shell interpretation at this site.",
        ["mlflow/projects/backend/local.py:258-259"]),
    ("mlflow/projects/backend/local.py", 262): ("summary", "tp", 0.95, "param", 0,
        "THE project entry-point executor: _run_entry_point(command, ...) receives the command string produced by EntryPoint.compute_command (MLproject command template with parameter substitution, _project_spec.py:232-237) and executes it via ['bash','-c',command] (line 277) / ['cmd','/c',command] (line 280).",
        ["mlflow/projects/_project_spec.py:232-237 'command_with_params = self.command.format(**params); command_arr.extend([f\"--{key} {value}\" ...])'",
         "mlflow/projects/backend/local.py:273-281"]),
    ("mlflow/projects/backend/local.py", 277): ("sink", "tp", 0.95, "argument", 2,
        "Confirmed shell sink: subprocess.Popen(['bash','-c', command]) - argument 2 is the MLproject entry-point command (untrusted project artifact) after str.format parameter substitution; declared parameters are quote()-wrapped by _sanitize_param_dict but the command template itself and the unquoted extra-parameter fragments '--{key} {value}' are interpolated raw.",
        ["mlflow/projects/backend/local.py:276-277",
         "mlflow/projects/_project_spec.py:234-237 (format + unquoted extra args)",
         "mlflow/utils/string_utils.py:130-131 quote() sanitizer for declared params"]),
    ("mlflow/projects/backend/local.py", 280): ("sink", "tp", 0.9, "argument", 2,
        "Windows shell sink: subprocess.Popen(['cmd','/c', command]) - argument 2 is the same MLproject entry-point command string (mutually exclusive with the bash branch at runtime); command injection via the command template or unquoted extra parameters applies analogously under cmd.exe.",
        ["mlflow/projects/backend/local.py:278-280"]),

    # --- mlflow/utils/requirements_utils.py ---
    ("mlflow/utils/requirements_utils.py", 193): ("summary", "tp", 0.8, "param", 0,
        "Pip subprocess wrapper: _run_command(cmd, timeout_seconds, env) forwards its cmd (pip argv list built from model requirement inference, e.g. ['python','-m','pip','install',...]) to subprocess.Popen at line 197.",
        ["mlflow/utils/requirements_utils.py:193-216"]),
    ("mlflow/utils/requirements_utils.py", 197): ("sink", "tp", 0.8, "argument", 0,
        "Popen(cmd) - argument 0 is a pip command (argv list form) built from model-derived requirements data; callers construct it without shell, but the model-inference provenance of requirement strings keeps this a genuine command-execution boundary.",
        ["mlflow/utils/requirements_utils.py:197 'proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)'"]),
    ("mlflow/utils/requirements_utils.py", 207): ("none", "fp", 0.95, "unknown", None,
        "f-string is part of a MlflowException message ('Encountered an unexpected error while running {cmd}'), not a command.",
        ["mlflow/utils/requirements_utils.py:205-212"]),
    ("mlflow/utils/requirements_utils.py", 208): ("none", "fp", 0.95, "unknown", None,
        "f-string is an exception-message fragment (exit status), not a command.",
        ["mlflow/utils/requirements_utils.py:205-212"]),
    ("mlflow/utils/requirements_utils.py", 209): ("none", "fp", 0.95, "unknown", None,
        "f-string is an exception-message fragment (stdout), not a command.",
        ["mlflow/utils/requirements_utils.py:205-212"]),
    ("mlflow/utils/requirements_utils.py", 210): ("none", "fp", 0.95, "unknown", None,
        "f-string is an exception-message fragment (stderr), not a command.",
        ["mlflow/utils/requirements_utils.py:205-212"]),

    # --- mlflow/gateway/runner.py ---
    ("mlflow/gateway/runner.py", 58): ("summary", "tp", 0.7, "field", None,
        "Gateway process launcher: Runner.start() spawns [sys.executable, '-m', 'gunicorn', '--bind', f'{host}:{port}', ...] from the Runner's config_path/host/port/workers fields (CLI-supplied via gateway/cli.py start); executed as an argv list without shell.",
        ["mlflow/gateway/runner.py:58-76",
         "mlflow/gateway/cli.py:43-... click start(config_path, host, port, workers)"]),
    ("mlflow/gateway/runner.py", 59): ("sink", "candidate", 0.55, "argument", 0,
        "Popen(argv) with fixed-program argv list (python -m gunicorn) and no shell; host/port come from CLI options - only bind-argument injection is conceivable, no shell interpretation.",
        ["mlflow/gateway/runner.py:59-71"]),
    ("mlflow/gateway/runner.py", 65): ("none", "fp", 0.85, "unknown", None,
        "f-string '{host}:{port}' is an argv element (--bind value) inside a no-shell Popen argv list; not a shell command string.",
        ["mlflow/gateway/runner.py:64-65"]),
    ("mlflow/gateway/runner.py", 70): ("none", "fp", 0.85, "unknown", None,
        "f-string app-module name is a fixed argv element; no shell involved.",
        ["mlflow/gateway/runner.py:70"]),

    # --- mlflow/recipes/utils/step.py ---
    ("mlflow/recipes/utils/step.py", 61): ("none", "fp", 0.85, "unknown", None,
        "display_html() only opens a generated HTML card with the platform opener; argv list, internal card path, no shell and no untrusted command data.",
        ["mlflow/recipes/utils/step.py:91-115"]),
    ("mlflow/recipes/utils/step.py", 78): ("none", "fp", 0.95, "unknown", None,
        "f-string is a MlflowException message about Databricks runtime version, not a command.",
        ["mlflow/recipes/utils/step.py:76-80"]),
    ("mlflow/recipes/utils/step.py", 108): ("none", "fp", 0.95, "unknown", None,
        "f-string is a log message ('Opening HTML file at ...'), not a command.",
        ["mlflow/recipes/utils/step.py:108"]),
    ("mlflow/recipes/utils/step.py", 110): ("sink", "fp", 0.8, "argument", 0,
        "subprocess.run([open_tool, html_file_path]) - argv list without shell; open_tool comes from shutil.which (fixed tool names) and html_file_path is the internally generated recipe card path.",
        ["mlflow/recipes/utils/step.py:92-110"]),
    ("mlflow/recipes/utils/step.py", 113): ("none", "fp", 0.95, "unknown", None,
        "f-string is a warning log message, not a command.",
        ["mlflow/recipes/utils/step.py:111-115"]),

    # --- mlflow/models/wheeled_model.py ---
    ("mlflow/models/wheeled_model.py", 201): ("summary", "tp", 0.9, "param", 0,
        "Wheel download wrapper: WheeledModel._download_wheels(pip_requirements_path, dst_path) reads MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS from the environment and builds the f-string pip command executed with shell=True at line 222.",
        ["mlflow/models/wheeled_model.py:214 'pip_wheel_options = MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS.get()'",
         "mlflow/models/wheeled_model.py:216-222"]),
    ("mlflow/models/wheeled_model.py", 217): ("none", "fp", 0.85, "unknown", None,
        "f-string download command construction site ('{sys.executable} -m pip wheel {pip_wheel_options} ...'); the actual execution (shell=True subprocess.run) is at line 222 - this row is construction only.",
        ["mlflow/models/wheeled_model.py:216-219"]),
    ("mlflow/models/wheeled_model.py", 222): ("sink", "tp", 0.95, "argument", 0,
        "Confirmed shell sink: subprocess.run([download_command], check=True, shell=True, capture_output=True) - a single-string command through the shell whose pip_wheel_options segment is the raw value of the MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS environment variable and whose paths derive from the model directory (untrusted model artifact).",
        ["mlflow/models/wheeled_model.py:216-222"]),
    ("mlflow/models/wheeled_model.py", 225): ("none", "fp", 0.95, "unknown", None,
        "str.format builds a MlflowException message ('An error occurred while downloading the dependency wheels ...'), not a command.",
        ["mlflow/models/wheeled_model.py:223-227"]),

    # --- mlflow/utils/__init__.py ---
    ("mlflow/utils/__init__.py", 203): ("none", "fp", 0.9, "unknown", None,
        "check_port_connectivity() probes with fixed 'nc' argv commands; ports are internally generated integers, no shell, no untrusted data.",
        ["mlflow/utils/__init__.py:203-221"]),
    ("mlflow/utils/__init__.py", 206): ("sink", "fp", 0.85, "argument", 0,
        "Popen(['nc','-l','-p',str(port)]) - fixed argv list, no shell, internally generated port.",
        ["mlflow/utils/__init__.py:206-210"]),
    ("mlflow/utils/__init__.py", 211): ("sink", "fp", 0.85, "argument", 0,
        "Popen(['nc','-zv','localhost',str(port)]) - fixed argv list, no shell.",
        ["mlflow/utils/__init__.py:211-215"]),
}

# Sink table key normalization: which sink-table entries are fed by which CSV rows
# is resolved by (file, line) matching; the callable/type in the signature comes
# from the merged rows.

# ---------------------------------------------------------------------------
# Source site overrides (file, line) -> verdict
# ---------------------------------------------------------------------------
SRC_OVERRIDES = {
    # environment variables that are genuine command carriers
    ("mlflow/utils/conda.py", 54): ("source", "tp", 0.85, "return", None,
        "MLFLOW_CONDA_HOME names the conda home directory; get_conda_bin_executable (conda.py:44-61) turns it into the conda binary path used as the executed program in conda env create/list commands (_exec_cmd callers).",
        ["mlflow/utils/conda.py:54-56 'conda_home = os.environ.get(MLFLOW_CONDA_HOME); return os.path.join(conda_home, \"bin/%s\" % executable_name)'"]),
    ("mlflow/utils/conda.py", 58): ("source", "tp", 0.75, "field", None,
        "CONDA_EXE presence check: its directory becomes the conda binary directory used for executed conda commands.",
        ["mlflow/utils/conda.py:57-60"]),
    ("mlflow/utils/conda.py", 59): ("source", "tp", 0.75, "field", None,
        "os.environ['CONDA_EXE'] dirname feeds the executed conda binary path.",
        ["mlflow/utils/conda.py:58-60"]),
    ("mlflow/utils/conda.py", 90): ("source", "tp", 0.8, "return", None,
        "MLFLOW_CONDA_CREATE_ENV_CMD overrides the executable used for 'conda env create' (_get_conda_executable_for_create_env -> _create_conda_env -> _exec_cmd); environment-controlled command program.",
        ["mlflow/utils/conda.py:90-95"]),
    ("mlflow/projects/_project_spec.py", 165): ("source", "tp", 0.8, "return", None,
        "os.environ.get('SHELL','bash') selects the interpreter program used to run '.sh' project entry points (ext_to_cmd in Project.get_entry_point, executed via bash -c/cmd /c in local.py:277/280).",
        ["mlflow/projects/_project_spec.py:165-167 'ext_to_cmd = {\".py\": \"python\", \".sh\": os.environ.get(\"SHELL\", \"bash\")}'"]),
    ("mlflow/models/wheeled_model.py", 214): ("source", "tp", 0.9, "return", None,
        "MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS is interpolated raw into the pip wheel download command f-string and executed with shell=True at wheeled_model.py:222 - direct command-option injection carrier.",
        ["mlflow/models/wheeled_model.py:214-222"]),
    ("mlflow/environment_variables.py", 20): ("source", "tp", 0.65, "field", None,
        "_EnvironmentVariable registry env access: the MLFLOW_* variable registry reads/writes os.environ; all MLFLOW_*.get() reads funnel through get_raw (line 23) / get (line 66).",
        ["mlflow/environment_variables.py:8-66"]),
    ("mlflow/environment_variables.py", 23): ("source", "tp", 0.75, "return", None,
        "_EnvironmentVariable.get_raw() returns os.getenv(self.name) - the central read point for every MLFLOW_* variable (75+ call sites across mlflow/), including command-relevant ones (MLFLOW_CONDA_HOME, MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS).",
        ["mlflow/environment_variables.py:22-24 'def get_raw(self): return os.getenv(self.name)'"]),
    ("mlflow/environment_variables.py", 26): ("none", "fp", 0.9, "field", None,
        "set() writes os.environ[self.name] - an env write, not an input read.",
        ["mlflow/environment_variables.py:26-27"]),
    ("mlflow/environment_variables.py", 29): ("none", "fp", 0.9, "return", None,
        "unset() pops the variable from os.environ - env removal, not an input read.",
        ["mlflow/environment_variables.py:28-30"]),
    ("mlflow/environment_variables.py", 66): ("source", "tp", 0.75, "return", None,
        "Second registry getenv read point (MLFLOW_SYSTEM_ENV_* class); same funnel semantics as get_raw().",
        ["mlflow/environment_variables.py:63-67"]),
    ("mlflow/models/container/__init__.py", 61): ("source", "tp", 0.7, "field", None,
        "sys.argv of the container entrypoint (_init cmd from the SageMaker/deployment harness) is external input; at this site it is only interpolated into an exception message, but the argv values (serve/train) select execution paths.",
        ["mlflow/models/container/__init__.py:61 'raise Exception(f\"Unrecognized command {cmd}, full args = {sys.argv}\")'"]),
    ("mlflow/models/container/__init__.py", 73): ("source", "candidate", 0.6, "field", None,
        "MLFLOW_DEPLOYMENT_FLAVOR_NAME selects the serving flavor path (mleap vs pyfunc) from the deployment environment - externally settable behavior selector, not a direct data carrier.",
        ["mlflow/models/container/__init__.py:73-74"]),
    ("mlflow/models/container/__init__.py", 74): ("source", "candidate", 0.6, "field", None,
        "MLFLOW_DEPLOYMENT_FLAVOR_NAME env read selecting the serving flavor path.",
        ["mlflow/models/container/__init__.py:73-77"]),
    ("mlflow/models/container/__init__.py", 146): ("source", "candidate", 0.55, "return", None,
        "DISABLE_NGINX env flag toggling serving behavior (boolean), not a command data carrier.",
        ["mlflow/models/container/__init__.py:146"]),
    ("mlflow/models/container/__init__.py", 147): ("source", "candidate", 0.55, "return", None,
        "ENABLE_MLSERVER env flag toggling serving behavior (boolean).",
        ["mlflow/models/container/__init__.py:147"]),
    ("mlflow/models/container/__init__.py", 148): ("source", "candidate", 0.55, "return", None,
        "DISABLE_ENV_CREATION env flag toggling dependency installation.",
        ["mlflow/models/container/__init__.py:148"]),
    ("mlflow/models/container/__init__.py", 190): ("source", "candidate", 0.55, "return", None,
        "MLSERVER_INFER_WORKERS env value (worker count), behavior configuration only.",
        ["mlflow/models/container/__init__.py:190"]),
    ("mlflow/utils/virtualenv.py", 147): ("source", "candidate", 0.6, "return", None,
        "PYENV_ROOT locates the pyenv installation; the resulting python binary path becomes part of virtualenv activation command strings, so it is path-relevant but operator-controlled.",
        ["mlflow/utils/virtualenv.py:141-151"]),
    ("mlflow/utils/virtualenv.py", 37): ("none", "fp", 0.75, "return", None,
        "MLFLOW_ENV_ROOT selects the virtualenv storage root directory - local configuration path, not a command carrier.",
        ["mlflow/utils/virtualenv.py:37"]),
    ("mlflow/server/handlers.py", 423): ("source", "tp", 0.95, "return", None,
        "json.loads(request_json) decodes double-encoded JSON HTTP request bodies inside _get_request_message - direct external request data entering the tracking/model-registry REST handlers.",
        ["mlflow/server/handlers.py:416-423"]),
    ("mlflow/pyfunc/scoring_server/__init__.py", 95): ("source", "tp", 0.95, "return", None,
        "json.loads(json_input) decodes pyfunc scoring-server prediction payloads (HTTP request body) - direct external request data.",
        ["mlflow/pyfunc/scoring_server/__init__.py:88-95"]),
    ("mlflow/pyfunc/scoring_server/__init__.py", 303): ("source", "tp", 0.75, "return", None,
        "open(input_path) reads the prediction input file (CLI --input-path) for pyfunc predict - external data file.",
        ["mlflow/pyfunc/scoring_server/__init__.py:300-310"]),
    ("mlflow/pyfunc/scoring_server/__init__.py", 317): ("none", "fp", 0.85, "return", None,
        "open(output_path, 'w') writes predictions - an output file, not an input read.",
        ["mlflow/pyfunc/scoring_server/__init__.py:317"]),
    ("mlflow/gateway/config.py", 275): ("source", "tp", 0.8, "return", None,
        "yaml.safe_load(path.read_text()) loads the gateway route configuration (model URLs, prompts, provider settings) from the config file passed to the gateway CLI - operator/serving-context input that drives the gateway service.",
        ["mlflow/gateway/config.py:272-276"]),
    ("mlflow/cli.py", 196): ("source", "tp", 0.85, "return", None,
        "json.loads in cli.py run parses CLI-supplied JSON (docker-args/param-list style options) - external CLI input.",
        ["mlflow/cli.py:193-197"]),
    ("mlflow/sagemaker/cli.py", 189): ("source", "tp", 0.8, "return", None,
        "json.load of the deployment config file given via the sagemaker CLI (-C/--config-json) - external CLI input that flows into deployment parameters.",
        ["mlflow/sagemaker/cli.py:186-190"]),
    ("mlflow/sagemaker/cli.py", 325): ("source", "tp", 0.8, "return", None,
        "json.load of the push-model config file from the sagemaker CLI - external CLI input.",
        ["mlflow/sagemaker/cli.py:322-326"]),
    ("mlflow/deployments/__init__.py", 74): ("source", "tp", 0.8, "return", None,
        "json.loads of the deployment config string/CLI value - external input to the deployment client.",
        ["mlflow/deployments/__init__.py:66-76"]),
    ("mlflow/projects/__init__.py", 315): ("source", "tp", 0.8, "return", None,
        "open(backend_config) reads the project backend-config JSON supplied via `mlflow run --backend-config` - external CLI/project input.",
        ["mlflow/projects/__init__.py:310-318"]),
    ("mlflow/projects/__init__.py", 413): ("source", "tp", 0.85, "return", None,
        "open(job_template) reads the Kubernetes job template YAML for project execution - externally supplied project input interpolated into the job spec.",
        ["mlflow/projects/__init__.py:410-415"]),
    ("mlflow/projects/__init__.py", 414): ("source", "tp", 0.85, "return", None,
        "yaml.safe_load of the kubernetes job template - external project input.",
        ["mlflow/projects/__init__.py:413-415"]),
    ("mlflow/projects/docker.py", 91): ("source", "tp", 0.8, "return", None,
        "open(build_ctx_path, 'rb') reads the docker build context tarball built from the project directory - project-derived (untrusted) content fed to docker build.",
        ["mlflow/projects/docker.py:88-93"]),
    ("mlflow/projects/docker.py", 134): ("none", "fp", 0.85, "return", None,
        "open(..., 'w') writes the generated Dockerfile - output write, not an input read.",
        ["mlflow/projects/docker.py:134"]),
    ("mlflow/models/model.py", 457): ("none", "fp", 0.85, "return", None,
        "open(path, 'w') writes MLmodel metadata - output write.",
        ["mlflow/models/model.py:457"]),
    ("mlflow/models/model.py", 485): ("source", "tp", 0.85, "return", None,
        "open(path) reads the MLmodel file of a model directory - the primary untrusted model-artifact metadata input (flavors, env file paths).",
        ["mlflow/models/model.py:483-486"]),
    ("mlflow/models/model.py", 486): ("source", "tp", 0.9, "return", None,
        "yaml.safe_load of the MLmodel file - untrusted model metadata (conda/virtualenv env paths, flavor configs) that later feeds command construction.",
        ["mlflow/models/model.py:485-486"]),
    ("mlflow/utils/requirements_utils.py", 109): ("source", "tp", 0.8, "return", None,
        "open(requirements) reads a requirements file (model artifact input for dependency inference).",
        ["mlflow/utils/requirements_utils.py:109-112"]),
    ("mlflow/utils/requirements_utils.py", 296): ("source", "tp", 0.75, "return", None,
        "open(output_file) reads the generated pip freeze output used to build model requirements - model-environment derived data.",
        ["mlflow/utils/requirements_utils.py:294-298"]),
    ("mlflow/utils/requirements_utils.py", 322): ("source", "tp", 0.75, "return", None,
        "open(output_file) reads inferred-requirements output (model-environment derived data).",
        ["mlflow/utils/requirements_utils.py:320-324"]),
    ("mlflow/utils/requirements_utils.py", 377): ("none", "fp", 0.8, "return", None,
        "open(pypi_index_path) reads mlflow's own packaged pypi_package_index.json resource - shipped internal data, not external input.",
        ["mlflow/utils/requirements_utils.py:377-379"]),
    # auth response object (not input)
    ("mlflow/server/auth/__init__.py", 586): ("none", "fp", 0.9, "param", 0,
        "_after_request(resp) receives the Flask response object - outbound data, not untrusted input.",
        ["mlflow/server/auth/__init__.py:584-590"]),
    # internal object params in handlers
    ("mlflow/server/handlers.py", 1151): ("none", "fp", 0.85, "param", 0,
        "_get_artifact_repo(run) receives an internally fetched Run object, not request data.",
        ["mlflow/server/handlers.py:1145-1155"]),
}

# write-mode open sites that would otherwise default (fp via write detection)
# (no extra entries needed - handled by mode detection)

MODEL_LOAD_TP = ("source", "tp", 0.9, "return", None,
    "Model.load(path) parses the MLmodel file of a (potentially remote/untrusted) model artifact; flavor configs and env file names from this metadata flow into command construction (container serving, conda/virtualenv environment managers, wheeled models).",
    ["mlflow/models/model.py:461-487 Model.load -> yaml.safe_load(MLmodel)",
     "mlflow/models/container/__init__.py:98-114 model config -> conda env create command",
     "mlflow/utils/virtualenv.py:190-214 model config -> virtualenv/python env commands"])

LOAD_PROJECT_TP = ("source", "tp", 0.95, "return", None,
    "load_project(directory) parses the MLproject YAML of an (untrusted) project directory; entry-point command templates and parameters from this file are the primary CWE-78 carriers into bash -c execution.",
    ["mlflow/projects/_project_spec.py:27-50 yaml.safe_load(MLproject) with entry_points[].command",
     "mlflow/projects/_project_spec.py:232-237 compute_command parameter substitution",
     "mlflow/projects/backend/local.py:277/280 bash -c / cmd /c execution"])


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def norm(row):
    f = row["file"]
    if f.startswith(PREFIX):
        f = f[len(PREFIX):]
    return f.replace("\\", "/")


def line_text(relfile, line):
    path = os.path.join(SRC_ROOT, relfile.replace("/", os.sep))
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:160]
    except OSError:
        pass
    return None


def open_is_write(text):
    if not text:
        return False
    modes = re.findall(r'[\"\']([rwabx+]+)[\"\']', text)
    return any(("w" in m or "a" in m or "x" in m) for m in modes)


def module_of(hint):
    if not hint or hint in ("builtin", "", "<unresolved>"):
        return None
    m = hint
    if m.endswith(".__init__"):
        m = m[: -len(".__init__")]
    return m


def package_of(hint):
    if not hint or hint in ("builtin", "", "<unresolved>"):
        return None
    top = hint.split(".")[0]
    return top if top in ("os", "json", "yaml", "click", "flask", "sys", "subprocess") else "mlflow"


def cli_param_conf(file, line):
    if file == "mlflow/cli.py" and 159 <= line <= 173:
        return 0.9, "click CLI values for `mlflow run` (uri, entry point, -P parameters, --docker-args, env-manager) - the primary external carriers into project command construction"
    if file in ("mlflow/gateway/cli.py", "mlflow/models/cli.py"):
        return 0.8, "click CLI argument/option values (model_uri, env_manager, config_path, host/port/workers ...) bound to command function parameters - external user input"
    if file in ("mlflow/sagemaker/cli.py", "mlflow/deployments/cli.py"):
        return 0.75, "click CLI argument/option values (model_uri, config, target, image_url ...) - external user input"
    return 0.7, "click CLI argument/option values - external user input"


def classify_source(site, rows, text):
    file, line = site
    primary = rows[0]
    flow = primary["flowKind"]
    callable_ = primary["callableName"]

    # 1. non-product code
    if file.startswith("dev/") or file == "setup.py" or file.startswith("docs/") or "/examples/" in ("/" + file):
        return ("none", "fp", 0.85, "receiver" if flow == "cli" else ("param" if flow == "param" else "unknown"), None,
                "Development/example script, not shipped product code (dev tooling, packaging, docs or examples/); excluded from the runtime attack surface of the mlflow distribution.",
                [f"site is under {'dev/' if file.startswith('dev/') else 'examples/docs/setup' } in the repository"])

    # 2. site overrides
    if site in SRC_OVERRIDES:
        return SRC_OVERRIDES[site]

    # 3. family rules
    if flow == "config":
        return MODEL_LOAD_TP
    if callable_ == "load_project":
        return LOAD_PROJECT_TP
    if flow == "internal_transfer":
        fk = "return" if callable_ in CALL_FORMS or callable_.startswith("_get_request") else "return"
        return ("source", "tp", 0.85, fk, None,
                "Internal request-decoding wrapper call (%s): the return value carries decoded external HTTP request data (query string, JSON body, protobuf message) into the handler logic." % callable_,
                ["mlflow/server/handlers.py:385-447 _get_request_json/_get_request_message decode query string and JSON bodies",
                 "mlflow/pyfunc/scoring_server/__init__.py:88-135 parse_json_input/parse_csv_input decode prediction payloads"])
    if flow == "http":
        if callable_ in ("method", "url_rule"):
            return ("source", "candidate", 0.55, "field", None,
                    "HTTP routing metadata (request method / matched url rule): attacker-selected but framework-constrained; not a data payload carrier - kept as candidate for recall.",
                    [])
        fk = "return" if callable_ in CALL_FORMS else "field"
        conf = 0.9
        return ("source", "tp", conf, fk, None,
                "Flask/FastAPI request field read: external HTTP request data (body, query, form, headers, stream) entering the tracking-server / scoring-server / auth / gateway handlers - primary external input boundary.",
                [])
    if flow == "cli":
        if callable_ == "argv":
            if file == "mlflow/tracking/context/default_context.py":
                return ("source", "candidate", 0.6, "field", None,
                        "sys.argv read used to derive default run tags - external CLI input, but consumed as tag values (not command data).",
                        [])
            return ("source", "candidate", 0.6, "field", None,
                    "sys.argv read - external process arguments; at this site consumed for metadata/context, not directly as command data.",
                    [])
        # decorator rows
        conf, why = 0.55, "click decorator declares a CLI input binding; the actual value enters via the decorated function's parameters (see the param entries for this file) - kept as candidate boundary marker for recall."
        return ("source", "candidate", conf, "receiver", None, why, [])
    if flow == "param":
        conf, why = cli_param_conf(file, line)
        return ("source", "tp", conf, "param", int(primary["argIndex"]) if primary["argIndex"] not in ("", "-1") else None,
                "click command function parameter: " + why + ".", [])
    if flow == "env" or (flow == "return" and callable_ == "getenv"):
        fk = "return" if callable_ in CALL_FORMS else "field"
        return ("none", "fp", 0.75, fk, None,
                "MLFLOW_* / os environment read used as configuration or credential value (timeout, chunk size, URI, credentials, flags, temp dirs, child-process env maps); operator-controlled configuration, not a request/attacker-influenced command carrier under this threat model.",
                [])
    if flow == "file":  # open()
        if open_is_write(text):
            return ("none", "fp", 0.85, "return", None,
                    "open(..., 'w'/'wb') writes an output file (env file, model artifact, generated Dockerfile, devnull) - not an input read.",
                    [])
        if file.startswith(FLAVOR_PREFIXES) or file in FLAVOR_FILES:
            return ("source", "tp", 0.7, "return", None,
                    "open() in a model flavor module reading model artifact data (model binaries, configs, pickles) - untrusted when the model comes from a remote registry/artifact store.",
                    [])
        if file.startswith(REMOTE_PREFIXES) or file in REMOTE_FILES:
            return ("source", "candidate", 0.55, "return", None,
                    "open() reading store/tracking/gateway data files - data previously written by mlflow (round-trip) or downloaded artifacts; attacker-influenced only indirectly via API round-trips.",
                    [])
        return ("source", "candidate", 0.55, "return", None,
                "open() reading an internal/pipeline file - round-trip or derived data; kept as candidate for recall.",
                [])
    if flow == "return":  # json/yaml decode
        if file.startswith(FLAVOR_PREFIXES) or file in FLAVOR_FILES:
            return ("source", "candidate", 0.65, "return", None,
                    "json/yaml decode in a model flavor module: model config artifact data or provider API responses - externally influenced but mixed provenance.",
                    [])
        if file.startswith(REMOTE_PREFIXES) or file in REMOTE_FILES:
            return ("source", "candidate", 0.6, "return", None,
                    "json/yaml decode of remote-service responses (tracking server, gateway, databricks, provider APIs) or store round-trips - untrusted-server dependent, candidate.",
                    [])
        if file.startswith(INTERNAL_PREFIXES) or file in INTERNAL_FILES:
            return ("source", "candidate", 0.55, "return", None,
                    "json/yaml decode of internal round-trip data (recipe state, evaluation outputs, utility config readers) - candidate for recall.",
                    [])
        if file == "mlflow/projects/_project_spec.py":
            return ("source", "tp", 0.95, "return", None,
                    "yaml.safe_load(mlproject_file) parses the MLproject spec - untrusted project artifact whose entry-point commands are the primary CWE-78 carriers.",
                    ["mlflow/projects/_project_spec.py:33-34"])
        return ("source", "candidate", 0.6, "return", None,
                "json/yaml decode of mixed-provenance data (internal round-trips, configs) - candidate for recall.",
                [])
    return ("source", "candidate", 0.5, "unknown", None,
            "Unclassified candidate row; kept as candidate.", [])


def build():
    sources = load_csv(os.path.join(IRIS, "extraction", "sources.csv"))
    sinks = load_csv(os.path.join(IRIS, "extraction", "sinks.csv"))

    for r in sources + sinks:
        r["_file"] = norm(r)
        r["_line"] = int(r["line"])

    # group rows by site
    def group(rows):
        g = OrderedDict()
        for r in rows:
            g.setdefault((r["_file"], r["_line"]), []).append(r)
        return g

    src_groups = group(sources)
    snk_groups = group(sinks)

    entries = []
    raw_records = []
    counts = {"role": {}, "cls": {}}

    def bump(role, cls):
        counts["role"][role] = counts["role"].get(role, 0) + 1
        counts["cls"][cls] = counts["cls"].get(cls, 0) + 1

    # ---- sinks ----
    snk_i = 0
    for site, rows in snk_groups.items():
        snk_i += 1
        if site not in SINK_TABLE:
            raise SystemExit("sink site missing from table: %s:%d" % site)
        role, cls, conf, fk, ai, rationale, evidence = SINK_TABLE[site]
        primary = rows[0]
        text = line_text(site[0], site[1])
        ev = ["code: " + text] if text else []
        ev += evidence
        ev.append("extraction rows merged: %d (matchKind: %s; flowKind: %s)"
                  % (len(rows), "/".join(sorted({r["matchKind"] for r in rows})), "/".join(sorted({r["flowKind"] for r in rows}))))
        recv = rows[0].get("receiver") or None
        type_ = recv if recv and recv[0].isupper() and recv not in ("Model",) else (recv if recv in ("Model",) else None)
        entries.append({
            "id": "snk-%03d" % snk_i,
            "role": role,
            "classification": cls,
            "confidence": conf,
            "signature": {
                "package": package_of(primary["moduleHint"]),
                "module": module_of(primary["moduleHint"]),
                "type": type_,
                "callable": primary["callableName"],
                "arg_index": ai,
                "flow_kind": fk,
            },
            "location": {"file": site[0], "line": site[1]},
            "rationale": rationale,
            "evidence": ev,
        })
        bump(role, cls)
        raw_records.append({"id": "snk-%03d" % snk_i, "file": site[0], "line": site[1],
                            "rows": [{"matchKind": r["matchKind"], "flowKind": r["flowKind"],
                                      "callable": r["callableName"], "receiver": r["receiver"]} for r in rows]})

    # ---- sanitizers (extra, verified in code) ----
    san = [
        ("san-001", "quote", "mlflow.utils.string_utils", None,
         ("sanitizer", "tp", 0.85, "param", 0,
          "mlflow.utils.string_utils.quote() = shlex.quote (POSIX) / mslex_quote (Windows): a genuine shell-quoting barrier. Applied to MLproject declared parameters (EntryPoint._sanitize_param_dict, _project_spec.py:241), entry-point script names (:167/:172), the R backend model path (rfunc/backend.py:80) and every element of the Databricks mlflow run argv (databricks.py:361) before those values reach bash -c / Rscript -e. Caveat: it does NOT protect the command template itself, the unquoted extra-parameter fragments '--{key} {value}' (_project_spec.py:236), or host/port values interpolated into R code.",
          ["mlflow/utils/string_utils.py:130-131 'def quote(s): return mslex_quote(s) if os.name == \"nt\" else shlex.quote(s)'",
           "mlflow/projects/_project_spec.py:239-241 '_sanitize_param_dict: {str(key): quote(str(value)) ...}'",
           "mlflow/projects/_project_spec.py:236 unquoted extra params remain: f\"--{key} {value}\"",
           "mlflow/rfunc/backend.py:79-82 quote(model_path) into R expression",
           "mlflow/projects/databricks.py:361 quote(elem) for mlflow run argv"]),
         "mlflow/utils/string_utils.py", 131),
        ("san-002", "_sanitize_param_dict", "mlflow.projects._project_spec", "EntryPoint",
         ("sanitizer", "tp", 0.8, "param", None,
          "EntryPoint._sanitize_param_dict applies string_utils.quote() to every declared and extra parameter value before str.format substitution into the MLproject command template - the effective shell-quoting barrier for project parameters. Caveat: the command template itself and the '--{key} {value}' extra-argument fragments joined at _project_spec.py:236 remain unquoted.",
          ["mlflow/projects/_project_spec.py:230 'return self._sanitize_param_dict(final_params), self._sanitize_param_dict(extra_params)'",
           "mlflow/projects/_project_spec.py:239-241",
           "mlflow/projects/_project_spec.py:232-237 compute_command format + unquoted extra args"]),
         "mlflow/projects/_project_spec.py", 241),
    ]
    for eid, call_, mod, type_, spec, file, line in san:
        role, cls, conf, fk, ai, rationale, evidence = spec
        entries.append({
            "id": eid, "role": role, "classification": cls, "confidence": conf,
            "signature": {"package": "mlflow", "module": mod, "type": type_, "callable": call_,
                          "arg_index": ai, "flow_kind": fk},
            "location": {"file": file, "line": line},
            "rationale": rationale,
            "evidence": evidence + (["code: " + line_text(file, line)] if line_text(file, line) else []),
        })
        bump(role, cls)

    # ---- sources ----
    src_i = 0
    for site, rows in src_groups.items():
        text = line_text(site[0], site[1])
        role, cls, conf, fk, ai, rationale, evidence = classify_source(site, rows, text)
        if role == "source" and cls in ("tp", "candidate"):
            src_i += 1
            eid = "src-%04d" % src_i
        else:
            eid = "non-%04d" % (len(entries) + 1)
        primary = rows[0]
        # flow_kind refinement for merged rows
        if fk in ("field", "return") and primary["flowKind"] in ("http", "env") and primary["callableName"] in CALL_FORMS:
            fk = "return"
        ev = ["code: " + text] if text else []
        ev += evidence
        ev.append("extraction rows merged: %d (matchKind: %s; flowKind: %s)"
                  % (len(rows), "/".join(sorted({r["matchKind"] for r in rows})), "/".join(sorted({r["flowKind"] for r in rows}))))
        recv = primary.get("receiver") or None
        type_ = recv if recv and recv[0].isupper() else None
        argidx = ai
        if fk == "param" and argidx is None:
            argidx = int(primary["argIndex"]) if primary["argIndex"] not in ("", "-1") else None
        entries.append({
            "id": eid,
            "role": role,
            "classification": cls,
            "confidence": conf,
            "signature": {
                "package": package_of(primary["moduleHint"]),
                "module": module_of(primary["moduleHint"]),
                "type": type_,
                "callable": primary["callableName"],
                "arg_index": argidx,
                "flow_kind": fk,
            },
            "location": {"file": site[0], "line": site[1]},
            "rationale": rationale,
            "evidence": ev,
        })
        bump(role, cls)
        raw_records.append({"id": eid, "file": site[0], "line": site[1],
                            "rows": [{"matchKind": r["matchKind"], "flowKind": r["flowKind"],
                                      "callable": r["callableName"], "receiver": r["receiver"]} for r in rows]})

    # ---- assemble labels.json ----
    labels = {
        "version": "0.3.0",
        "metadata": {
            "run_id": "mlflow-iris-pass2-labeling-20261015",
            "generated_at": "2026-10-15T00:00:00Z",
            "language": "python",
            "framework": "flask",
            "model": "glm-5.3 (Claude Code CLI harness; deterministic tool-assisted labeling, batched review)",
            "project": "mlflow (vulnerable snapshot 2.5.1.dev0, sha 330bf0b38b07d4adf3fae99af1b44c8e857f514a)",
            "notes": [
                "Single-pass scoped run: pass 2 (CWE-78, Command/Argument Injection).",
                "Pass 1 block is a schema-required stub (labels_schema.json 'contains' mandates a pass_id=1 entry); path-traversal CWEs are out of scope and carry zero entries.",
                "Threat model: external input enters via the Flask tracking/model-registry REST API, the pyfunc scoring server, the click CLI (mlflow run -P/--docker-args), untrusted project/model artifacts (MLproject commands, MLmodel/conda/python_env metadata), and MLFLOW_* environment variables in shared/deployment environments; command execution concentrates in subprocess/os.system/shell sites of the project execution engine, pyfunc/deployment backends and the container serving entrypoint.",
                "All 1293 extraction candidates (1148 source rows + 145 sink rows) were processed; dedup by (file, line) merged api/ast and Attribute/Attribute() duplicate rows into 949 source sites and 93 sink sites; 2 sanitizer entries added from in-repo verification (quote / _sanitize_param_dict). Reconciliation detail in labels_raw_pass2.json.",
                "classification=tp means the candidate is a genuine source/sink/sanitizer API for CWE-78 labeling; it is NOT a final vulnerability ground-truth TP (final alert truth requires the Phase 2 taint analysis).",
                "arg_index is 0-based per this run's extraction columnContract (mlflow run, unlike earlier projects that used 1-based param positions); for method wrappers the index excludes self/cls.",
                "Write-mode open() sites (open(..., 'w'/'wb')) are labeled fp (output writes, not input reads); dev/, examples/, setup.py and docs/ rows are labeled fp as non-product code.",
                "Running MLproject entry points, building docker images and creating conda/pip environments is intended MLflow functionality; sink labels mark command-execution boundaries and do not by themselves assert a vulnerability (attack requires attacker influence over project/model artifacts, request fields, CLI values or environment).",
                "Not covered by this run's candidate rows (from detection.json uncoveredCases): mlflow/utils/virtualenv.py:133-137 _exec_cmd(..., shell=not _IS_UNIX) is reached through the _exec_cmd summary (snk entry for process.py:31/95), not as its own row.",
                "No ground-truth artifacts (PyVul confirmed_vulns.json, cmd_sinks*.csv, CVE/fix diffs) were consulted; no source code, database or Augur files were modified.",
            ],
        },
        "passes": [
            {
                "pass_id": 1,
                "focus": "Path Traversal (CWE-022/023/036/073) - out of scope stub; this run is scoped to pass 2 only, block present to satisfy the schema 'contains' constraint on pass_id=1",
                "cwes": ["022"],
                "entries": [],
            },
            {
                "pass_id": 2,
                "focus": "Command/Argument Injection (CWE-78): HTTP request fields, CLI arguments, project/model artifact metadata and MLFLOW_* environment variables reaching subprocess/os.system/shell command execution",
                "cwes": ["077", "078", "088"],
                "entries": entries,
            },
        ],
    }

    # ---- schema validation (inline) ----
    errors = validate(labels)
    if errors:
        raise SystemExit("schema violations:\n" + "\n".join(errors))

    out = os.path.join(IRIS, "labels", "labels.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2, ensure_ascii=False)

    raw_out = os.path.join(IRIS, "labels", "labels_raw_pass2.json")
    with open(raw_out, "w", encoding="utf-8") as f:
        json.dump({
            "run_id": "mlflow-iris-pass2-labeling-20261015",
            "batches": [
                {"batch": "sink-01", "description": "all 93 unique sink sites (exec APIs, shell wrappers, cmd_format constructions) - hand-reviewed against source", "candidates": 93},
                {"batch": "src-01", "description": "http / internal_transfer / param boundaries (server handlers, auth, scoring server, gateway, click CLI params)", "candidates": "see per-site records"},
                {"batch": "src-02", "description": "env boundaries (MLFLOW_* registry + direct os.environ/os.getenv)", "candidates": "see per-site records"},
                {"batch": "src-03", "description": "decode/open boundaries (json/yaml, open read vs write mode distinguished)", "candidates": "see per-site records"},
                {"batch": "reconciliation", "description": "dedup by (file,line); api/ast merge; non-product (dev/, examples/, setup.py, docs/) -> fp; write-mode open -> fp", "candidates": 0},
            ],
            "reconciliation": {
                "source_csv_rows": len(sources),
                "sink_csv_rows": len(sinks),
                "unique_source_sites": len(src_groups),
                "unique_sink_sites": len(snk_groups),
                "api_ast_merges": sum(1 for rows in list(src_groups.values()) + list(snk_groups.values()) if len({r["matchKind"] for r in rows}) > 1),
                "extra_sanitizer_entries": 2,
            },
            "sites": raw_records,
        }, f, indent=2, ensure_ascii=False)

    # ---- stats ----
    print("entries:", len(entries))
    print("role counts:", counts["role"])
    print("classification counts:", counts["cls"])
    conf_bins = {"<0.6": 0, "0.6-0.7": 0, "0.7-0.8": 0, "0.8-0.9": 0, "0.9-1.0": 0}
    for e in entries:
        c = e["confidence"]
        if c < 0.6:
            conf_bins["<0.6"] += 1
        elif c < 0.7:
            conf_bins["0.6-0.7"] += 1
        elif c < 0.8:
            conf_bins["0.7-0.8"] += 1
        elif c < 0.9:
            conf_bins["0.8-0.9"] += 1
        else:
            conf_bins["0.9-1.0"] += 1
    print("confidence:", conf_bins)
    # sink detail
    tp_sinks = [e for e in entries if e["role"] == "sink" and e["classification"] == "tp"]
    print("tp sinks:", len(tp_sinks))
    for e in tp_sinks:
        print("  ", e["location"]["file"], e["location"]["line"], e["signature"]["callable"],
              "arg", e["signature"]["arg_index"], e["confidence"])


def validate(labels):
    errors = []
    roles = {"source", "sink", "sanitizer", "summary", "none"}
    clss = {"tp", "fp", "candidate", "unknown"}
    fks = {"param", "argument", "return", "receiver", "field", "unknown"}
    if not re.match(r"^v?[0-9]+\.[0-9]+(\.[0-9]+)?$", labels["version"]):
        errors.append("version pattern")
    md = labels["metadata"]
    for k in ("run_id", "generated_at", "language", "framework", "model", "project"):
        if k not in md:
            errors.append("metadata missing " + k)
    if md["language"] not in ("python", "go", "java", "javascript", "csharp"):
        errors.append("language enum")
    if not any(p["pass_id"] == 1 for p in labels["passes"]):
        errors.append("passes must contain pass_id=1")
    ids = set()
    for p in labels["passes"]:
        for e in p["entries"]:
            if e["id"] in ids:
                errors.append("duplicate id " + e["id"])
            ids.add(e["id"])
            for k in ("id", "role", "classification", "confidence", "signature", "rationale"):
                if k not in e:
                    errors.append("entry missing " + k)
            if e["role"] not in roles:
                errors.append("role enum " + e["id"])
            if e["classification"] not in clss:
                errors.append("classification enum " + e["id"])
            if not (0 <= e["confidence"] <= 1):
                errors.append("confidence range " + e["id"])
            sig = e["signature"]
            for k in ("callable", "flow_kind", "arg_index"):
                if k not in sig:
                    errors.append("signature missing " + k + " " + e["id"])
            if sig["flow_kind"] not in fks:
                errors.append("flow_kind enum " + e["id"])
            if sig["flow_kind"] == "argument":
                if not isinstance(sig["arg_index"], int) or sig["arg_index"] < 0:
                    errors.append("argument flow requires int arg_index>=0 " + e["id"])
            elif sig["arg_index"] is not None and (not isinstance(sig["arg_index"], int) or sig["arg_index"] < 0):
                errors.append("arg_index must be null or int>=0 " + e["id"])
            if "location" in e:
                if not (isinstance(e["location"]["file"], str) and isinstance(e["location"]["line"], int) and e["location"]["line"] >= 1):
                    errors.append("location " + e["id"])
    return errors


if __name__ == "__main__":
    build()
