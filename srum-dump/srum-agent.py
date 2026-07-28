"""Interactive local LLM assistant for SRUM SQLite query tools.

The agent intentionally reuses ``srum_mcp_query`` in-process instead of
starting a separate MCP server. It converts SRUM ESE data into the enriched
SQLite format first, then gives a local model a small set of documented query
tools that automatically target that SQLite database.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI


DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_LLAMA_CPP_URL = "http://localhost:8080/v1"
DEFAULT_REMOTE_MODEL = "gpt-4o-mini"
DEFAULT_LOCAL_AI_DIR = pathlib.Path.home() / ".srum-agent" / "local-ai"
TOOL_ITERATION_LIMIT = 15
TOOL_CONTINUATION_LIMIT = 5
SRUM_EXPERT_FILENAME = "SRUM_EXPERT.MD"
_MANAGED_PROCESSES: list[subprocess.Popen[Any]] = []
API_URL_ENV_VARS = ("SRUM_AGENT_API_URL", "AI_API_URL", "OPENAI_BASE_URL")
API_KEY_ENV_VARS = ("SRUM_AGENT_API_KEY", "AI_API_KEY", "OPENAI_API_KEY")
API_MODEL_ENV_VARS = ("SRUM_AGENT_MODEL", "AI_MODEL", "OPENAI_MODEL")


@dataclass(frozen=True)
class SystemResources:
	cpu_count: int
	ram_gb: float | None
	database_size_gb: float | None


@dataclass(frozen=True)
class ModelOption:
	key: str
	label: str
	backend: str
	model: str
	required_ram_gb: float
	profile: str
	description: str


@dataclass(frozen=True)
class GgufModelOption:
	key: str
	label: str
	repo: str
	filename: str
	required_ram_gb: float
	description: str


@dataclass(frozen=True)
class AgentTool:
	name: str
	description: str
	callable: Callable[..., Any]


@dataclass(frozen=True)
class InferenceConfig:
	backend: str
	model: str
	api_url: str | None = None
	api_key: str | None = None


MODEL_CATALOG: tuple[ModelOption, ...] = (
	ModelOption(
		key="quick",
		label="Quick",
		backend="ollama",
		model="llama3.2:3b",
		required_ram_gb=6,
		profile="quick responses",
		description="Fastest local option for simple triage questions.",
	),
	ModelOption(
		key="balanced",
		label="Balanced",
		backend="ollama",
		model="qwen2.5:7b-instruct",
		required_ram_gb=10,
		profile="balanced reasoning",
		description="Good default when the workstation has enough memory.",
	),
	ModelOption(
		key="deep",
		label="Deeper",
		backend="ollama",
		model="llama3.1:8b",
		required_ram_gb=12,
		profile="slower deeper analysis",
		description="Slower, more capable choice for open-ended forensic analysis.",
	),
	ModelOption(
		key="llama-cpp",
		label="llama.cpp server",
		backend="llama_cpp",
		model="local-gguf",
		required_ram_gb=8,
		profile="existing llama.cpp runtime",
		description="Uses a running llama.cpp OpenAI-compatible server.",
	),
)

GGUF_MODEL_CATALOG: tuple[GgufModelOption, ...] = (
	GgufModelOption(
		key="quick",
		label="Quick",
		repo="bartowski/Llama-3.2-3B-Instruct-GGUF",
		filename="Llama-3.2-3B-Instruct-Q4_K_M.gguf",
		required_ram_gb=6,
		description="Small GGUF model for quick local triage.",
	),
	GgufModelOption(
		key="balanced",
		label="Balanced",
		repo="bartowski/Qwen2.5-7B-Instruct-GGUF",
		filename="Qwen2.5-7B-Instruct-Q4_K_M.gguf",
		required_ram_gb=10,
		description="Good default GGUF model for SRUM analysis on a workstation.",
	),
	GgufModelOption(
		key="deep",
		label="Deeper",
		repo="bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
		filename="Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
		required_ram_gb=12,
		description="Larger GGUF model for deeper local analysis.",
	),
)

LLAMA_CPP_EXECUTABLE_NAMES = ("llama-server.exe", "llama-server", "server.exe")


SYSTEM_PROMPT = """You are a forensic SRUM analysis assistant.
Use the available tools whenever the answer depends on SRUM database facts.
Prefer purpose-built MCP tools over query_database_read_only. Use direct SQL only
when no purpose-built tool can answer the question, or when inspecting schema,
date coverage, or unusual columns. For user/process questions, prefer
query_processes_by_user_in_time_range or query_process_summary_by_user_in_time_range.
For user/file questions, prefer query_files_by_user_in_time_range or
query_file_summary_by_user_in_time_range. For schema, table names, available
columns, or date coverage questions, call explain_database_schema and only use
query_database_read_only when needed.
Ask for exact time ranges when needed. Keep answers concise, cite tool results,
and never invent records that were not returned by a tool.
"""


def load_srum_expert_context() -> str:
	path = pathlib.Path(__file__).with_name(SRUM_EXPERT_FILENAME)
	try:
		content = path.read_text(encoding="utf-8").strip()
	except OSError as exc:
		return f"SRUM expert guidance file could not be loaded from {path}: {exc}"
	return content or f"SRUM expert guidance file was empty: {path}"


def _load_srum_mcp_query() -> Any:
	try:
		import srum_mcp_query
	except ImportError as exc:
		raise RuntimeError(f"Install requirements.txt before converting or querying SRUM data: {exc}") from exc
	return srum_mcp_query


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Convert SRUM data to SQLite and query it with a local LLM agent."
	)
	parser.add_argument("--SRUM_INFILE", "-i", help="Path to SRUDB.dat. Required unless --SQLITE_IN is supplied.")
	parser.add_argument("--OUT_DIR", "-o", help="Working output directory for generated SQLite databases.")
	parser.add_argument("--REG_HIVE", "-r", help="Optional SOFTWARE hive for offline registry enrichment.")
	parser.add_argument(
		"--ESE_ENGINE",
		"-e",
		choices=("pyesedb", "dissect"),
		default="dissect",
		help="ESE parser to use for conversion. Default: dissect.",
	)
	parser.add_argument("--DEBUG", "-v", action="store_true", help="Print verbose progress and backend diagnostics.")
	parser.add_argument("--NO_CONFIRM", "-q", action="store_true", help="Choose defaults without interactive prompts.")
	parser.add_argument("--SQLITE_IN", help="Use an existing SRUM SQLite database instead of converting SRUDB.dat.")
	parser.add_argument("--SQLITE_OUT", help="Path for the generated SQLite database.")
	parser.add_argument("--OVERWRITE", action="store_true", help="Replace --SQLITE_OUT if it already exists.")
	parser.add_argument("--MODEL", help="Model name to load, for example llama3.2:3b.")
	parser.add_argument(
		"--BACKEND",
		choices=("auto", "remote", "ollama", "llama_cpp"),
		default="auto",
		help="Model backend. Default: auto, which asks for remote API or local setup.",
	)
	parser.add_argument("--API_URL", help="OpenAI-compatible API base URL. Defaults to SRUM_AGENT_API_URL, AI_API_URL, or OPENAI_BASE_URL.")
	parser.add_argument("--API_KEY", help="OpenAI-compatible API key. Defaults to SRUM_AGENT_API_KEY, AI_API_KEY, or OPENAI_API_KEY.")
	parser.add_argument("--API_MODEL", help="OpenAI-compatible model name. Defaults to SRUM_AGENT_MODEL, AI_MODEL, or OPENAI_MODEL.")
	parser.add_argument("--NO_PULL", action="store_true", help="Do not pull/download missing model files.")
	parser.add_argument("--OLLAMA_URL", default=DEFAULT_OLLAMA_URL, help="Ollama base URL.")
	parser.add_argument("--LLAMA_CPP_URL", default=DEFAULT_LLAMA_CPP_URL, help="OpenAI-compatible llama.cpp base URL.")
	parser.add_argument("--LLAMA_CPP_API_KEY", default="llama.cpp", help="API key value for llama.cpp servers that require one.")
	parser.add_argument("--GGUF_MODEL_PATH", help="Local GGUF model path for llama.cpp server startup.")
	parser.add_argument("--HF_GGUF_REPO", help="Hugging Face repository containing a GGUF model file.")
	parser.add_argument("--HF_GGUF_FILE", help="GGUF filename inside --HF_GGUF_REPO.")
	parser.add_argument("--LOCAL_AI_DIR", help="Directory containing or receiving a local llama.cpp runtime and GGUF model.")
	parser.add_argument("--START_LLAMA_SERVER", action="store_true", help="Start llama-server with the resolved GGUF model.")
	parser.add_argument("--LLAMA_CPP_SERVER_CMD", default="llama-server", help="llama.cpp server executable name or path.")
	return parser.parse_args(argv)


def _windows_total_memory_gb() -> float | None:
	if os.name != "nt":
		return None
	try:
		import ctypes

		class MemoryStatusEx(ctypes.Structure):
			_fields_ = [
				("dwLength", ctypes.c_ulong),
				("dwMemoryLoad", ctypes.c_ulong),
				("ullTotalPhys", ctypes.c_ulonglong),
				("ullAvailPhys", ctypes.c_ulonglong),
				("ullTotalPageFile", ctypes.c_ulonglong),
				("ullAvailPageFile", ctypes.c_ulonglong),
				("ullTotalVirtual", ctypes.c_ulonglong),
				("ullAvailVirtual", ctypes.c_ulonglong),
				("ullAvailExtendedVirtual", ctypes.c_ulonglong),
			]

		status = MemoryStatusEx()
		status.dwLength = ctypes.sizeof(status)
		if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
			return round(status.ullTotalPhys / (1024**3), 1)
	except Exception:
		return None
	return None


def collect_system_resources(database_path: str | None) -> SystemResources:
	database_size_gb: float | None = None
	if database_path and pathlib.Path(database_path).exists():
		database_size_gb = round(pathlib.Path(database_path).stat().st_size / (1024**3), 3)
	return SystemResources(
		cpu_count=os.cpu_count() or 1,
		ram_gb=_windows_total_memory_gb(),
		database_size_gb=database_size_gb,
	)


def recommend_model(resources: SystemResources, backend: str) -> ModelOption:
	if backend == "remote":
		backend = "auto"
	allowed = [option for option in MODEL_CATALOG if backend in ("auto", option.backend)]
	if backend == "auto":
		allowed = [option for option in allowed if option.backend == "ollama"] or allowed
	if not allowed:
		return MODEL_CATALOG[0]
	if resources.ram_gb is None:
		return allowed[0]
	suitable = [option for option in allowed if resources.ram_gb >= option.required_ram_gb]
	return suitable[-1] if suitable else allowed[0]


def recommend_gguf_model(resources: SystemResources) -> GgufModelOption:
	if resources.ram_gb is None:
		return GGUF_MODEL_CATALOG[0]
	suitable = [option for option in GGUF_MODEL_CATALOG if resources.ram_gb >= option.required_ram_gb]
	return suitable[-1] if suitable else GGUF_MODEL_CATALOG[0]


def _first_set_value(*values: str | None) -> str | None:
	for value in values:
		if value:
			return value
	return None


def _first_env_value(names: Sequence[str]) -> str | None:
	return _first_set_value(*(os.environ.get(name) for name in names))


def remote_api_defaults(args: argparse.Namespace) -> InferenceConfig:
	return InferenceConfig(
		backend="remote",
		model=_first_set_value(args.API_MODEL, _first_env_value(API_MODEL_ENV_VARS), args.MODEL, DEFAULT_REMOTE_MODEL) or DEFAULT_REMOTE_MODEL,
		api_url=_first_set_value(args.API_URL, _first_env_value(API_URL_ENV_VARS)),
		api_key=_first_set_value(args.API_KEY, _first_env_value(API_KEY_ENV_VARS)),
	)


def _has_remote_api(config: InferenceConfig) -> bool:
	return bool(config.api_url and config.api_key)


def _prompt_remote_api(config: InferenceConfig) -> InferenceConfig:
	api_url = config.api_url or input("OpenAI-compatible API URL: ").strip()
	api_key = config.api_key or getpass.getpass("API key: ").strip()
	model_prompt = f"Model name [default {config.model}]: "
	model = input(model_prompt).strip() or config.model
	if not api_url or not api_key:
		raise ValueError("Remote API selection requires both an API URL and an API key.")
	return InferenceConfig(backend="remote", model=model, api_url=api_url, api_key=api_key)


def _local_setup_label() -> str:
	if platform.system() == "Darwin" and platform.machine().lower() in {"arm64", "aarch64"}:
		return "setup a slow but functional local LLM from a local AI directory"
	return "setup a slow but functional local LLM"


def _prompt_local_ai_dir(args: argparse.Namespace) -> pathlib.Path:
	if args.LOCAL_AI_DIR:
		path = pathlib.Path(args.LOCAL_AI_DIR).expanduser()
	else:
		default_path = DEFAULT_LOCAL_AI_DIR
		if args.NO_CONFIRM:
			path = default_path
		else:
			selection = input(f"Local AI runtime directory [default {default_path}]: ").strip()
			path = pathlib.Path(selection).expanduser() if selection else default_path
	path.mkdir(parents=True, exist_ok=True)
	args.LOCAL_AI_DIR = str(path)
	return path


def _find_local_file(directory: pathlib.Path, names: Iterable[str]) -> pathlib.Path | None:
	name_set = {name.lower() for name in names}
	for candidate in directory.rglob("*"):
		if candidate.is_file() and candidate.name.lower() in name_set:
			return candidate
	return None


def _find_local_gguf(directory: pathlib.Path) -> pathlib.Path | None:
	for candidate in directory.rglob("*.gguf"):
		if candidate.is_file():
			return candidate
	return None


def _confirm(prompt: str, args: argparse.Namespace, default: bool = True) -> bool:
	if args.NO_CONFIRM:
		return default
	suffix = "[Y/n]" if default else "[y/N]"
	answer = input(f"{prompt} {suffix} ").strip().lower()
	if not answer:
		return default
	return answer in {"y", "yes"}


def _download_url(url: str, destination: pathlib.Path) -> pathlib.Path:
	destination.parent.mkdir(parents=True, exist_ok=True)
	with urllib.request.urlopen(url) as response, destination.open("wb") as output:
		shutil.copyfileobj(response, output)
	return destination


def _llama_cpp_asset_url() -> str:
	with urllib.request.urlopen("https://api.github.com/repos/ggml-org/llama.cpp/releases/latest") as response:
		release = json.load(response)
	assets = release.get("assets") or []
	system = platform.system().lower()
	machine = platform.machine().lower()
	if system == "windows":
		required = ("win", "x64" if "64" in machine or "amd64" in machine else "x86")
		extensions = (".zip",)
	elif system == "darwin":
		required = ("macos", "arm64" if machine in {"arm64", "aarch64"} else "x64")
		extensions = (".zip", ".tar.gz")
	else:
		required = ("linux", "x64" if "64" in machine or "amd64" in machine else "x86")
		extensions = (".tar.gz", ".zip")
	for asset in assets:
		name = str(asset.get("name") or "").lower()
		if all(part in name for part in required) and name.endswith(extensions) and not any(skip in name for skip in ("cuda", "vulkan", "sycl")):
			return str(asset["browser_download_url"])
	for asset in assets:
		name = str(asset.get("name") or "").lower()
		if system in name and name.endswith(extensions):
			return str(asset["browser_download_url"])
	raise RuntimeError("Could not find a suitable llama.cpp release asset for this system.")


def download_llama_cpp_engine(local_ai_dir: pathlib.Path, debug: bool = False) -> pathlib.Path:
	url = _llama_cpp_asset_url()
	archive_path = local_ai_dir / "downloads" / pathlib.Path(urllib.parse.urlparse(url).path).name
	if debug:
		print(f"Downloading llama.cpp runtime: {url}")
	_download_url(url, archive_path)
	extract_dir = local_ai_dir / "llama.cpp"
	extract_dir.mkdir(parents=True, exist_ok=True)
	if archive_path.suffix.lower() == ".zip":
		with zipfile.ZipFile(archive_path) as archive:
			archive.extractall(extract_dir)
	else:
		with tarfile.open(archive_path) as archive:
			archive.extractall(extract_dir)
	executable = _find_local_file(extract_dir, LLAMA_CPP_EXECUTABLE_NAMES)
	if executable is None:
		raise RuntimeError(f"Downloaded llama.cpp, but no llama-server executable was found under {extract_dir}.")
	return executable


def download_gguf_model(option: GgufModelOption, local_ai_dir: pathlib.Path) -> pathlib.Path:
	try:
		from huggingface_hub import hf_hub_download
	except ImportError as exc:
		raise RuntimeError("Install huggingface_hub to download GGUF models for llama.cpp.") from exc
	model_dir = local_ai_dir / "models"
	model_dir.mkdir(parents=True, exist_ok=True)
	return pathlib.Path(hf_hub_download(repo_id=option.repo, filename=option.filename, local_dir=str(model_dir)))


def configure_local_ai_runtime(args: argparse.Namespace, resources: SystemResources) -> InferenceConfig:
	local_ai_dir = _prompt_local_ai_dir(args)
	executable = _find_local_file(local_ai_dir, LLAMA_CPP_EXECUTABLE_NAMES)
	if executable is None:
		if args.NO_PULL:
			raise RuntimeError(f"No llama.cpp server executable was found in {local_ai_dir}, and --NO_PULL was supplied.")
		if not _confirm(f"No llama.cpp server was found in {local_ai_dir}. Download llama.cpp now?", args):
			raise RuntimeError("Local setup requires llama.cpp, Ollama, or a remote API endpoint.")
		executable = download_llama_cpp_engine(local_ai_dir, args.DEBUG)

	gguf_path = pathlib.Path(args.GGUF_MODEL_PATH).expanduser() if args.GGUF_MODEL_PATH else _find_local_gguf(local_ai_dir)
	if gguf_path is None:
		if args.NO_PULL:
			raise RuntimeError(f"No GGUF model was found in {local_ai_dir}, and --NO_PULL was supplied.")
		model_option = recommend_gguf_model(resources)
		if not _confirm(f"No GGUF model was found in {local_ai_dir}. Download {model_option.label} model {model_option.filename}?", args):
			raise RuntimeError("Local setup requires a GGUF model file.")
		gguf_path = download_gguf_model(model_option, local_ai_dir)
	elif not gguf_path.exists():
		raise FileNotFoundError(f"GGUF model does not exist: {gguf_path}")

	args.START_LLAMA_SERVER = True
	args.LLAMA_CPP_SERVER_CMD = str(executable)
	args.GGUF_MODEL_PATH = str(gguf_path)
	return InferenceConfig(backend="llama_cpp", model=args.MODEL or "local-gguf")


def choose_local_model(args: argparse.Namespace, resources: SystemResources) -> InferenceConfig:
	if args.BACKEND in {"auto", "remote"}:
		return configure_local_ai_runtime(args, resources)
	else:
		backend = args.BACKEND
	if backend == "llama_cpp":
		if args.LOCAL_AI_DIR or args.GGUF_MODEL_PATH or args.HF_GGUF_REPO or args.HF_GGUF_FILE or args.START_LLAMA_SERVER:
			return configure_local_ai_runtime(args, resources)
		return InferenceConfig(backend="llama_cpp", model=args.MODEL or "local-gguf")
	if args.MODEL:
		return InferenceConfig(backend=backend, model=args.MODEL)

	recommended = recommend_model(resources, backend)
	if args.NO_CONFIRM:
		return InferenceConfig(backend=recommended.backend, model=recommended.model)

	print("\nAvailable local model choices:")
	for index, option in enumerate(MODEL_CATALOG, start=1):
		marker = " (recommended)" if option == recommended else ""
		print(f"  {index}. {option.label}: {option.model} [{option.profile}]{marker}")
		print(f"     {option.description}")
	selection = input(f"Choose a model [default {recommended.key}]: ").strip()
	if not selection:
		return InferenceConfig(backend=recommended.backend, model=recommended.model)
	if selection.isdigit() and 1 <= int(selection) <= len(MODEL_CATALOG):
		option = MODEL_CATALOG[int(selection) - 1]
		return InferenceConfig(backend=option.backend, model=option.model)
	for option in MODEL_CATALOG:
		if selection.lower() in {option.key.lower(), option.model.lower()}:
			return InferenceConfig(backend=option.backend, model=option.model)
	return InferenceConfig(backend=backend, model=selection)


def choose_inference(args: argparse.Namespace, resources: SystemResources) -> InferenceConfig:
	remote_config = remote_api_defaults(args)
	if args.BACKEND == "remote":
		if args.NO_CONFIRM and not _has_remote_api(remote_config):
			raise ValueError("--BACKEND remote requires API URL and API key from arguments or environment when --NO_CONFIRM is supplied.")
		return remote_config if _has_remote_api(remote_config) else _prompt_remote_api(remote_config)
	if args.BACKEND in {"ollama", "llama_cpp"}:
		return choose_local_model(args, resources)
	if args.NO_CONFIRM:
		return remote_config if _has_remote_api(remote_config) else choose_local_model(args, resources)
	if _has_remote_api(remote_config):
		return remote_config

	default_choice = "1" if _has_remote_api(remote_config) else "2"
	print("\nInference setup:")
	print("  1. Use existing API key and remote/OpenAI-compatible AI URL")
	print(f"  2. {_local_setup_label()}")
	selection = input(f"Choose inference setup [default {default_choice}]: ").strip() or default_choice
	if selection == "1":
		return remote_config if _has_remote_api(remote_config) else _prompt_remote_api(remote_config)
	if selection == "2":
		return choose_local_model(args, resources)
	raise ValueError("Choose 1 for an existing API endpoint or 2 for local LLM setup.")


def resolve_sqlite_path(args: argparse.Namespace) -> str:
	if args.SQLITE_IN:
		return str(pathlib.Path(args.SQLITE_IN))
	if args.SQLITE_OUT:
		return str(pathlib.Path(args.SQLITE_OUT))
	output_dir = pathlib.Path(args.OUT_DIR) if args.OUT_DIR else pathlib.Path.cwd()
	stem = pathlib.Path(args.SRUM_INFILE or "SRUDB").stem or "SRUDB"
	timestamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
	return str(output_dir / f"{stem}-agent-{timestamp}.sqlite3")


def prepare_sqlite(args: argparse.Namespace) -> str:
	srum_mcp_query = _load_srum_mcp_query()
	if args.SQLITE_IN:
		path = pathlib.Path(args.SQLITE_IN)
		if not path.exists():
			raise FileNotFoundError(f"SQLite input does not exist: {path}")
		srum_mcp_query._CURRENT_SQLITE_PATH = str(path)
		return str(path)
	if not args.SRUM_INFILE:
		raise ValueError("--SRUM_INFILE is required unless --SQLITE_IN is supplied.")
	sqlite_path = resolve_sqlite_path(args)
	print(f"Converting SRUM to SQLite: {sqlite_path}")
	return srum_mcp_query.SRUM_to_SQLITE3(
		args.SRUM_INFILE,
		sqlite_path,
		registry_path=args.REG_HIVE,
		engine=args.ESE_ENGINE,
		overwrite=args.OVERWRITE,
	)


def _run_command(command: list[str], debug: bool = False) -> subprocess.CompletedProcess[str]:
	if debug:
		print("Running:", " ".join(command))
	return subprocess.run(command, capture_output=True, check=False, text=True)


def _ollama_models(debug: bool = False) -> set[str]:
	if shutil.which("ollama") is None:
		return set()
	result = _run_command(["ollama", "list"], debug)
	if result.returncode != 0:
		return set()
	models: set[str] = set()
	for line in result.stdout.splitlines()[1:]:
		parts = line.split()
		if parts:
			models.add(parts[0])
	return models


def prepare_ollama_model(model: str, no_pull: bool, debug: bool = False) -> None:
	if shutil.which("ollama") is None:
		raise RuntimeError("Ollama executable was not found on PATH. Install Ollama or use --BACKEND llama_cpp.")
	installed = _ollama_models(debug)
	if model in installed:
		return
	if no_pull:
		raise RuntimeError(f"Ollama model '{model}' is not installed and --NO_PULL was supplied.")
	print(f"Pulling Ollama model: {model}")
	result = _run_command(["ollama", "pull", model], debug)
	if result.returncode != 0:
		raise RuntimeError(result.stderr.strip() or f"ollama pull failed for {model}")


def resolve_gguf_model(args: argparse.Namespace) -> str | None:
	if args.GGUF_MODEL_PATH:
		path = pathlib.Path(args.GGUF_MODEL_PATH)
		if not path.exists():
			raise FileNotFoundError(f"GGUF model does not exist: {path}")
		return str(path)
	if bool(args.HF_GGUF_REPO) != bool(args.HF_GGUF_FILE):
		raise ValueError("--HF_GGUF_REPO and --HF_GGUF_FILE must be supplied together.")
	if not args.HF_GGUF_REPO:
		return None
	if args.NO_PULL:
		raise RuntimeError("A Hugging Face GGUF model was requested, but --NO_PULL was supplied.")
	try:
		from huggingface_hub import hf_hub_download
	except ImportError as exc:
		raise RuntimeError("Install huggingface_hub to download GGUF models for llama.cpp.") from exc
	return hf_hub_download(repo_id=args.HF_GGUF_REPO, filename=args.HF_GGUF_FILE)


def _llama_cpp_port(base_url: str) -> str:
	parsed = urllib.parse.urlparse(base_url)
	return str(parsed.port or 8080)


def _wait_for_llama_server(base_url: str, timeout_seconds: float = 20.0) -> None:
	models_url = base_url.rstrip("/") + "/models"
	deadline = time.monotonic() + timeout_seconds
	last_error: Exception | None = None
	while time.monotonic() < deadline:
		try:
			with urllib.request.urlopen(models_url, timeout=1):
				return
		except Exception as exc:
			last_error = exc
			time.sleep(0.25)
	raise RuntimeError(f"llama.cpp server did not become ready at {models_url}: {last_error}")


def maybe_start_llama_cpp_server(args: argparse.Namespace) -> None:
	if not args.START_LLAMA_SERVER:
		return
	gguf_path = resolve_gguf_model(args)
	if not gguf_path:
		raise ValueError("--START_LLAMA_SERVER requires --GGUF_MODEL_PATH or --HF_GGUF_REPO/--HF_GGUF_FILE.")
	server_cmd = shutil.which(args.LLAMA_CPP_SERVER_CMD) or args.LLAMA_CPP_SERVER_CMD
	command = [server_cmd, "--model", gguf_path, "--port", _llama_cpp_port(args.LLAMA_CPP_URL)]
	if args.DEBUG:
		print("Starting llama.cpp server:", " ".join(command))
	process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	_MANAGED_PROCESSES.append(process)
	_wait_for_llama_server(args.LLAMA_CPP_URL)


def build_chat_model(config: InferenceConfig, args: argparse.Namespace) -> Any:
	if config.backend == "remote":
		if not config.api_url or not config.api_key:
			raise ValueError("Remote API backend requires an API URL and API key.")
		return ChatOpenAI(model=config.model, base_url=config.api_url, api_key=config.api_key)
	if config.backend == "ollama":
		prepare_ollama_model(config.model, args.NO_PULL, args.DEBUG)
		return ChatOllama(model=config.model, base_url=args.OLLAMA_URL)
	if config.backend == "llama_cpp":
		maybe_start_llama_cpp_server(args)
		if shutil.which(args.LLAMA_CPP_SERVER_CMD) is None and not args.START_LLAMA_SERVER:
			print("llama-server was not found on PATH; assuming an OpenAI-compatible llama.cpp server is already running.")
		return ChatOpenAI(model=config.model, base_url=args.LLAMA_CPP_URL, api_key=args.LLAMA_CPP_API_KEY)
	raise ValueError(f"Unsupported backend: {config.backend}")


def stop_managed_processes() -> None:
	while _MANAGED_PROCESSES:
		process = _MANAGED_PROCESSES.pop()
		if process.poll() is None:
			process.terminate()


def _tool_result(value: Any) -> str:
	return json.dumps(value, default=str, ensure_ascii=False)[:12000]


def _message_content_text(message: Any) -> str:
	content = getattr(message, "content", "")
	if isinstance(content, str):
		return content.strip()
	if isinstance(content, list):
		parts: list[str] = []
		for item in content:
			if isinstance(item, str):
				parts.append(item)
			elif isinstance(item, dict):
				text = item.get("text") or item.get("content")
				if isinstance(text, str):
					parts.append(text)
		return "\n".join(part.strip() for part in parts if part and part.strip()).strip()
	return str(content).strip() if content is not None else ""


def _looks_like_date_coverage_question(query: str) -> bool:
	lowered = query.lower()
	return any(word in lowered for word in ("date", "dates", "time", "times", "range")) and any(
		phrase in lowered for phrase in ("represented", "covered", "coverage", "in the srum", "in srum", "earliest", "latest")
	)


def _quote_sqlite_identifier(identifier: str) -> str:
	return '"' + identifier.replace('"', '""') + '"'


def _looks_like_timestamp_column(source_column: str, sqlite_column: str) -> bool:
	source = source_column.lower()
	sqlite_name = sqlite_column.lower()
	return (
		"timestamp" in source
		or "timestamp" in sqlite_name
		or source in {"starttime", "endtime", "connectstarttime", "eventtimestamp"}
		or sqlite_name in {"starttime", "endtime", "connectstarttime", "eventtimestamp"}
		or source.endswith("date")
		or sqlite_name.endswith("date")
	)


def _date_coverage_fallback(tools_by_name: dict[str, AgentTool]) -> str | None:
	schema_tool = tools_by_name.get("explain_database_schema")
	query_tool = tools_by_name.get("query_database_read_only")
	if schema_tool is None or query_tool is None:
		return None
	schema = schema_tool.callable(include_columns=True)
	results: list[dict[str, Any]] = []
	for table in schema.get("tables", []):
		columns = table.get("columns") or []
		time_columns: list[str] = []
		for column in columns:
			source = str(column.get("source_column") or "")
			sqlite_column = str(column.get("resolved_column") or column.get("sqlite_column") or "")
			if sqlite_column and _looks_like_timestamp_column(source, sqlite_column):
				time_columns.append(sqlite_column)
		for column_name in dict.fromkeys(time_columns):
			quoted_table = _quote_sqlite_identifier(str(table["sqlite_name"]))
			quoted_column = _quote_sqlite_identifier(column_name)
			try:
				coverage = query_tool.callable(
					sql=(
						f"SELECT MIN({quoted_column}) AS earliest, MAX({quoted_column}) AS latest, "
						f"COUNT({quoted_column}) AS populated_rows FROM {quoted_table} "
						f"WHERE {quoted_column} IS NOT NULL"
					),
					limit=1,
				)
			except Exception:
				continue
			rows = coverage.get("rows") or []
			if not rows:
				continue
			row = rows[0]
			if row.get("earliest") is None and row.get("latest") is None:
				continue
			results.append(
				{
					"display_name": table.get("display_name"),
					"column": column_name,
					"earliest": row.get("earliest"),
					"latest": row.get("latest"),
					"populated_rows": row.get("populated_rows"),
				}
			)
	if not results:
		return None
	global_earliest = min(str(row["earliest"]) for row in results if row.get("earliest") is not None)
	global_latest = max(str(row["latest"]) for row in results if row.get("latest") is not None)
	lines = [f"SRUM date coverage appears to run from {global_earliest} through {global_latest}.", "", "By table:"]
	for row in results[:20]:
		lines.append(
			f"- {row['display_name']} ({row['column']}): {row['earliest']} to {row['latest']} "
			f"across {row['populated_rows']} populated rows"
		)
	if len(results) > 20:
		lines.append(f"- ...and {len(results) - 20} more timestamp columns.")
	return "\n".join(lines)


def _local_fallback_answer(user_query: str, tools_by_name: dict[str, AgentTool]) -> str | None:
	if _looks_like_date_coverage_question(user_query):
		return _date_coverage_fallback(tools_by_name)
	return None


def create_agent_tools(sqlite_path: str) -> list[AgentTool]:
	srum_mcp_query = _load_srum_mcp_query()

	def bind(func: Callable[..., Any]) -> Callable[..., Any]:
		def wrapper(**kwargs: Any) -> Any:
			kwargs["sqlite_path"] = sqlite_path
			return func(**kwargs)

		return wrapper

	return [
		AgentTool(
			"query_processes_running_in_time_range",
			"Return Application Resource Usage rows. Optional start_time/end_time default to all dates.",
			bind(srum_mcp_query.query_processes_running_in_time_range),
		),
		AgentTool(
			"query_processes_by_user_in_time_range",
			"Preferred tool for questions like 'what processes did USER run in TIME RANGE'. Returns Application Resource Usage rows for a user. Optional start_time/end_time default to all dates.",
			bind(srum_mcp_query.query_processes_by_user_in_time_range),
		),
		AgentTool(
			"query_process_summary_by_user_in_time_range",
			"Preferred tool for 'top/most processes run by USER' questions. Summarizes process/application activity for a user. Optional start_time/end_time default to all dates.",
			bind(srum_mcp_query.query_process_summary_by_user_in_time_range),
		),
		AgentTool(
			"query_files_accessed_in_time_range",
			"Return VFU file activity rows. Optional start_time/end_time default to all dates.",
			bind(srum_mcp_query.query_files_accessed_in_time_range),
		),
		AgentTool(
			"query_files_by_user_in_time_range",
			"Preferred tool for questions like 'what files did USER open/access in TIME RANGE'. Returns VFU file activity rows for a user. Optional start_time/end_time default to all dates.",
			bind(srum_mcp_query.query_files_by_user_in_time_range),
		),
		AgentTool(
			"query_file_summary_by_user_in_time_range",
			"Preferred tool for 'top/most files opened/accessed by USER' questions. Summarizes file activity for a user. Optional start_time/end_time default to all dates.",
			bind(srum_mcp_query.query_file_summary_by_user_in_time_range),
		),
		AgentTool(
			"query_network_connections_in_time_range",
			"Return Network Connectivity Usage rows. Optional start_time/end_time default to all dates.",
			bind(srum_mcp_query.query_network_connections_in_time_range),
		),
		AgentTool(
			"query_pid_artifacts",
			"Return rows from all SRUM tables containing the specified pid.",
			bind(srum_mcp_query.query_pid_artifacts),
		),
		AgentTool(
			"query_top_processes_by_cpu_usage",
			"Return top process rows by CPU cycles for start_time, end_time, and optional top_n.",
			bind(srum_mcp_query.query_top_processes_by_cpu_usage),
		),
		AgentTool(
			"query_top_network_connections_by_bytes_transferred",
			"Return top network data rows by bytes for start_time, end_time, and optional top_n.",
			bind(srum_mcp_query.query_top_network_connections_by_bytes_transferred),
		),
		AgentTool(
			"query_wifi_connections_in_time_range",
			"Return Wi-Fi connection rows between start_time and end_time strings.",
			bind(srum_mcp_query.query_wifi_connections_in_time_range),
		),
		AgentTool(
			"query_wifi_connection_artifacts_in_time_range",
			"Return network rows matching wifi_connection text within a time range.",
			bind(srum_mcp_query.query_wifi_connection_artifacts_in_time_range),
		),
		AgentTool(
			"query_database_read_only",
			"Fallback tool. Run one read-only SELECT/WITH SQL query only when purpose-built MCP tools cannot answer the question or schema/date coverage inspection requires SQL.",
			bind(srum_mcp_query.query_database_read_only),
		),
		AgentTool(
			"explain_database_schema",
			"Describe SRUM SQLite tables, row counts, columns, and table contents.",
			bind(srum_mcp_query.explain_database_schema),
		),
	]


def _langchain_tool(tool: AgentTool) -> Any:
	return StructuredTool.from_function(func=tool.callable, name=tool.name, description=tool.description)


def bind_tools(llm: Any, tools: list[AgentTool]) -> tuple[Any, dict[str, AgentTool]]:
	if not hasattr(llm, "bind_tools"):
		raise RuntimeError("The selected LangChain chat model does not support bind_tools().")
	return llm.bind_tools([_langchain_tool(tool) for tool in tools]), {tool.name: tool for tool in tools}


def _status_tool_args(args: dict[str, Any]) -> str:
	text = json.dumps(args, default=str, ensure_ascii=False)
	return text if len(text) <= 1000 else text[:997] + "..."


def run_tool_call_loop(
	llm_with_tools: Any,
	tools_by_name: dict[str, AgentTool],
	user_query: str,
	messages: list[Any],
	status_callback: Callable[[str], None] | None = None,
	continue_callback: Callable[[int], bool] | None = None,
) -> str:
	if not messages:
		messages.append(SystemMessage(content=SYSTEM_PROMPT))
		messages.append(SystemMessage(content=load_srum_expert_context()))
	messages.append(HumanMessage(content=user_query))

	last_response: Any = None
	empty_response_count = 0
	round_limit = TOOL_ITERATION_LIMIT
	total_rounds = 0
	while True:
		for _ in range(round_limit):
			total_rounds += 1
			if status_callback:
				status_callback("Calling AI model...")
			last_response = llm_with_tools.invoke(messages)
			messages.append(last_response)
			tool_calls = getattr(last_response, "tool_calls", None) or []
			if not tool_calls:
				content = _message_content_text(last_response)
				if content:
					return content
				empty_response_count += 1
				if empty_response_count == 1:
					messages.append(
						HumanMessage(
							content=(
								"Your previous assistant message was empty. Answer the user's SRUM question now. "
								"If the answer depends on database facts, call explain_database_schema or "
								"query_database_read_only before producing the final response."
							)
						)
					)
					continue
				fallback = _local_fallback_answer(user_query, tools_by_name)
				if fallback:
					return fallback
				metadata = getattr(last_response, "response_metadata", None) or getattr(last_response, "additional_kwargs", None) or {}
				raise RuntimeError(f"The selected model returned an empty response with no tool calls. Metadata: {metadata}")
			for call in tool_calls:
				name = call.get("name")
				args = call.get("args") or {}
				if status_callback:
					status_callback(f"Calling tool {name or 'unknown'} with arguments {_status_tool_args(args)}")
				tool = tools_by_name.get(name)
				if tool is None:
					content = f"Unknown tool: {name}"
				else:
					try:
						content = _tool_result(tool.callable(**args))
					except Exception as exc:
						content = f"Tool {name} failed: {exc}"
				if status_callback:
					status_callback(f"Tool {name or 'unknown'} completed.")
				messages.append(ToolMessage(content=content, tool_call_id=call.get("id", name or "tool")))
		content = _message_content_text(last_response)
		if content:
			return content
		fallback = _local_fallback_answer(user_query, tools_by_name)
		if fallback:
			return fallback
		if continue_callback and continue_callback(total_rounds):
			if status_callback:
				status_callback(f"Continuing for {TOOL_CONTINUATION_LIMIT} more tool rounds...")
			round_limit = TOOL_CONTINUATION_LIMIT
			continue
		break
	content = _message_content_text(last_response)
	if content:
		return content
	fallback = _local_fallback_answer(user_query, tools_by_name)
	if fallback:
		return fallback
	return (
		"Agent stopped before producing a final answer because the model reached the tool-call iteration limit. "
		"Try asking a narrower question, specifying a user/time range/table, or ask the agent to summarize the tool results already retrieved."
	)


def interactive_loop(llm_with_tools: Any, tools_by_name: dict[str, AgentTool]) -> None:
	messages: list[Any] = []
	print("\nAsk SRUM questions. Type 'quit' or 'exit' to stop.")

	def ask_continue(rounds_completed: int) -> bool:
		answer = input(
			f"The agent has used {rounds_completed} tool rounds without a final answer. Continue for {TOOL_CONTINUATION_LIMIT} more rounds? [y/N] "
		).strip().lower()
		return answer in {"y", "yes"}

	while True:
		try:
			query = input("Ask SRUM > ").strip()
		except (EOFError, KeyboardInterrupt):
			print()
			break
		if query.lower() in {"quit", "exit"}:
			break
		if not query:
			continue
		try:
			answer = run_tool_call_loop(llm_with_tools, tools_by_name, query, messages, print, ask_continue).strip()
			print(answer or "Agent error: the selected model returned an empty response with no explanation.")
		except Exception as exc:
			print(f"Agent error: {exc}")


def main(argv: Sequence[str] | None = None) -> int:
	args = parse_args(argv)
	try:
		resources = collect_system_resources(args.SQLITE_IN)
		inference = choose_inference(args, resources)
		print(f"Using backend={inference.backend}, model={inference.model}")
		llm = build_chat_model(inference, args)
		sqlite_path = prepare_sqlite(args)
		tools = create_agent_tools(sqlite_path)
		print(f"Using sqlite={sqlite_path}")
		llm_with_tools, tools_by_name = bind_tools(llm, tools)
		interactive_loop(llm_with_tools, tools_by_name)
		return 0
	except Exception as exc:
		print(f"srum-agent error: {exc}", file=sys.stderr)
		return 1
	finally:
		stop_managed_processes()


if __name__ == "__main__":
	raise SystemExit(main())


