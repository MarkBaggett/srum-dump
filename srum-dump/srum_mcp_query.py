"""FastMCP tools and callable helpers for converting SRUM ESE data to SQLite.

The converter intentionally reuses the existing SRUM-DUMP database wrappers and
helper lookups. Those wrappers own ESE type conversion, SID/AppId resolution
inputs, and registry-derived enrichment, so this module treats them as the
authoritative extraction boundary and only handles SQLite schema/write logic.
"""

from __future__ import annotations

import codecs
import ctypes
import datetime as _dt
import os
import pathlib
import re
import sqlite3
import struct
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import closing
from typing import Any

import helpers

try:
	from fastmcp import FastMCP
except Exception:  # pragma: no cover - exercised only when dependency is absent
	FastMCP = None


class _NoOpMCP:
	"""Small compatibility shim so tests/scripts can import without FastMCP."""

	def tool(self, func=None, *args, **kwargs):
		def decorator(target):
			return target

		return decorator(func) if func is not None else decorator

	def run(self):
		raise RuntimeError("fastmcp is not installed. Install requirements.txt to run the MCP server.")


class InMemoryConfig:
	"""ConfigManager-compatible store used by the converter.

	The existing database wrappers call ``get_config`` for lookup dictionaries.
	Using this small in-memory object avoids writing a temporary config file
	while preserving the contract that ``db_dissect`` and ``db_ese`` expect.
	"""

	def __init__(self, initial: Mapping[str, Any] | None = None):
		self.data = dict(initial or {})

	def set_config(self, name: str, config: Any) -> None:
		self.data[name] = config

	def get_config(self, name: str) -> Any:
		return self.data.get(name, {})

	def delete_config(self, name: str) -> None:
		self.data.pop(name, None)

	def save(self) -> None:
		return None

	def load(self) -> None:
		return None


mcp = FastMCP("srum-dump") if FastMCP is not None else _NoOpMCP()
_CURRENT_SQLITE_PATH: str | None = None
READ_ONLY_SQL_DENYLIST = re.compile(
	r"\b(attach|alter|create|delete|detach|drop|insert|pragma|reindex|replace|update|vacuum)\b",
	re.IGNORECASE,
)


def sqlite_identifier(value: str, fallback: str = "srum_table") -> str:
	"""Return a stable SQLite-safe identifier for SRUM table/column names.

	Friendly SRUM table names and registry-derived names are useful for humans
	but can contain spaces, braces, or punctuation. This helper normalizes them
	while leaving reversibility to the metadata tables.
	"""

	identifier = re.sub(r"\W+", "_", str(value).strip()).strip("_").lower()
	if not identifier:
		identifier = fallback
	if identifier[0].isdigit():
		identifier = f"_{identifier}"
	return identifier


def quote_identifier(identifier: str) -> str:
	"""Quote a SQLite identifier after escaping embedded quotes."""

	return '"' + identifier.replace('"', '""') + '"'


def infer_sqlite_type(values: Iterable[Any]) -> str:
	"""Infer a SQLite affinity from observed wrapper values."""

	for value in values:
		if value in (None, "", "Empty"):
			continue
		if isinstance(value, bool):
			return "INTEGER"
		if isinstance(value, int):
			return "INTEGER"
		if isinstance(value, float):
			return "REAL"
		if isinstance(value, (_dt.datetime, _dt.date)):
			return "TEXT"
		if isinstance(value, (bytes, bytearray, memoryview)):
			return "BLOB"
		return "TEXT"
	return "TEXT"


def normalize_sqlite_value(value: Any) -> Any:
	"""Convert wrapper values into values SQLite can persist predictably."""

	if value == "Empty":
		return None
	if isinstance(value, _dt.datetime):
		return value.isoformat(sep=" ")
	if isinstance(value, _dt.date):
		return value.isoformat()
	if isinstance(value, bytes):
		return value
	if isinstance(value, bytearray):
		return bytes(value)
	if isinstance(value, memoryview):
		return value.tobytes()
	return value


def build_column_markups(config: InMemoryConfig, table_guid: str, table_name: str) -> dict[str, dict[str, Any]]:
	"""Merge default, friendly-name, and GUID-specific column markups.

	This mirrors ``srum_dump.py`` so registry-derived friendly names and GUID
	overrides continue to control translations consistently across outputs.
	"""

	column_markups = config.get_config("column_markups") or {}
	all_table_markups = column_markups.get("All Tables", {})
	table_specific_markups = column_markups.get(table_name, {})
	table_specific_guid_markups = column_markups.get(table_guid, {})
	merged: dict[str, dict[str, Any]] = {}
	all_columns = set(all_table_markups) | set(table_specific_markups) | set(table_specific_guid_markups)
	for column in all_columns:
		column_attrs = dict(all_table_markups.get(column, {}))
		column_attrs.update(table_specific_markups.get(column, {}))
		column_attrs.update(table_specific_guid_markups.get(column, {}))
		merged[column] = column_attrs
	return merged


def translate_record_value(value: Any, translation: str | None, config: InMemoryConfig) -> Any:
	"""Translate a raw wrapper value with SRUM-DUMP helper lookups.

	``APPID`` and ``SID`` use the SRUDbIdMapTable loaded by the ESE wrapper.
	Network/interface translations use registry-derived maps when available.
	Timestamp translations delegate to ``helpers`` so future wrapper changes are
	shared by CSV/XLSX and SQLite outputs.
	"""

	if not translation or value in (None, "", "Empty"):
		return None
	if translation in {"APPID", "SID"}:
		return config.get_config("SRUDbIdMapTable").get(str(value), "")
	if translation == "OLE":
		return helpers.ole_timestamp(value)
	if translation == "seconds":
		try:
			return float(value) / 86400.0
		except (TypeError, ValueError):
			return value
	if translation.startswith("FILE:"):
		return helpers.file_timestamp(value)
	if translation == "network_interface":
		return config.get_config("network_interfaces").get(str(value), value)
	if translation == "interface_types":
		try:
			interface_type = struct.unpack(">H6B", codecs.decode(format(int(value), "016x"), "hex"))[0]
		except Exception:
			return value
		interface_types = config.get_config("interface_types")
		return interface_types.get(str(interface_type), interface_types.get(interface_type, interface_type))
	return value


def prepare_table_schema(
	table_guid: str,
	table_name: str,
	column_names: list[str],
	markups: Mapping[str, Mapping[str, Any]],
	existing_names: set[str] | None = None,
) -> dict[str, Any]:
	"""Build SQLite table and column metadata for a SRUM table.

	Raw columns are always preserved. Columns with configured translations get
	an additional ``*_resolved`` column containing helper-derived values.
	Excel-only formula markups are recorded in metadata but are not emitted as
	forensic facts unless they are represented by normal translated values.
	"""

	existing_names = existing_names if existing_names is not None else set()
	base_name = sqlite_identifier(table_name or table_guid)
	sqlite_name = base_name
	suffix = 2
	while sqlite_name in existing_names:
		sqlite_name = f"{base_name}_{suffix}"
		suffix += 1
	existing_names.add(sqlite_name)

	used_columns: set[str] = set()
	columns: list[dict[str, Any]] = []
	for source_column in column_names:
		base_column = sqlite_identifier(source_column, "column")
		sqlite_column = base_column
		suffix = 2
		while sqlite_column in used_columns:
			sqlite_column = f"{base_column}_{suffix}"
			suffix += 1
		used_columns.add(sqlite_column)
		markup = dict(markups.get(source_column, {}))
		columns.append(
			{
				"source_column": source_column,
				"sqlite_column": sqlite_column,
				"friendly_name": markup.get("friendly_name", source_column),
				"translate": markup.get("translate"),
				"formula": markup.get("formula"),
				"sqlite_type": "TEXT",
				"resolved_column": None,
			}
		)
		if markup.get("translate"):
			resolved_base = sqlite_identifier(f"{source_column}_resolved", "resolved")
			resolved_column = resolved_base
			suffix = 2
			while resolved_column in used_columns:
				resolved_column = f"{resolved_base}_{suffix}"
				suffix += 1
			used_columns.add(resolved_column)
			columns[-1]["resolved_column"] = resolved_column

	return {
		"table_guid": table_guid,
		"display_name": table_name,
		"sqlite_name": sqlite_name,
		"columns": columns,
	}


def iter_enriched_rows(records: Iterable[Any], schema: Mapping[str, Any], config: InMemoryConfig) -> Iterator[tuple[Any, ...]]:
	"""Yield raw and enriched SQLite rows from wrapper records."""

	columns = schema["columns"]
	for record in records:
		row: list[Any] = []
		for column in columns:
			raw_value = record.value(column["source_column"])
			row.append(normalize_sqlite_value(raw_value))
			if column["resolved_column"]:
				translated = translate_record_value(raw_value, column["translate"], config)
				row.append(normalize_sqlite_value(translated))
		yield tuple(row)


def write_table_batches(
	conn: sqlite3.Connection,
	schema: Mapping[str, Any],
	rows: Iterable[tuple[Any, ...]],
	batch_size: int = 1000,
) -> int:
	"""Create a SRUM table and write row batches through one SQLite writer."""

	sqlite_columns: list[tuple[str, str]] = []
	for column in schema["columns"]:
		sqlite_columns.append((column["sqlite_column"], column["sqlite_type"]))
		if column["resolved_column"]:
			sqlite_columns.append((column["resolved_column"], "TEXT"))

	column_sql = ", ".join(f"{quote_identifier(name)} {column_type}" for name, column_type in sqlite_columns)
	conn.execute(f"CREATE TABLE {quote_identifier(schema['sqlite_name'])} ({column_sql})")
	placeholders = ", ".join("?" for _ in sqlite_columns)
	insert_sql = f"INSERT INTO {quote_identifier(schema['sqlite_name'])} VALUES ({placeholders})"

	total_rows = 0
	batch: list[tuple[Any, ...]] = []
	for row in rows:
		batch.append(row)
		if len(batch) >= batch_size:
			conn.executemany(insert_sql, batch)
			total_rows += len(batch)
			batch.clear()
	if batch:
		conn.executemany(insert_sql, batch)
		total_rows += len(batch)
	return total_rows


def _bootstrap_config(registry_path: str | None = None) -> InMemoryConfig:
	config = InMemoryConfig(
		{
			"dirty_words": dict(helpers.dirty_words),
			"known_tables": dict(helpers.known_tables),
			"known_sids": dict(helpers.known_sids),
			"network_interfaces": {},
			"skip_tables": list(helpers.skip_tables),
			"interface_types": dict(helpers.interface_types),
			"column_markups": dict(helpers.column_markups),
		}
	)
	if registry_path:
		network_interfaces = helpers.load_interfaces(registry_path)
		registry_sids = helpers.load_registry_sids(registry_path)
		srum_table_names = helpers.load_srum_table_names(registry_path)
		if srum_table_names:
			known_tables = dict(config.get_config("known_tables"))
			known_tables.update(srum_table_names)
			config.set_config("known_tables", known_tables)
		if network_interfaces:
			config.set_config("network_interfaces", network_interfaces)
		if registry_sids:
			known_sids = dict(config.get_config("known_sids"))
			known_sids.update(registry_sids)
			config.set_config("known_sids", known_sids)
	return config


def _is_admin() -> bool:
	try:
		return ctypes.windll.shell32.IsUserAnAdmin() == 1
	except Exception:
		return False


def _is_live_windows_srum(path: pathlib.Path) -> bool:
	system_root = os.environ.get("SystemRoot")
	if not system_root:
		return False
	try:
		return pathlib.Path(system_root).resolve() in path.resolve().parents
	except OSError:
		return False


def _resolve_live_paths(srum_path: str, sqlite_path: str | None) -> tuple[pathlib.Path, str | None, tempfile.TemporaryDirectory[str] | None]:
	original_path = pathlib.Path(srum_path)
	if not _is_live_windows_srum(original_path):
		return original_path, None, None
	if not _is_admin():
		raise PermissionError(
			"The selected SRUM database is under SystemRoot and is locked by Windows. "
			"Run as administrator so VSS extraction can copy SRUDB.dat and SOFTWARE, "
			"or provide an offline SRUM database path."
		)

	destination = pathlib.Path(sqlite_path).parent if sqlite_path else None
	temp_dir: tempfile.TemporaryDirectory[str] | None = None
	if destination is None:
		temp_dir = tempfile.TemporaryDirectory(prefix="srum_sqlite_")
		destination = pathlib.Path(temp_dir.name)
	destination.mkdir(parents=True, exist_ok=True)

	import copy_locked

	if not copy_locked.copy_locked_files(destination):
		if temp_dir is not None:
			temp_dir.cleanup()
		raise RuntimeError(f"VSS extraction failed while copying SRUDB.dat and SOFTWARE to {destination}")

	copied_srum = destination / "SRUDB.dat"
	if not copied_srum.exists():
		copied_srum = destination / "srudb.dat"
	copied_registry = destination / "SOFTWARE"
	return copied_srum, str(copied_registry) if copied_registry.exists() else None, temp_dir


def _load_database_class(engine: str):
	if engine == "pyesedb":
		from db_ese import srum_database
	elif engine == "dissect":
		from db_dissect import srum_database
	else:
		raise ValueError("engine must be 'dissect' or 'pyesedb'")
	return srum_database


def _create_metadata_tables(conn: sqlite3.Connection) -> None:
	conn.executescript(
		"""
		CREATE TABLE srum_tables (
			table_guid TEXT PRIMARY KEY,
			display_name TEXT NOT NULL,
			sqlite_name TEXT NOT NULL UNIQUE,
			row_count INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE srum_columns (
			table_guid TEXT NOT NULL,
			source_column TEXT NOT NULL,
			sqlite_column TEXT NOT NULL,
			friendly_name TEXT,
			translate TEXT,
			resolved_column TEXT,
			formula TEXT,
			PRIMARY KEY (table_guid, source_column)
		);
		CREATE TABLE srum_id_map (
			id_index TEXT PRIMARY KEY,
			resolved_value TEXT
		);
		CREATE TABLE srum_network_interfaces (
			interface_id TEXT PRIMARY KEY,
			interface_name TEXT
		);
		CREATE TABLE srum_interface_types (
			interface_type TEXT PRIMARY KEY,
			description TEXT
		);
		CREATE TABLE srum_conversion_info (
			key TEXT PRIMARY KEY,
			value TEXT
		);
		"""
	)


def _write_metadata(conn: sqlite3.Connection, schema: Mapping[str, Any], row_count: int) -> None:
	conn.execute(
		"INSERT INTO srum_tables(table_guid, display_name, sqlite_name, row_count) VALUES (?, ?, ?, ?)",
		(schema["table_guid"], schema["display_name"], schema["sqlite_name"], row_count),
	)
	conn.executemany(
		"""
		INSERT INTO srum_columns(table_guid, source_column, sqlite_column, friendly_name, translate, resolved_column, formula)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		""",
		[
			(
				schema["table_guid"],
				column["source_column"],
				column["sqlite_column"],
				column["friendly_name"],
				column["translate"],
				column["resolved_column"],
				column["formula"],
			)
			for column in schema["columns"]
		],
	)


def _initialize_sqlite(path: pathlib.Path, overwrite: bool) -> sqlite3.Connection:
	if path.exists():
		if not overwrite:
			raise FileExistsError(f"SQLite output already exists: {path}")
		path.unlink()
	path.parent.mkdir(parents=True, exist_ok=True)
	conn = sqlite3.connect(str(path))
	conn.execute("PRAGMA journal_mode=OFF")
	conn.execute("PRAGMA synchronous=OFF")
	conn.execute("PRAGMA temp_store=MEMORY")
	conn.execute("PRAGMA locking_mode=EXCLUSIVE")
	return conn


def _default_sqlite_path(srum_path: pathlib.Path) -> pathlib.Path:
	timestamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
	stem = srum_path.stem or "SRUDB"
	return pathlib.Path.cwd() / f"{stem}-{timestamp}.sqlite3"


@mcp.tool
def SRUM_to_SQLITE3(
	srum_path: str,
	sqlite_path: str | None = None,
	registry_path: str | None = None,
	engine: str = "dissect",
	workers: int | None = None,
	overwrite: bool = False,
) -> str:
	"""Convert a SRUM ESE database into an enriched SQLite database.

	Args:
		srum_path: Path to an offline SRUDB.dat, or the live Windows SRUM path.
		sqlite_path: Output SQLite path. Defaults to a timestamped file in cwd.
		registry_path: Optional offline SOFTWARE hive for SID, network profile,
			interface, and SRUM table-name enrichment.
		engine: Existing ESE wrapper to use: ``dissect`` by default or ``pyesedb``.
		workers: Reserved for future multiprocessing. The current implementation
			keeps one SQLite writer to avoid write-lock contention.
		overwrite: Replace an existing SQLite output when true.

	Returns:
		The created SQLite database path.

	When ``srum_path`` points under ``%SystemRoot%``, Windows keeps the database
	locked. In that case this function requires administrator rights and calls
	``copy_locked.copy_locked_files`` so both SRUDB.dat and SOFTWARE are copied
	through VSS before conversion.
	"""

	del workers
	global _CURRENT_SQLITE_PATH

	effective_srum, copied_registry, temp_dir = _resolve_live_paths(srum_path, sqlite_path)
	effective_registry = copied_registry or registry_path
	output_path = pathlib.Path(sqlite_path) if sqlite_path else _default_sqlite_path(effective_srum)
	config = _bootstrap_config(effective_registry)
	database_class = _load_database_class(engine)
	ese_db = database_class(str(effective_srum), config)
	try:
		config.set_config("SRUDbIdMapTable", dict(getattr(ese_db, "id_lookup", {})))
		known_tables = config.get_config("known_tables") or {}
		skip_tables = set(config.get_config("skip_tables") or helpers.skip_tables)
		table_names = [table for table in ese_db.get_tables() if table not in skip_tables]

		conn = _initialize_sqlite(output_path, overwrite)
		try:
			_create_metadata_tables(conn)
			conn.executemany(
				"INSERT INTO srum_id_map(id_index, resolved_value) VALUES (?, ?)",
				sorted((str(key), str(value)) for key, value in config.get_config("SRUDbIdMapTable").items()),
			)
			conn.executemany(
				"INSERT INTO srum_network_interfaces(interface_id, interface_name) VALUES (?, ?)",
				sorted((str(key), str(value)) for key, value in (config.get_config("network_interfaces") or {}).items()),
			)
			conn.executemany(
				"INSERT INTO srum_interface_types(interface_type, description) VALUES (?, ?)",
				sorted((str(key), str(value)) for key, value in (config.get_config("interface_types") or {}).items()),
			)

			used_table_names: set[str] = set()
			total_rows = 0
			for table_guid in table_names:
				table_object = ese_db.get_table(table_guid)
				if table_object is None:
					continue
				display_name = known_tables.get(table_guid, table_guid)
				column_names = list(table_object.column_names)
				markups = build_column_markups(config, table_guid, display_name)
				schema = prepare_table_schema(table_guid, display_name, column_names, markups, used_table_names)
				row_count = write_table_batches(conn, schema, iter_enriched_rows(ese_db.get_records(table_guid), schema, config))
				_write_metadata(conn, schema, row_count)
				total_rows += row_count

			conn.executemany(
				"INSERT INTO srum_conversion_info(key, value) VALUES (?, ?)",
				[
					("source_srum_path", str(pathlib.Path(srum_path))),
					("effective_srum_path", str(effective_srum)),
					("registry_path", str(effective_registry or "")),
					("engine", engine),
					("converted_at_utc", _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")),
					("total_rows", str(total_rows)),
					("schema", "raw_tables_with_enriched_columns"),
				],
			)
			conn.commit()
		finally:
			conn.close()
	finally:
		close = getattr(ese_db, "close", None)
		if callable(close):
			close()
		if temp_dir is not None:
			temp_dir.cleanup()

	_CURRENT_SQLITE_PATH = str(output_path)
	return str(output_path)


def _connect_query_db(sqlite_path: str | None = None) -> sqlite3.Connection:
	path = sqlite_path or _CURRENT_SQLITE_PATH
	if not path:
		raise RuntimeError("SRUM_to_SQLITE3 has not run and no SQLite path was provided.")
	conn = sqlite3.connect(path)
	conn.row_factory = sqlite3.Row
	return conn


def _connect_read_only_db(sqlite_path: str | None = None) -> sqlite3.Connection:
	path_value = sqlite_path or _CURRENT_SQLITE_PATH
	if not path_value:
		raise RuntimeError("SRUM_to_SQLITE3 has not run and no SQLite path was provided.")
	path = pathlib.Path(path_value)
	if not path:
		raise RuntimeError("SRUM_to_SQLITE3 has not run and no SQLite path was provided.")
	if not path.exists():
		raise FileNotFoundError(f"SQLite database does not exist: {path}")
	conn = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
	conn.row_factory = sqlite3.Row
	conn.execute("PRAGMA query_only = ON")
	return conn


def _strip_sql_comments(sql: str) -> str:
	sql = re.sub(r"--.*?(?=\r?\n|$)", " ", sql)
	return re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)


def _validate_read_only_sql(sql: str) -> str:
	cleaned = _strip_sql_comments(sql).strip()
	if not cleaned:
		raise ValueError("SQL query is empty.")
	if ";" in cleaned.rstrip(";"):
		raise ValueError("Only one SQL statement is allowed.")
	statement = cleaned.rstrip("; ")
	if not re.match(r"^(select|with)\b", statement, flags=re.IGNORECASE):
		raise ValueError("Only SELECT or WITH read-only queries are allowed.")
	if READ_ONLY_SQL_DENYLIST.search(statement):
		raise ValueError("SQL contains a keyword that is not allowed in read-only queries.")
	return statement


def _normalize_query_parameters(parameters: Any) -> Any:
	if parameters is None:
		return ()
	if isinstance(parameters, (list, tuple, dict)):
		return parameters
	raise TypeError("parameters must be a list, tuple, dict, or None.")


@mcp.tool
def query_database_read_only(
	sql: str,
	parameters: list[Any] | dict[str, Any] | None = None,
	limit: int = 500,
	sqlite_path: str | None = None,
) -> dict[str, Any]:
	"""Run one read-only SELECT/WITH query against the SRUM SQLite database.

	The database is opened in SQLite read-only mode and ``PRAGMA query_only`` is
	enabled. Mutating statements and multi-statement SQL are rejected before
	execution. A LIMIT is appended when the query does not already specify one.
	"""

	if limit < 1 or limit > 5000:
		raise ValueError("limit must be between 1 and 5000.")
	statement = _validate_read_only_sql(sql)
	if not re.search(r"\blimit\b", statement, flags=re.IGNORECASE):
		statement = f"SELECT * FROM ({statement}) LIMIT ?"
		parameters = [*_normalize_query_parameters(parameters), limit] if not isinstance(parameters, dict) else {**parameters, "_srum_limit": limit}
		if isinstance(parameters, dict):
			statement = statement[:-1] + ":_srum_limit"
	else:
		parameters = _normalize_query_parameters(parameters)
	with closing(_connect_read_only_db(sqlite_path)) as conn:
		rows = conn.execute(statement, parameters).fetchall()
	return {"sql": statement, "row_count": len(rows), "rows": [dict(row) for row in rows]}


def _describe_srum_table(display_name: str, sqlite_name: str, column_names: Iterable[str]) -> str:
	haystack = f"{display_name} {sqlite_name} {' '.join(column_names)}".lower()
	if "application" in haystack and "resource" in haystack:
		return "Per-application resource usage, including process identifiers, app/user resolution, timestamps, and CPU cycle counters."
	if "network" in haystack and "connectivity" in haystack:
		return "Network connectivity events such as connection timing, profile/interface identifiers, and resolved network context where available."
	if "network" in haystack and "data" in haystack:
		return "Per-application network byte counters, including sent/received totals and resolved application/profile identifiers where available."
	if "vfu" in haystack or "file" in haystack:
		return "Volume/file usage activity, including file-related identifiers, timestamps, and resolved values where configured."
	if "energy" in haystack:
		return "Energy and battery-related SRUM measurements captured by Windows."
	return "SRUM table converted from the ESE database with raw columns and any configured resolved companion columns."


@mcp.tool
def explain_database_schema(sqlite_path: str | None = None, include_columns: bool = True) -> dict[str, Any]:
	"""Describe the SRUM SQLite schema, table purposes, row counts, and columns."""

	with closing(_connect_read_only_db(sqlite_path)) as conn:
		database_list = [dict(row) for row in conn.execute("PRAGMA database_list").fetchall()]
		schema_tables = conn.execute(
			"SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
		).fetchall()
		metadata_rows = {
			row["sqlite_name"]: row
			for row in conn.execute("SELECT table_guid, display_name, sqlite_name, row_count FROM srum_tables").fetchall()
		}
		column_metadata: dict[str, list[sqlite3.Row]] = {}
		for row in conn.execute("SELECT * FROM srum_columns ORDER BY table_guid, source_column").fetchall():
			column_metadata.setdefault(row["table_guid"], []).append(row)

		tables: list[dict[str, Any]] = []
		for table in schema_tables:
			metadata = metadata_rows.get(table["name"])
			pragma_columns = [dict(row) for row in conn.execute(f"PRAGMA table_info({quote_identifier(table['name'])})").fetchall()]
			description = "SRUM metadata table used by the converter and query tools."
			columns: list[dict[str, Any]] = []
			if metadata:
				metadata_columns = column_metadata.get(metadata["table_guid"], [])
				description = _describe_srum_table(
					metadata["display_name"],
					metadata["sqlite_name"],
					[column["source_column"] for column in metadata_columns],
				)
				if include_columns:
					columns = [
						{
							"source_column": column["source_column"],
							"sqlite_column": column["sqlite_column"],
							"friendly_name": column["friendly_name"],
							"translate": column["translate"],
							"resolved_column": column["resolved_column"],
							"formula": column["formula"],
						}
						for column in metadata_columns
					]
			elif include_columns:
				columns = [{"sqlite_column": column["name"], "sqlite_type": column["type"]} for column in pragma_columns]

			tables.append(
				{
					"table_guid": metadata["table_guid"] if metadata else None,
					"display_name": metadata["display_name"] if metadata else table["name"],
					"sqlite_name": table["name"],
					"row_count": metadata["row_count"] if metadata else None,
					"description": description,
					"create_sql": table["sql"],
					"columns": columns,
				}
			)
	return {"database": database_list, "table_count": len(tables), "tables": tables}


def _find_table(conn: sqlite3.Connection, *needles: str) -> sqlite3.Row | None:
	rows = conn.execute("SELECT * FROM srum_tables").fetchall()
	lowered = [needle.lower() for needle in needles]
	for row in rows:
		haystack = f"{row['table_guid']} {row['display_name']} {row['sqlite_name']}".lower()
		if all(needle in haystack for needle in lowered):
			return row
	return None


def _columns_for(conn: sqlite3.Connection, table_guid: str) -> list[sqlite3.Row]:
	return conn.execute("SELECT * FROM srum_columns WHERE table_guid = ?", (table_guid,)).fetchall()


def _pick_column(columns: list[sqlite3.Row], candidates: Iterable[str], prefer_resolved: bool = False) -> str | None:
	by_source = {row["source_column"].lower(): row for row in columns}
	for candidate in candidates:
		row = by_source.get(candidate.lower())
		if row:
			if prefer_resolved and row["resolved_column"]:
				return row["resolved_column"]
			return row["sqlite_column"]
	return None


def _row_value(row: Mapping[str, Any], candidates: Iterable[str]) -> Any:
	lowered = {key.lower(): key for key in row}
	for candidate in candidates:
		key = lowered.get(candidate.lower())
		if key and row.get(key) not in (None, ""):
			return row[key]
	return None


def _summarize_grouped_rows(
	rows: list[dict[str, Any]],
	group_candidates: Iterable[str],
	time_candidates: Iterable[str],
	app_candidates: Iterable[str] = ("appid_resolved", "appid", "AppId"),
	pid_candidates: Iterable[str] = ("processid", "ProcessId", "pid", "PID"),
	cpu_candidates: Iterable[str] = ("foregroundcycletime", "backgroundcycletime", "ForegroundCycleTime", "BackgroundCycleTime"),
	top_n: int = 25,
) -> list[dict[str, Any]]:
	groups: dict[str, dict[str, Any]] = {}
	for row in rows:
		group_value = _row_value(row, group_candidates)
		if group_value in (None, ""):
			group_value = "<unresolved>"
		group_key = str(group_value)
		entry = groups.setdefault(
			group_key,
			{
				"value": group_value,
				"row_count": 0,
				"first_seen": None,
				"last_seen": None,
				"applications": set(),
				"process_ids": set(),
				"cpu_total": 0,
			},
		)
		entry["row_count"] += 1
		timestamp = _row_value(row, time_candidates)
		if timestamp not in (None, ""):
			timestamp_text = str(timestamp)
			entry["first_seen"] = timestamp_text if entry["first_seen"] is None else min(entry["first_seen"], timestamp_text)
			entry["last_seen"] = timestamp_text if entry["last_seen"] is None else max(entry["last_seen"], timestamp_text)
		application = _row_value(row, app_candidates)
		if application not in (None, ""):
			entry["applications"].add(str(application))
		process_id = _row_value(row, pid_candidates)
		if process_id not in (None, ""):
			entry["process_ids"].add(str(process_id))
		for candidate in cpu_candidates:
			value = _row_value(row, [candidate])
			try:
				entry["cpu_total"] += int(value)
			except (TypeError, ValueError):
				continue

	results: list[dict[str, Any]] = []
	for entry in groups.values():
		results.append(
			{
				"value": entry["value"],
				"row_count": entry["row_count"],
				"first_seen": entry["first_seen"],
				"last_seen": entry["last_seen"],
				"applications": sorted(entry["applications"]),
				"process_ids": sorted(entry["process_ids"]),
				"cpu_total": entry["cpu_total"],
			}
		)
	return sorted(results, key=lambda row: (row["row_count"], row["cpu_total"]), reverse=True)[:top_n]


def _select_rows(
	conn: sqlite3.Connection,
	table_row: sqlite3.Row,
	start_time: str | None = None,
	end_time: str | None = None,
	limit: int = 500,
) -> list[dict[str, Any]]:
	columns = _columns_for(conn, table_row["table_guid"])
	time_column = _pick_column(columns, ["TimeStamp", "StartTime", "EventTimestamp", "ConnectStartTime", "EndTime"], True)
	sql = f"SELECT * FROM {quote_identifier(table_row['sqlite_name'])}"
	params: list[Any] = []
	clauses: list[str] = []
	if time_column and start_time:
		clauses.append(f"{quote_identifier(time_column)} >= ?")
		params.append(start_time)
	if time_column and end_time:
		clauses.append(f"{quote_identifier(time_column)} <= ?")
		params.append(end_time)
	if clauses:
		sql += " WHERE " + " AND ".join(clauses)
	if time_column:
		sql += f" ORDER BY {quote_identifier(time_column)}"
	sql += " LIMIT ?"
	params.append(limit)
	return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _select_rows_by_user(
	conn: sqlite3.Connection,
	table_row: sqlite3.Row,
	user: str,
	start_time: str | None = None,
	end_time: str | None = None,
	limit: int = 500,
) -> list[dict[str, Any]]:
	columns = _columns_for(conn, table_row["table_guid"])
	user_column = _pick_column(columns, ["UserId", "UserSID", "Sid"], True) or _pick_column(columns, ["UserId", "UserSID", "Sid"])
	time_column = _pick_column(columns, ["TimeStamp", "StartTime", "EventTimestamp", "ConnectStartTime", "EndTime"], True)
	if not user_column:
		return []
	sql = f"SELECT * FROM {quote_identifier(table_row['sqlite_name'])} WHERE CAST({quote_identifier(user_column)} AS TEXT) LIKE ?"
	params: list[Any] = [f"%{user}%"]
	if time_column and start_time:
		sql += f" AND {quote_identifier(time_column)} >= ?"
		params.append(start_time)
	if time_column and end_time:
		sql += f" AND {quote_identifier(time_column)} <= ?"
		params.append(end_time)
	if time_column:
		sql += f" ORDER BY {quote_identifier(time_column)}"
	sql += " LIMIT ?"
	params.append(limit)
	return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _query_named_table(needles: tuple[str, ...], start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	with closing(_connect_query_db(sqlite_path)) as conn:
		table_row = _find_table(conn, *needles)
		if table_row is None:
			return []
		return _select_rows(conn, table_row, start_time, end_time)


def _query_named_table_by_user(
	needles: tuple[str, ...],
	user: str,
	start_time: str | None = None,
	end_time: str | None = None,
	sqlite_path: str | None = None,
) -> list[dict[str, Any]]:
	with closing(_connect_query_db(sqlite_path)) as conn:
		table_row = _find_table(conn, *needles)
		if table_row is None:
			return []
		return _select_rows_by_user(conn, table_row, user, start_time, end_time)


@mcp.tool
def query_processes_running_in_time_range(start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return Application Resource Usage rows, optionally constrained by time range."""

	return _query_named_table(("application", "resource"), start_time, end_time, sqlite_path)


@mcp.tool
def query_processes_by_user_in_time_range(user: str, start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return Application Resource Usage rows for a user, optionally constrained by time range.

	``user`` may be a SID, account fragment, or any text contained in the resolved
	user column.
	"""

	return _query_named_table_by_user(("application", "resource"), user, start_time, end_time, sqlite_path)


@mcp.tool
def query_process_summary_by_user_in_time_range(
	user: str,
	start_time: str | None = None,
	end_time: str | None = None,
	top_n: int = 25,
	sqlite_path: str | None = None,
) -> list[dict[str, Any]]:
	"""Summarize processes/applications run by a user, optionally constrained by time range.

	Use this for investigator questions such as "what processes did this user run"
	or "what did this user run most" before falling back to direct SQL.
	"""

	rows = query_processes_by_user_in_time_range(user, start_time, end_time, sqlite_path)
	return _summarize_grouped_rows(
		rows,
		("appid_resolved", "AppId_resolved", "AppId", "appid"),
		("timestamp", "TimeStamp", "starttime", "StartTime", "endtime", "EndTime"),
		top_n=top_n,
	)


@mcp.tool
def query_files_accessed_in_time_range(start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return VFU file activity rows, optionally constrained by time range."""

	return _query_named_table(("vfu",), start_time, end_time, sqlite_path)


@mcp.tool
def query_files_by_user_in_time_range(user: str, start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return VFU file activity rows for a user, optionally constrained by time range.

	``user`` may be a SID, account fragment, or any text contained in the resolved
	user column.
	"""

	return _query_named_table_by_user(("vfu",), user, start_time, end_time, sqlite_path)


@mcp.tool
def query_file_summary_by_user_in_time_range(
	user: str,
	start_time: str | None = None,
	end_time: str | None = None,
	top_n: int = 25,
	sqlite_path: str | None = None,
) -> list[dict[str, Any]]:
	"""Summarize files accessed by a user, optionally constrained by time range.

	Use this for investigator questions such as "what files did this user open"
	or "what files did this user access most" before falling back to direct SQL.
	"""

	rows = query_files_by_user_in_time_range(user, start_time, end_time, sqlite_path)
	return _summarize_grouped_rows(
		rows,
		(
			"filename_resolved",
			"filepath_resolved",
			"path_resolved",
			"fileid_resolved",
			"FileName",
			"FilePath",
			"Path",
			"FileId",
			"fileid",
		),
		("timestamp", "TimeStamp", "starttime", "StartTime", "endtime", "EndTime"),
		top_n=top_n,
	)


@mcp.tool
def query_network_connections_in_time_range(start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return Network Connectivity Usage rows, optionally constrained by time range."""

	return _query_named_table(("network", "connectivity"), start_time, end_time, sqlite_path)


@mcp.tool
def query_pid_artifacts(pid: int | str, sqlite_path: str | None = None) -> dict[str, list[dict[str, Any]]]:
	"""Return rows from all tables that expose a ProcessId column matching ``pid``."""

	results: dict[str, list[dict[str, Any]]] = {}
	with closing(_connect_query_db(sqlite_path)) as conn:
		for table_row in conn.execute("SELECT * FROM srum_tables").fetchall():
			columns = _columns_for(conn, table_row["table_guid"])
			pid_column = _pick_column(columns, ["ProcessId", "PID"])
			if not pid_column:
				continue
			sql = f"SELECT * FROM {quote_identifier(table_row['sqlite_name'])} WHERE {quote_identifier(pid_column)} = ? LIMIT 500"
			rows = [dict(row) for row in conn.execute(sql, (pid,)).fetchall()]
			if rows:
				results[table_row["display_name"]] = rows
	return results


@mcp.tool
def query_top_processes_by_cpu_usage(start_time: str | None = None, end_time: str | None = None, top_n: int = 10, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return top Application Resource Usage rows by CPU cycle columns, optionally constrained by time range."""

	with closing(_connect_query_db(sqlite_path)) as conn:
		table_row = _find_table(conn, "application", "resource")
		if table_row is None:
			return []
		columns = _columns_for(conn, table_row["table_guid"])
		foreground = _pick_column(columns, ["ForegroundCycleTime"])
		background = _pick_column(columns, ["BackgroundCycleTime"])
		app_column = _pick_column(columns, ["AppId"], True) or _pick_column(columns, ["AppId"])
		time_column = _pick_column(columns, ["TimeStamp", "StartTime", "EndTime"], True)
		if not foreground and not background:
			return []
		cpu_expr = " + ".join(f"COALESCE({quote_identifier(col)}, 0)" for col in [foreground, background] if col)
		sql = f"SELECT {quote_identifier(app_column) if app_column else '*'}, ({cpu_expr}) AS cpu_total FROM {quote_identifier(table_row['sqlite_name'])}"
		params: list[Any] = []
		clauses: list[str] = []
		if time_column and start_time:
			clauses.append(f"{quote_identifier(time_column)} >= ?")
			params.append(start_time)
		if time_column and end_time:
			clauses.append(f"{quote_identifier(time_column)} <= ?")
			params.append(end_time)
		if clauses:
			sql += " WHERE " + " AND ".join(clauses)
		sql += " ORDER BY cpu_total DESC LIMIT ?"
		params.append(top_n)
		return [dict(row) for row in conn.execute(sql, params).fetchall()]


@mcp.tool
def query_top_network_connections_by_bytes_transferred(start_time: str | None = None, end_time: str | None = None, top_n: int = 10, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return top Network Data Usage rows by sent plus received bytes, optionally constrained by time range."""

	with closing(_connect_query_db(sqlite_path)) as conn:
		table_row = _find_table(conn, "network", "data")
		if table_row is None:
			return []
		columns = _columns_for(conn, table_row["table_guid"])
		sent = _pick_column(columns, ["BytesSent"])
		received = _pick_column(columns, ["BytesRecvd", "BytesReceived"])
		time_column = _pick_column(columns, ["TimeStamp", "StartTime", "EndTime"], True)
		if not sent and not received:
			return []
		byte_expr = " + ".join(f"COALESCE({quote_identifier(col)}, 0)" for col in [sent, received] if col)
		sql = f"SELECT *, ({byte_expr}) AS total_bytes FROM {quote_identifier(table_row['sqlite_name'])}"
		params: list[Any] = []
		clauses: list[str] = []
		if time_column and start_time:
			clauses.append(f"{quote_identifier(time_column)} >= ?")
			params.append(start_time)
		if time_column and end_time:
			clauses.append(f"{quote_identifier(time_column)} <= ?")
			params.append(end_time)
		if clauses:
			sql += " WHERE " + " AND ".join(clauses)
		sql += " ORDER BY total_bytes DESC LIMIT ?"
		params.append(top_n)
		return [dict(row) for row in conn.execute(sql, params).fetchall()]


@mcp.tool
def query_wifi_connections_in_time_range(start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return network connectivity rows, including resolved Wi-Fi profile values when present, optionally constrained by time range."""

	return query_network_connections_in_time_range(start_time, end_time, sqlite_path)


@mcp.tool
def query_wifi_connection_artifacts_in_time_range(wifi_connection: str, start_time: str | None = None, end_time: str | None = None, sqlite_path: str | None = None) -> list[dict[str, Any]]:
	"""Return network rows whose resolved profile/interface text matches ``wifi_connection``, optionally constrained by time range."""

	rows = query_network_connections_in_time_range(start_time, end_time, sqlite_path)
	needle = wifi_connection.lower()
	return [row for row in rows if any(needle in str(value).lower() for key, value in row.items() if "profile" in key.lower() or "interface" in key.lower())]


if __name__ == "__main__":
	mcp.run()
