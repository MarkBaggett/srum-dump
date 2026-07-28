import importlib.util
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


class FakeStructuredTool:
    @classmethod
    def from_function(cls, func, name, description):
        return {"func": func, "name": name, "description": description}


def install_fake_langchain_modules():
    langchain_core = types.ModuleType("langchain_core")
    messages = types.ModuleType("langchain_core.messages")
    messages.HumanMessage = FakeMessage
    messages.SystemMessage = FakeMessage
    messages.ToolMessage = FakeMessage
    tools = types.ModuleType("langchain_core.tools")
    tools.StructuredTool = FakeStructuredTool
    ollama = types.ModuleType("langchain_ollama")
    ollama.ChatOllama = mock.Mock(name="ChatOllama")
    openai = types.ModuleType("langchain_openai")
    openai.ChatOpenAI = mock.Mock(name="ChatOpenAI")
    sys.modules.update(
        {
            "langchain_core": langchain_core,
            "langchain_core.messages": messages,
            "langchain_core.tools": tools,
            "langchain_ollama": ollama,
            "langchain_openai": openai,
        }
    )


def load_agent_module():
    install_fake_langchain_modules()
    path = pathlib.Path(__file__).with_name("srum-agent.py")
    spec = importlib.util.spec_from_file_location("srum_agent", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["srum_agent"] = module
    spec.loader.exec_module(module)
    return module


class FakeMessage:
    def __init__(self, content="", tool_call_id=None):
        self.content = content
        self.tool_call_id = tool_call_id


class FakeResponse:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class FakeToolCallingModel:
    def __init__(self):
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        if self.calls == 1:
            return FakeResponse(
                tool_calls=[
                    {
                        "id": "call-1",
                        "name": "query_pid_artifacts",
                        "args": {"pid": 4242},
                    }
                ]
            )
        return FakeResponse("pid results summarized")


class FakeEmptyThenAnswerModel:
    def __init__(self):
        self.calls = 0
        self.messages = []

    def invoke(self, messages):
        self.calls += 1
        self.messages = list(messages)
        if self.calls == 1:
            return FakeResponse("")
        return FakeResponse("Recovered answer")


class FakeAlwaysEmptyModel:
    def invoke(self, messages):
        response = FakeResponse("")
        response.response_metadata = {"finish_reason": "stop"}
        return response


class FakeEndlessToolModel:
    def invoke(self, messages):
        return FakeResponse(tool_calls=[{"id": "call-loop", "name": "loop_tool", "args": {}}])


class FakeToolLimitThenAnswerModel:
    def __init__(self, tool_calls_before_answer):
        self.tool_calls_before_answer = tool_calls_before_answer
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        if self.calls <= self.tool_calls_before_answer:
            return FakeResponse(tool_calls=[{"id": f"call-{self.calls}", "name": "loop_tool", "args": {"round": self.calls}}])
        return FakeResponse("continued answer")


class SrumAgentTests(unittest.TestCase):
    def setUp(self):
        self.agent = load_agent_module()

    def test_parse_args_accepts_srum_dump_and_agent_flags(self):
        args = self.agent.parse_args(
            [
                "-i",
                "SRUDB.dat",
                "-o",
                "out",
                "-r",
                "SOFTWARE",
                "-e",
                "dissect",
                "-q",
                "--SQLITE_OUT",
                "srum.sqlite3",
                "--MODEL",
                "llama3.2:3b",
                "--BACKEND",
                "ollama",
                "--LOCAL_AI_DIR",
                "local-ai",
                "--NO_PULL",
            ]
        )

        self.assertEqual("SRUDB.dat", args.SRUM_INFILE)
        self.assertEqual("out", args.OUT_DIR)
        self.assertEqual("SOFTWARE", args.REG_HIVE)
        self.assertEqual("srum.sqlite3", args.SQLITE_OUT)
        self.assertEqual("llama3.2:3b", args.MODEL)
        self.assertEqual("local-ai", args.LOCAL_AI_DIR)
        self.assertTrue(args.NO_CONFIRM)
        self.assertTrue(args.NO_PULL)

    def test_recommend_model_uses_available_ram(self):
        low = self.agent.SystemResources(cpu_count=4, ram_gb=7, database_size_gb=1)
        high = self.agent.SystemResources(cpu_count=16, ram_gb=32, database_size_gb=1)

        self.assertEqual("quick", self.agent.recommend_model(low, "auto").key)
        self.assertEqual("deep", self.agent.recommend_model(high, "auto").key)

    def test_choose_inference_uses_env_remote_with_no_confirm(self):
        args = self.agent.parse_args(["--SQLITE_IN", "srum.sqlite3", "--NO_CONFIRM"])
        resources = self.agent.SystemResources(cpu_count=4, ram_gb=8, database_size_gb=None)

        with mock.patch.dict(
            "os.environ",
            {
                "SRUM_AGENT_API_URL": "https://ai.example/v1",
                "SRUM_AGENT_API_KEY": "test-key",
                "SRUM_AGENT_MODEL": "case-model",
            },
        ):
            config = self.agent.choose_inference(args, resources)

        self.assertEqual("remote", config.backend)
        self.assertEqual("https://ai.example/v1", config.api_url)
        self.assertEqual("test-key", config.api_key)
        self.assertEqual("case-model", config.model)

    def test_choose_inference_auto_uses_complete_remote_config_without_prompt(self):
        args = self.agent.parse_args(
            ["--SQLITE_IN", "srum.sqlite3", "--API_URL", "https://ai.example/v1", "--API_MODEL", "case-model"]
        )
        resources = self.agent.SystemResources(cpu_count=4, ram_gb=8, database_size_gb=None)

        with mock.patch.dict("os.environ", {"SRUM_AGENT_API_KEY": "test-key"}), \
            mock.patch("builtins.input", side_effect=AssertionError("choose_inference should not prompt")):
            config = self.agent.choose_inference(args, resources)

        self.assertEqual("remote", config.backend)
        self.assertEqual("https://ai.example/v1", config.api_url)
        self.assertEqual("test-key", config.api_key)
        self.assertEqual("case-model", config.model)

    def test_choose_local_model_auto_uses_local_ai_directory(self):
        resources = self.agent.SystemResources(cpu_count=4, ram_gb=8, database_size_gb=None)
        with tempfile.TemporaryDirectory() as temp_dir:
            local_ai_dir = pathlib.Path(temp_dir)
            server_path = local_ai_dir / "llama-server.exe"
            model_path = local_ai_dir / "models" / "case.gguf"
            server_path.write_bytes(b"server")
            model_path.parent.mkdir()
            model_path.write_bytes(b"gguf")
            args = self.agent.parse_args(["--SQLITE_IN", "srum.sqlite3", "--LOCAL_AI_DIR", str(local_ai_dir)])

            with mock.patch("builtins.input", side_effect=AssertionError("local directory setup should not prompt when runtime and model exist")), \
                mock.patch.object(self.agent.shutil, "which", return_value="ollama"):
                config = self.agent.choose_local_model(args, resources)

        self.assertEqual("llama_cpp", config.backend)
        self.assertEqual("local-gguf", config.model)
        self.assertTrue(args.START_LLAMA_SERVER)
        self.assertEqual(str(server_path), args.LLAMA_CPP_SERVER_CMD)
        self.assertEqual(str(model_path), args.GGUF_MODEL_PATH)

    def test_choose_local_model_auto_bootstraps_empty_local_ai_directory(self):
        resources = self.agent.SystemResources(cpu_count=4, ram_gb=8, database_size_gb=None)
        with tempfile.TemporaryDirectory() as temp_dir:
            local_ai_dir = pathlib.Path(temp_dir)
            server_path = local_ai_dir / "llama.cpp" / "llama-server.exe"
            model_path = local_ai_dir / "models" / "case.gguf"
            args = self.agent.parse_args(["--SQLITE_IN", "srum.sqlite3", "--LOCAL_AI_DIR", str(local_ai_dir)])

            with mock.patch.object(self.agent, "_confirm", return_value=True) as confirm, \
                mock.patch.object(self.agent, "download_llama_cpp_engine", return_value=server_path) as download_engine, \
                mock.patch.object(self.agent, "download_gguf_model", return_value=model_path) as download_model:
                config = self.agent.choose_local_model(args, resources)

        self.assertEqual("llama_cpp", config.backend)
        self.assertEqual(2, confirm.call_count)
        download_engine.assert_called_once_with(local_ai_dir, False)
        download_model.assert_called_once()
        self.assertTrue(args.START_LLAMA_SERVER)
        self.assertEqual(str(server_path), args.LLAMA_CPP_SERVER_CMD)
        self.assertEqual(str(model_path), args.GGUF_MODEL_PATH)

    def test_choose_local_model_explicit_ollama_keeps_ollama_catalog(self):
        resources = self.agent.SystemResources(cpu_count=4, ram_gb=8, database_size_gb=None)
        args = self.agent.parse_args(["--SQLITE_IN", "srum.sqlite3", "--BACKEND", "ollama", "--NO_CONFIRM"])

        with mock.patch.object(self.agent, "configure_local_ai_runtime", side_effect=AssertionError("explicit Ollama should not use local directory setup")):
            config = self.agent.choose_local_model(args, resources)

        self.assertEqual("ollama", config.backend)
        self.assertEqual("llama3.2:3b", config.model)

    def test_main_sets_up_inference_before_sqlite_conversion(self):
        events = []
        fake_config = self.agent.InferenceConfig(backend="remote", model="case-model", api_url="https://ai.example/v1", api_key="test-key")
        fake_llm = mock.Mock()
        fake_llm.bind_tools.return_value = FakeToolCallingModel()

        with mock.patch.object(self.agent, "choose_inference", side_effect=lambda *args: events.append("choose") or fake_config), \
            mock.patch.object(self.agent, "build_chat_model", side_effect=lambda *args: events.append("build") or fake_llm), \
            mock.patch.object(self.agent, "prepare_sqlite", side_effect=lambda *args: events.append("convert") or "case.sqlite3"), \
            mock.patch.object(self.agent, "create_agent_tools", return_value=[]), \
            mock.patch.object(self.agent, "interactive_loop", side_effect=lambda *args: events.append("interactive")):
            result = self.agent.main(["--SQLITE_IN", "case.sqlite3", "--NO_CONFIRM"])

        self.assertEqual(0, result)
        self.assertEqual(["choose", "build", "convert", "interactive"], events)

    def test_prepare_sqlite_calls_converter_with_registry_and_engine(self):
        calls = []
        fake_module = types.SimpleNamespace(
            SRUM_to_SQLITE3=lambda *args, **kwargs: calls.append((args, kwargs)) or "out.sqlite3"
        )
        args = self.agent.parse_args(
            [
                "-i",
                "SRUDB.dat",
                "--SQLITE_OUT",
                "out.sqlite3",
                "--REG_HIVE",
                "SOFTWARE",
                "--ESE_ENGINE",
                "pyesedb",
                "--OVERWRITE",
            ]
        )

        with mock.patch.object(self.agent, "_load_srum_mcp_query", return_value=fake_module):
            result = self.agent.prepare_sqlite(args)

        self.assertEqual("out.sqlite3", result)
        self.assertEqual(("SRUDB.dat", "out.sqlite3"), calls[0][0][:2])
        self.assertEqual("SOFTWARE", calls[0][1]["registry_path"])
        self.assertEqual("pyesedb", calls[0][1]["engine"])
        self.assertTrue(calls[0][1]["overwrite"])

    def test_prepare_sqlite_reuses_existing_sqlite_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sqlite_path = pathlib.Path(temp_dir) / "srum.sqlite3"
            sqlite_path.write_bytes(b"sqlite")
            fake_module = types.SimpleNamespace(_CURRENT_SQLITE_PATH=None)
            args = self.agent.parse_args(["--SQLITE_IN", str(sqlite_path)])

            with mock.patch.object(self.agent, "_load_srum_mcp_query", return_value=fake_module):
                result = self.agent.prepare_sqlite(args)

        self.assertEqual(str(sqlite_path), result)
        self.assertEqual(str(sqlite_path), fake_module._CURRENT_SQLITE_PATH)

    def test_agent_tools_inject_sqlite_path(self):
        captured = {}

        def fake_query_pid_artifacts(**kwargs):
            captured.update(kwargs)
            return {"ok": True}

        fake_module = types.SimpleNamespace(
            query_processes_running_in_time_range=lambda **kwargs: [],
            query_processes_by_user_in_time_range=lambda **kwargs: [],
            query_process_summary_by_user_in_time_range=lambda **kwargs: [],
            query_files_accessed_in_time_range=lambda **kwargs: [],
            query_files_by_user_in_time_range=lambda **kwargs: [],
            query_file_summary_by_user_in_time_range=lambda **kwargs: [],
            query_network_connections_in_time_range=lambda **kwargs: [],
            query_pid_artifacts=fake_query_pid_artifacts,
            query_top_processes_by_cpu_usage=lambda **kwargs: [],
            query_top_network_connections_by_bytes_transferred=lambda **kwargs: [],
            query_wifi_connections_in_time_range=lambda **kwargs: [],
            query_wifi_connection_artifacts_in_time_range=lambda **kwargs: [],
            query_database_read_only=lambda **kwargs: [],
            explain_database_schema=lambda **kwargs: {},
        )

        with mock.patch.object(self.agent, "_load_srum_mcp_query", return_value=fake_module):
            tools = {tool.name: tool for tool in self.agent.create_agent_tools("case.sqlite3")}

        self.assertEqual({"ok": True}, tools["query_pid_artifacts"].callable(pid=4242))
        self.assertEqual(4242, captured["pid"])
        self.assertEqual("case.sqlite3", captured["sqlite_path"])

    def test_tool_call_loop_executes_requested_tool(self):
        model = FakeToolCallingModel()
        tool = self.agent.AgentTool("query_pid_artifacts", "pid lookup", lambda **kwargs: {"pid": kwargs["pid"]})
        statuses = []

        result = self.agent.run_tool_call_loop(model, {tool.name: tool}, "show pid 4242", [], statuses.append)

        self.assertEqual("pid results summarized", result)
        self.assertEqual(2, model.calls)
        self.assertIn("Calling AI model...", statuses)
        self.assertIn('Calling tool query_pid_artifacts with arguments {"pid": 4242}', statuses)
        self.assertIn("Tool query_pid_artifacts completed.", statuses)

    def test_tool_call_loop_retries_empty_response(self):
        model = FakeEmptyThenAnswerModel()

        result = self.agent.run_tool_call_loop(model, {}, "what dates are represented?", [])

        self.assertEqual("Recovered answer", result)
        self.assertEqual(2, model.calls)
        self.assertIn("previous assistant message was empty", model.messages[-1].content)

    def test_tool_call_loop_loads_srum_expert_system_message(self):
        model = FakeEmptyThenAnswerModel()
        messages = []

        self.agent.run_tool_call_loop(model, {}, "what files matter?", messages)

        self.assertEqual(2, len(messages[:2]))
        self.assertIn("forensic SRUM analysis assistant", messages[0].content)
        self.assertIn("SRUM Expert Guidance", messages[1].content)

    def test_tool_call_loop_returns_nonblank_message_at_iteration_limit(self):
        tool = self.agent.AgentTool("loop_tool", "loop", lambda **kwargs: {"ok": True})

        result = self.agent.run_tool_call_loop(FakeEndlessToolModel(), {tool.name: tool}, "keep looping", [])

        self.assertIn("tool-call iteration limit", result)
        self.assertTrue(result.strip())

    def test_tool_call_loop_can_continue_after_iteration_limit(self):
        model = FakeToolLimitThenAnswerModel(self.agent.TOOL_ITERATION_LIMIT + 1)
        tool = self.agent.AgentTool("loop_tool", "loop", lambda **kwargs: {"ok": True})
        continue_prompts = []

        result = self.agent.run_tool_call_loop(
            model,
            {tool.name: tool},
            "keep going",
            [],
            continue_callback=lambda rounds: continue_prompts.append(rounds) or True,
        )

        self.assertEqual("continued answer", result)
        self.assertEqual([self.agent.TOOL_ITERATION_LIMIT], continue_prompts)
        self.assertEqual(self.agent.TOOL_ITERATION_LIMIT + 2, model.calls)

    def test_tool_call_loop_raises_after_repeated_empty_response(self):
        with self.assertRaisesRegex(RuntimeError, "empty response"):
            self.agent.run_tool_call_loop(FakeAlwaysEmptyModel(), {}, "what dates are represented?", [])

    def test_tool_call_loop_answers_date_coverage_after_repeated_empty_response(self):
        schema_tool = self.agent.AgentTool(
            "explain_database_schema",
            "schema",
            lambda **kwargs: {
                "tables": [
                    {
                        "display_name": "Application Resource Usage",
                        "sqlite_name": "application_resource_usage",
                        "columns": [
                            {"source_column": "TimeStamp", "sqlite_column": "timestamp"},
                            {"source_column": "ForegroundCycleTime", "sqlite_column": "foregroundcycletime"},
                        ],
                    }
                ]
            },
        )
        queries = []

        def fake_read_only_query(**kwargs):
            queries.append(kwargs["sql"])
            return {
                "rows": [
                    {
                        "earliest": "2026-07-28 12:00:00",
                        "latest": "2026-07-28 13:00:00",
                        "populated_rows": 3,
                    }
                ]
            }

        query_tool = self.agent.AgentTool("query_database_read_only", "sql", fake_read_only_query)

        result = self.agent.run_tool_call_loop(
            FakeAlwaysEmptyModel(),
            {schema_tool.name: schema_tool, query_tool.name: query_tool},
            "what are the dates represented in the srum?",
            [],
        )

        self.assertIn("2026-07-28 12:00:00 through 2026-07-28 13:00:00", result)
        self.assertIn("Application Resource Usage", result)
        self.assertEqual(1, len(queries))
        self.assertNotIn("foregroundcycletime", queries[0])

    def test_message_content_text_extracts_structured_blocks(self):
        message = FakeResponse([{"type": "text", "text": "first"}, {"content": "second"}])

        self.assertEqual("first\nsecond", self.agent._message_content_text(message))

    def test_resolve_gguf_model_uses_existing_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = pathlib.Path(temp_dir) / "model.gguf"
            model_path.write_bytes(b"gguf")
            args = self.agent.parse_args(["--SQLITE_IN", "srum.sqlite3", "--GGUF_MODEL_PATH", str(model_path)])

            self.assertEqual(str(model_path), self.agent.resolve_gguf_model(args))

    def test_resolve_gguf_model_downloads_with_huggingface_hub(self):
        args = self.agent.parse_args(
            [
                "--SQLITE_IN",
                "srum.sqlite3",
                "--HF_GGUF_REPO",
                "example/repo",
                "--HF_GGUF_FILE",
                "model.gguf",
            ]
        )
        fake_hub = types.ModuleType("huggingface_hub")
        fake_hub.hf_hub_download = mock.Mock(return_value="downloaded.gguf")

        with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hub}):
            result = self.agent.resolve_gguf_model(args)

        self.assertEqual("downloaded.gguf", result)
        fake_hub.hf_hub_download.assert_called_once_with(repo_id="example/repo", filename="model.gguf")

    def test_resolve_gguf_model_requires_repo_and_file_together(self):
        args = self.agent.parse_args(["--SQLITE_IN", "srum.sqlite3", "--HF_GGUF_REPO", "example/repo"])

        with self.assertRaises(ValueError):
            self.agent.resolve_gguf_model(args)


if __name__ == "__main__":
    unittest.main()