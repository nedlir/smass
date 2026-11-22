import sys
import types
from dataclasses import replace

from smass.agents.base import _build_chat
from smass.config import load


def _fake_chat_module(mod_name: str, class_name: str, captured: dict):
    mod = types.ModuleType(mod_name)

    class _Fake:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    setattr(mod, class_name, _Fake)
    return mod


def test_build_chat_anthropic_direct(cfg, monkeypatch):
    captured = {}
    monkeypatch.setitem(
        sys.modules, "langchain_anthropic",
        _fake_chat_module("langchain_anthropic", "ChatAnthropic", captured),
    )
    _build_chat(cfg, "claude-opus-5-5")
    assert captured["model"] == "claude-opus-5-5"
    assert captured["api_key"] == "test-key"
    assert "base_url" not in captured  # no proxy configured


def test_build_chat_anthropic_proxy(cfg, monkeypatch):
    captured = {}
    monkeypatch.setitem(
        sys.modules, "langchain_anthropic",
        _fake_chat_module("langchain_anthropic", "ChatAnthropic", captured),
    )
    c = replace(cfg, llm_base_url="http://localhost:8317")
    _build_chat(c, "claude-opus-5-5")
    assert captured["base_url"] == "http://localhost:8317"


def test_build_chat_openai_proxy(cfg, monkeypatch):
    captured = {}
    monkeypatch.setitem(
        sys.modules, "langchain_openai",
        _fake_chat_module("langchain_openai", "ChatOpenAI", captured),
    )
    c = replace(cfg, llm_base_url="http://localhost:4000", llm_api="openai")
    _build_chat(c, "claude-opus-5-5")
    assert captured["base_url"] == "http://localhost:4000"
    assert captured["model"] == "claude-opus-5-5"


def test_run_llm_requires_an_api_key(cfg):
    from smass.agents.base import run_llm

    import pytest

    c = replace(cfg, llm_api_key="")
    with pytest.raises(RuntimeError, match="LLM API key"):
        run_llm(c, "m", "s", "u")


def test_load_reads_key_and_endpoint():
    cfg = load({"SMASS_LLM_API_KEY": "k", "SMASS_LLM_BASE_URL": "http://p:1",
                "SMASS_LLM_API": "openai"})
    assert cfg.llm_api_key == "k"
    assert cfg.llm_base_url == "http://p:1"
    assert cfg.llm_api == "openai"


def test_load_key_falls_back_to_anthropic_env():
    assert load({"ANTHROPIC_API_KEY": "a"}).llm_api_key == "a"


def test_load_defaults():
    cfg = load({})
    assert cfg.llm_base_url is None
    assert cfg.llm_api == "anthropic"
    assert cfg.llm_api_key == ""
