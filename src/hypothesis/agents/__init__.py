"""Agent-driven vulnerability analysis with CEGIS verification.

Tools:
  - Analyst: Fixed-temperature hypothesis generation + revision
  - CodeGen: Flask mock generation with compile retry
  - TestRunner: Mock server management + T1-T4 testing
  - RuleGen: Suricata rule generation with RAG + validation

Runner:
  - Per-trace CEGIS loop controller
"""

from .analyst_tool import Analyst
from .codegen_tool import CodeGen
from .test_tool import TestRunner
from .rule_agent import RuleGenAgent

__all__ = [
    "Analyst",
    "CodeGen",
    "TestRunner",
    "RuleGenAgent",
    "Runner",
]


def __getattr__(name):
    if name == "Runner":
        from .runner import Runner
        return Runner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
