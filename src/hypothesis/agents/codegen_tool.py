"""CodeGen tool: Deterministic mock server generation.

Responsibilities:
  - generate(): Produce mock server code via deterministic skeleton
  - Detection condition is the only LLM-generated part
  - Static verification (rejection sampling)
  - Compile check as safety net
"""

import logging
import ast
import re

from ..skeleton import ConditionGenerationFailed, generate_flask_from_skeleton
from ..temperature import TEMP_GENERATIVE

logger = logging.getLogger("codegen")


class CodeGen:

    def __init__(self):
        pass

    def generate(self, http_request: dict, analysis: dict,
                 counterexample: dict = None,
                 temperature: float = TEMP_GENERATIVE,
                 trace_response: dict = None,
                 blackboard: dict = None) -> dict:
        """Generate mock server code.

        The skeleton handles:
          1. Deterministic request parsing
          2. LLM detection condition generation
          3. Static verification (rejection sampling)
          4. Template assembly + compile check
        """
        logger.info("CodeGen: generating mock (temp=%.2f)", temperature)

        try:
            code = generate_flask_from_skeleton(
                http_request, analysis, counterexample,
                temperature=TEMP_GENERATIVE,
                trace_response=trace_response,
                blackboard=blackboard)
        except ConditionGenerationFailed as e:
            logger.error("CodeGen: condition generation failed: %s", e)
            return {
                "success": False,
                "flask_code": None,
                "error": f"condition_generation: {e}",
                "condition_generation_failed": True,
                "rejection_reasons": e.rejection_reasons,
            }
        except Exception as e:
            logger.error("CodeGen: generation failed: %s", e)
            return {"success": False, "flask_code": None, "error": f"generation: {e}"}

        try:
            compile(code, "<mock>", "exec")
        except SyntaxError as e:
            lines = code.splitlines()
            start = max(0, (e.lineno or 1) - 3)
            end = min(len(lines), (e.lineno or 1) + 2)
            snippet = "\n".join(lines[start:end])
            error_msg = f"SyntaxError at line {e.lineno}: {e.msg}\n{snippet}"
            logger.error("CodeGen: compile failed: %s", error_msg)
            return {
                "success": False,
                "flask_code": code,
                "error": error_msg,
                "compile_error": True,
            }

        return {
            "success": True,
            "flask_code": code,
            "error": None,
            "identified_param": self._extract_constant(code, "PARAM_NAME"),
            "attack_value": self._extract_constant(code, "ATTACK_VALUE"),
        }

    @staticmethod
    def _extract_constant(code: str, name: str):
        m = re.search(rf"(?m)^{re.escape(name)}\s*=\s*(.+)$", code)
        if not m:
            return None
        try:
            return ast.literal_eval(m.group(1).strip())
        except Exception:
            return None
