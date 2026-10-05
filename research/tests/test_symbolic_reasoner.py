"""
Unit tests for Neuro-Symbolic Reasoner & Code Synthesizer (Option B).
"""

import unittest

import _bootstrap  # noqa: F401
from agent_core import StatelessAgentCore
from ast_guard import check_source
from benchmark import OfflineNetwork
from code_synthesizer import CodeSynthesizer
from hardware_telemetry import HardwareBudget, HardwareTelemetry
from reasoner import NeuroSymbolicReasoner
from symbolic_core import ExecutionGraph, IntentKind, SymbolicCore


class SymbolicCoreTests(unittest.TestCase):
    def setUp(self):
        self.core = SymbolicCore()
        self.telemetry = HardwareTelemetry(cpu_sample_ms=0)

    def test_intent_classification(self):
        self.assertEqual(self.core.classify_intent("Explain Rust ownership"), IntentKind.EXPLAIN_CONCEPT)
        self.assertEqual(self.core.classify_intent("What is Mamba SSM?"), IntentKind.EXPLAIN_CONCEPT)
        self.assertEqual(self.core.classify_intent("Write a python function to filter data"), IntentKind.GENERATE_CODE)
        self.assertEqual(self.core.classify_intent("Optimize memory pipeline bottleneck"), IntentKind.OPTIMIZE_ALGORITHM)
        self.assertEqual(self.core.classify_intent("Verify formal proof invariants"), IntentKind.VERIFY_CLAIM)

    def test_budget_aware_graph_depth(self):
        # Compressed budget
        b_compressed = HardwareBudget(compute_tier="COMPRESSED", max_context_bytes=1024,
                                      allow_speculation=False, thread_pool_limit=1, throttle_warning="")
        g_comp = self.core.build_execution_graph("Explain Rust", None, b_compressed)
        self.assertIn("step_3_synthesis", g_comp.nodes)
        self.assertNotIn("step_3_deduction", g_comp.nodes)

        # High budget
        b_high = HardwareBudget(compute_tier="HIGH", max_context_bytes=64*1024*1024,
                                allow_speculation=True, thread_pool_limit=8, throttle_warning="")
        g_high = self.core.build_execution_graph("Explain Rust", None, b_high)
        self.assertIn("step_3_deduction", g_high.nodes)
        self.assertIn("step_4_synthesis", g_high.nodes)

    def test_premise_extraction(self):
        context = "TOPIC: Rust\nDESCRIPTION: Fast systems language\n\nRust provides memory safety without a garbage collector."
        premises = self.core.deduce_premises(context)
        self.assertGreaterEqual(len(premises), 2)
        self.assertTrue(any("memory safety" in p for p in premises))


class CodeSynthesizerTests(unittest.TestCase):
    def setUp(self):
        self.synth = CodeSynthesizer()

    def test_synthesized_python_passes_ast_guard(self):
        res = self.synth.synthesize(IntentKind.GENERATE_CODE, "write python data transformer", [], "HIGH")
        self.assertIn("```python", res)
        # Extract code inside backticks
        code_match = res.split("```python")[1].split("```")[0].strip()
        guard = check_source(code_match)
        self.assertTrue(guard.ok, f"Generated code violated AST guard: {guard.violations}")

    def test_synthesized_rust_code(self):
        res = self.synth.synthesize(IntentKind.GENERATE_CODE, "write rust byte processor", [], "HIGH")
        self.assertIn("```rust", res)
        self.assertIn("pub fn", res)

    def test_synthesized_explanation_grounds_premises(self):
        premises = ["Premise A: Systems language", "Premise B: Zero cost abstractions"]
        res = self.synth.synthesize(IntentKind.EXPLAIN_CONCEPT, "Explain Rust", premises, "BALANCED")
        self.assertIn("P1: Premise A: Systems language", res)
        self.assertIn("P2: Premise B: Zero cost abstractions", res)
        self.assertIn("Factual Grounding: Grounded on 2 premise(s)", res)


class NeuroSymbolicReasonerIntegrationTests(unittest.TestCase):
    def test_agent_with_neuro_symbolic_reasoner_and_purge(self):
        reasoner = NeuroSymbolicReasoner()
        agent = StatelessAgentCore(network=OfflineNetwork(64), reasoner=reasoner)
        result = agent.execute_task("Explain Rust ownership")

        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.reasoner_name, reasoner.name)
        self.assertIn("Neuro-Symbolic", result.synthesized_output)
        self.assertTrue(result.memory_purged_successfully)
        self.assertGreater(result.purge.bytes_wiped, 0)

    def test_agent_synthesizes_code_safely(self):
        reasoner = NeuroSymbolicReasoner()
        agent = StatelessAgentCore(network=OfflineNetwork(64), reasoner=reasoner)
        result = agent.execute_task("write a python function to transform packets")

        self.assertEqual(result.status, "SUCCESS")
        self.assertIn("def function_to_transform", result.synthesized_output)
        self.assertIn("Tier-1 AST Guard: PASS", result.synthesized_output)
        self.assertTrue(result.memory_purged_successfully)


if __name__ == "__main__":
    unittest.main()
