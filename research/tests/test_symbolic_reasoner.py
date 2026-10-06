"""
Unit tests for Neuro-Symbolic Reasoner & Code Synthesizer (Option B).
Verifies Evidence Atoms, Conflict Resolution, Execution Graphs, Grounding Validation,
and Formal Invariants I1 through I6.
"""

import unittest

import _bootstrap  # noqa: F401
from agent_core import StatelessAgentCore
from ast_guard import check_source
from benchmark import OfflineNetwork
from code_synthesizer import CodeSynthesizer
from hardware_telemetry import HardwareBudget, HardwareTelemetry
from reasoner import NeuroSymbolicReasoner
from symbolic_core import (
    ConflictDetector,
    EvidenceAtom,
    ExecutionGraph,
    GroundingValidator,
    IntentKind,
    LogicNode,
    SymbolicCore,
)


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
        b_compressed = HardwareBudget(compute_tier="COMPRESSED", max_context_bytes=1024,
                                      allow_speculation=False, thread_pool_limit=1, throttle_warning="")
        g_comp = self.core.build_execution_graph("Explain Rust", None, b_compressed)
        self.assertIn("step_3_synthesis", g_comp.nodes)
        self.assertNotIn("step_3_deduction", g_comp.nodes)

        b_high = HardwareBudget(compute_tier="HIGH", max_context_bytes=64 * 1024 * 1024,
                                allow_speculation=True, thread_pool_limit=8, throttle_warning="")
        g_high = self.core.build_execution_graph("Explain Rust", None, b_high)
        self.assertIn("step_3_deduction", g_high.nodes)
        self.assertIn("step_4_synthesis", g_high.nodes)
        self.assertIn("step_5_grounding_audit", g_high.nodes)

    def test_premise_extraction(self):
        context = "TOPIC: Rust\nDESCRIPTION: Fast systems language\n\nRust provides memory safety without a garbage collector."
        premises = self.core.deduce_premises(context)
        self.assertGreaterEqual(len(premises), 2)
        self.assertTrue(any("memory safety" in p.lower() or "systems language" in p.lower() for p in premises))

    def test_atom_extraction(self):
        context = (
            "TOPIC: Rust Programming\n"
            "DESCRIPTION: Fast and memory efficient\n"
            "Rust is a systems programming language.\n"
            "Rust provides zero-cost abstractions."
        )
        atoms = self.core.extract_atoms(context, default_trust=0.8)
        self.assertGreaterEqual(len(atoms), 3)
        self.assertTrue(all(isinstance(a, EvidenceAtom) for a in atoms))
        self.assertEqual(atoms[0].source_trust, 0.8)
        self.assertTrue(any("systems programming" in a.object.lower() for a in atoms))


class ConflictDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = ConflictDetector()

    def test_direct_negation_conflict_resolved_by_trust(self):
        a1 = EvidenceAtom(atom_id="ATOM-001", subject="Python", predicate="is", object="compiled",
                          polarity=True, source_trust=0.3, raw_text="Python is compiled")
        a2 = EvidenceAtom(atom_id="ATOM-002", subject="Python", predicate="is", object="compiled",
                          polarity=False, source_trust=0.9, raw_text="Python is not compiled")

        rep = self.detector.detect_and_resolve([a1, a2])
        self.assertEqual(len(rep.conflicts_detected), 1)
        # ATOM-002 has higher trust (0.9 vs 0.3, delta >= 0.2), so ATOM-002 prevails
        self.assertIn("ATOM-002", rep.resolved_atoms)
        self.assertNotIn("ATOM-001", rep.resolved_atoms)
        self.assertEqual(len(rep.unresolved_conflicts), 0)

    def test_functional_collision_with_equal_trust_flags_unresolved(self):
        a1 = EvidenceAtom(atom_id="ATOM-001", subject="Rust", predicate="is", object="interpreted",
                          polarity=True, source_trust=0.5, raw_text="Rust is interpreted")
        a2 = EvidenceAtom(atom_id="ATOM-002", subject="Rust", predicate="is", object="compiled",
                          polarity=True, source_trust=0.55, raw_text="Rust is compiled")

        rep = self.detector.detect_and_resolve([a1, a2])
        self.assertEqual(len(rep.conflicts_detected), 1)
        # Delta is 0.05 (< 0.20), so dialectic tension is flagged as unresolved
        self.assertEqual(len(rep.unresolved_conflicts), 1)

    def test_negation_extraction_and_unresolved_conflict(self):
        core = SymbolicCore()
        context = "Python is slow.\nPython is not slow."
        atoms = core.extract_atoms(context)
        self.assertEqual(len(atoms), 2)
        self.assertEqual(atoms[0].subject.lower(), "python")
        self.assertEqual(atoms[0].predicate, "is")
        self.assertEqual(atoms[0].object, "slow")
        self.assertTrue(atoms[0].polarity)

        self.assertEqual(atoms[1].subject.lower(), "python")
        self.assertEqual(atoms[1].predicate, "is")
        self.assertEqual(atoms[1].object, "slow")
        self.assertFalse(atoms[1].polarity)

        rep = self.detector.detect_and_resolve(atoms)
        self.assertEqual(len(rep.conflicts_detected), 1)
        self.assertEqual(len(rep.unresolved_conflicts), 1)
        self.assertIn("Direct negation", rep.conflicts_detected[0][2])

    def test_per_source_trust_wiring(self):
        core = SymbolicCore()
        context = (
            "[Source: local_knowledge]\n"
            "Python is dynamic.\n\n"
            "[Source: duckduckgo]\n"
            "Python is static.\n"
        )
        atoms = core.extract_atoms(context)
        self.assertEqual(len(atoms), 2)
        self.assertAlmostEqual(atoms[0].source_trust, 0.95)
        self.assertAlmostEqual(atoms[1].source_trust, 0.50)

        rep = self.detector.detect_and_resolve(atoms)
        self.assertEqual(len(rep.conflicts_detected), 1)
        self.assertIn(atoms[0].atom_id, rep.resolved_atoms)
        self.assertNotIn(atoms[1].atom_id, rep.resolved_atoms)
        self.assertEqual(len(rep.unresolved_conflicts), 0)


class GroundingValidatorTests(unittest.TestCase):
    def setUp(self):
        self.validator = GroundingValidator()
        self.a1 = EvidenceAtom(atom_id="ATOM-001", subject="rust", predicate="is", object="fast")
        self.a2 = EvidenceAtom(atom_id="ATOM-002", subject="rust", predicate="has", object="ownership")
        self.atoms = {"ATOM-001": self.a1, "ATOM-002": self.a2}

    def test_valid_grounding(self):
        text = "According to [ATOM-001], rust is fast, and [ATOM-002] confirms ownership."
        rep = self.validator.validate(text, self.atoms, [])
        self.assertTrue(rep.is_grounded)
        self.assertEqual(len(rep.grounded_atoms), 2)
        self.assertEqual(rep.grounding_score, 1.0)
        self.assertIn("SYNTACTIC_GROUNDING", rep.status)

    def test_invalid_citation_and_unresolved_hazard(self):
        text = "Claim cites [ATOM-001] and [ATOM-999]."
        hazards = [("ATOM-001", "ATOM-002", "negation")]
        rep = self.validator.validate(text, self.atoms, hazards)
        self.assertFalse(rep.is_grounded)
        self.assertIn("ATOM-999", rep.invalid_citations)
        self.assertIn("ATOM-001", rep.unresolved_hazards)
        self.assertIn("PARTIAL_GROUNDING", rep.status)

    def test_empty_atoms_marked_ungrounded(self):
        text = "Evaluating claim without external context."
        rep = self.validator.validate(text, {}, [])
        self.assertFalse(rep.is_grounded)
        self.assertEqual(rep.grounding_score, 0.0)
        self.assertIn("UNGROUNDED", rep.status)


class ExecutionGraphTests(unittest.TestCase):
    def test_topological_execution(self):
        graph = ExecutionGraph()
        graph.add_node(LogicNode(node_id="n1", operation="OP1", handler=lambda ctx, b: 10))
        graph.add_node(LogicNode(node_id="n2", operation="OP2", handler=lambda ctx, b: ctx["n1"] * 2, dependencies=["n1"]))

        budget = HardwareBudget(compute_tier="BALANCED", max_context_bytes=4096,
                                allow_speculation=False, thread_pool_limit=2, throttle_warning="")
        ctx, trace = graph.execute(budget)
        self.assertEqual(ctx["n1"], 10)
        self.assertEqual(ctx["n2"], 20)
        self.assertEqual(trace.executed_nodes, ["n1", "n2"])
        self.assertGreaterEqual(trace.total_time_ms, 0.0)

    def test_cycle_detection_fails_closed(self):
        graph = ExecutionGraph()
        graph.add_node(LogicNode(node_id="n1", operation="OP1", dependencies=["n2"]))
        graph.add_node(LogicNode(node_id="n2", operation="OP2", dependencies=["n1"]))

        budget = HardwareBudget(compute_tier="BALANCED", max_context_bytes=4096,
                                allow_speculation=False, thread_pool_limit=2, throttle_warning="")
        with self.assertRaises(ValueError):
            graph.execute(budget)

    def test_depth_cap_halts_execution_early(self):
        graph = ExecutionGraph()
        executed = []
        for i in range(6):
            def make_h(idx):
                return lambda ctx, b: executed.append(idx)
            graph.add_node(LogicNode(node_id=f"n{i}", operation=f"OP{i}", handler=make_h(i)))

        # COMPRESSED tier cap is 4
        budget = HardwareBudget(compute_tier="COMPRESSED", max_context_bytes=1024,
                                allow_speculation=False, thread_pool_limit=1, throttle_warning="")
        ctx, trace = graph.execute(budget)
        self.assertTrue(trace.halted_early)
        self.assertEqual(trace.node_count, 4)
        self.assertEqual(executed, [0, 1, 2, 3])
        self.assertIn("Depth cap 4 reached for tier COMPRESSED", trace.halt_reason)
        self.assertIsNone(graph.nodes["n4"].result)
        self.assertIsNone(graph.nodes["n5"].result)


class CodeSynthesizerTests(unittest.TestCase):
    def setUp(self):
        self.synth = CodeSynthesizer()

    def test_synthesized_python_passes_ast_guard(self):
        res = self.synth.synthesize(IntentKind.GENERATE_CODE, "write python data transformer", [], "HIGH")
        self.assertIn("```python", res)
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
        self.assertIn("Extracted 2 premise(s)", res)


class FormalInvariantsTests(unittest.TestCase):
    """
    Formal Invariant Tests (I1 through I6) per docs/ALGORITHM.md and ADR-007.
    """
    def setUp(self):
        self.core = SymbolicCore()
        self.synth = CodeSynthesizer()
        self.reasoner = NeuroSymbolicReasoner()
        self.budget_balanced = HardwareBudget(
            compute_tier="BALANCED", max_context_bytes=16384,
            allow_speculation=False, thread_pool_limit=2, throttle_warning=""
        )

    def test_invariant_i1_strict_grounding(self):
        """I1: Uncited claims or empty context are explicitly marked UNGROUNDED."""
        res_empty = self.synth.synthesize(IntentKind.EXPLAIN_CONCEPT, "Is the earth flat?", [], "BALANCED")
        self.assertIn("UNGROUNDED", res_empty)

        # Grounded context with atoms
        atom = EvidenceAtom(atom_id="ATOM-001", subject="Earth", predicate="is", object="oblate spheroid")
        res_grounded = self.synth.synthesize(
            IntentKind.EXPLAIN_CONCEPT, "Shape of Earth", [], "BALANCED", atoms=[atom]
        )
        self.assertIn("[ATOM-001]", res_grounded)
        self.assertIn("Extracted 1 premise(s)", res_grounded)

    def test_invariant_i2_deterministic_termination(self):
        """I2: Execution graph halts deterministically within budget depth cap."""
        graph = self.core.build_execution_graph("Explain Rust", "Rust is fast", self.budget_balanced, self.synth)
        topo = graph.validate_acyclic()
        self.assertLessEqual(len(topo), ExecutionGraph.TIER_DEPTH_CAPS["BALANCED"])

        ctx, trace = graph.execute(self.budget_balanced)
        self.assertFalse(trace.halted_early)
        self.assertGreater(trace.node_count, 0)

    def test_invariant_i3_budget_containment(self):
        """I3: Compressed tier enforces reduced node depth."""
        b_compressed = HardwareBudget(
            compute_tier="COMPRESSED", max_context_bytes=1024,
            allow_speculation=False, thread_pool_limit=1, throttle_warning="LOW_RAM"
        )
        graph = self.core.build_execution_graph("Explain Rust", None, b_compressed, self.synth)
        ctx, trace = graph.execute(b_compressed)
        self.assertLessEqual(trace.node_count, ExecutionGraph.TIER_DEPTH_CAPS["COMPRESSED"])

    def test_invariant_i4_ephemeral_purge(self):
        """I4: Working node registers are zeroized/cleared post-execution."""
        graph = self.core.build_execution_graph("Explain Rust", "Rust has safety", self.budget_balanced, self.synth)
        ctx, _ = graph.execute(self.budget_balanced)
        self.assertIsNotNone(graph.nodes["step_1_intent"].result)

        wiped_bytes = graph.purge_registers()
        self.assertGreater(wiped_bytes, 0)
        for node in graph.nodes.values():
            self.assertIsNone(node.result)
            self.assertEqual(len(node.parameters), 0)

    def test_invariant_i5_auditability_trace(self):
        """I5: Reasoning output contains structured audit trace and timings."""
        context = "TOPIC: Rust\nRust is a memory safe systems language."
        output = self.reasoner.reason("Explain Rust", context, self.budget_balanced)
        self.assertIn("--- Execution Trace (Audit Invariant I5) ---", output)
        self.assertIn("Nodes Executed:", output)
        self.assertIn("Compute Tier: BALANCED", output)

    def test_invariant_i6_ast_isolation(self):
        """I6: Synthesized code passes Tier-1 AST Guard without forbidden hooks."""
        out = self.synth.synthesize(IntentKind.GENERATE_CODE, "write python packet parser", [], "BALANCED")
        self.assertIn("Tier-1 AST Guard: PASS", out)
        code = out.split("```python")[1].split("```")[0].strip()
        report = check_source(code)
        self.assertTrue(report.ok)
        self.assertEqual(report.violations, [])


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
