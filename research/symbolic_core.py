"""
Symbolic Core Engine (Neuro-Symbolic Reasoning Pillar - Option B)
Part of Personal Agentic AI (PAI) - Custom Architecture from Scratch.

Transforms natural language queries and ingested context into Evidence Atoms,
detects and resolves dialectic contradictions, and executes a budget-bounded
Directed Acyclic Graph (DAG) for deterministic logic deduction.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from hardware_telemetry import HardwareBudget


class IntentKind(Enum):
    EXPLAIN_CONCEPT = auto()
    GENERATE_CODE = auto()
    OPTIMIZE_ALGORITHM = auto()
    VERIFY_CLAIM = auto()
    GENERAL_QUERY = auto()


@dataclass(frozen=True)
class EvidenceAtom:
    """
    Indivisible proposition with provenance and trust metadata.
    Maps to <id, subject, predicate, object, polarity, source_trust, timestamp>.
    """
    atom_id: str
    subject: str
    predicate: str
    object: str
    polarity: bool = True           # True = positive assertion; False = negated
    source_trust: float = 0.5       # [0.0, 1.0]
    timestamp: float = field(default_factory=time.time)
    raw_text: str = ""

    def summary(self) -> str:
        pol = "" if self.polarity else "NOT "
        return f"[{self.atom_id}] {self.subject} {pol}{self.predicate} {self.object} (trust={self.source_trust:.2f})"


@dataclass
class ConflictReport:
    """Outcome of dialectic contradiction detection across premises."""
    conflicts_detected: List[Tuple[str, str, str]] = field(default_factory=list)  # (atom1_id, atom2_id, reason)
    resolved_atoms: Dict[str, EvidenceAtom] = field(default_factory=dict)
    unresolved_conflicts: List[Tuple[str, str, str]] = field(default_factory=list)


class ConflictDetector:
    """Detects and resolves contradictions between evidence atoms."""

    # Functional predicates: subject cannot have distinct objects for this predicate
    FUNCTIONAL_PREDICATES = {
        "is", "is_a", "has_capital", "created_in", "author_of", "version",
        "primary_type", "type_of", "inventor_of", "headquarters"
    }

    TRUST_RESOLUTION_THRESHOLD = 0.20

    def detect_and_resolve(self, atoms: List[EvidenceAtom]) -> ConflictReport:
        report = ConflictReport()
        if not atoms:
            return report

        by_subj_pred: Dict[Tuple[str, str], List[EvidenceAtom]] = {}
        for a in atoms:
            key = (a.subject.strip().lower(), a.predicate.strip().lower())
            by_subj_pred.setdefault(key, []).append(a)

        eliminated_atoms: Set[str] = set()

        for (subj, pred), group in by_subj_pred.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a1 = group[i]
                    a2 = group[j]

                    is_conflict = False
                    reason = ""

                    # Direct negation: same subject, predicate, object, opposite polarity
                    if a1.object.strip().lower() == a2.object.strip().lower() and a1.polarity != a2.polarity:
                        is_conflict = True
                        reason = f"Direct negation on '{subj} {pred} {a1.object}'"

                    # Functional predicate inconsistency: same subject & predicate, different objects, both positive
                    elif a1.object.strip().lower() != a2.object.strip().lower() and a1.polarity and a2.polarity:
                        if pred in self.FUNCTIONAL_PREDICATES:
                            is_conflict = True
                            reason = f"Functional collision: '{subj} {pred}' cannot simultaneously be '{a1.object}' and '{a2.object}'"

                    if is_conflict:
                        report.conflicts_detected.append((a1.atom_id, a2.atom_id, reason))
                        trust_delta = abs(a1.source_trust - a2.source_trust)

                        if trust_delta >= self.TRUST_RESOLUTION_THRESHOLD:
                            # Higher trust prevails
                            if a1.source_trust > a2.source_trust:
                                eliminated_atoms.add(a2.atom_id)
                            else:
                                eliminated_atoms.add(a1.atom_id)
                        else:
                            # Unresolvable dialectic tension; both flagged as unresolved
                            report.unresolved_conflicts.append((a1.atom_id, a2.atom_id, reason))

        for a in atoms:
            if a.atom_id not in eliminated_atoms:
                report.resolved_atoms[a.atom_id] = a

        return report


@dataclass
class GroundingReport:
    """Audit report verifying that claims cite active, non-conflicting atoms."""
    is_grounded: bool
    grounded_atoms: List[str]
    invalid_citations: List[str]
    unresolved_hazards: List[str]
    grounding_score: float
    status: str
    details: str


class GroundingValidator:
    """
    Validates that claims in synthesized reasoning outputs are rigorously
    grounded in active evidence atoms and cite valid atom IDs.
    """
    CITATION_PATTERN = re.compile(r"\[ATOM-([A-Za-z0-9_-]+)\]")

    def validate(
        self,
        text: str,
        available_atoms: Dict[str, EvidenceAtom],
        unresolved_conflicts: List[Tuple[str, str, str]]
    ) -> GroundingReport:
        citations = self.CITATION_PATTERN.findall(text)
        cited_ids = set(f"ATOM-{c}" if not c.startswith("ATOM-") else c for c in citations)

        hazard_ids = set()
        for a1, a2, _ in unresolved_conflicts:
            hazard_ids.add(a1)
            hazard_ids.add(a2)

        grounded: List[str] = []
        invalid: List[str] = []
        hazards: List[str] = []

        for cid in sorted(cited_ids):
            if cid in available_atoms:
                grounded.append(cid)
                if cid in hazard_ids:
                    hazards.append(cid)
            else:
                invalid.append(cid)

        total_citations = len(cited_ids)
        if total_citations == 0:
            if not available_atoms:
                status = "UNGROUNDED (no external premises provided; evaluated by structural heuristics only)"
            else:
                status = "UNGROUNDED (assertions lack evidence atom citations)"
            return GroundingReport(
                is_grounded=False,
                grounded_atoms=[],
                invalid_citations=[],
                unresolved_hazards=[],
                grounding_score=0.0,
                status=status,
                details="Zero evidence atom citations found in synthesized output."
            )

        denom = max(1, len(grounded) + len(invalid))
        score = max(0.0, (len(grounded) - len(hazards)) / float(denom))
        is_ok = (len(invalid) == 0) and (len(hazards) == 0) and (len(grounded) > 0)

        if is_ok:
            status = f"GROUNDED ({len(grounded)} atom(s) verified, score={score:.2f})"
        else:
            status = f"PARTIAL_GROUNDING (invalid={len(invalid)}, hazards={len(hazards)}, score={score:.2f})"

        return GroundingReport(
            is_grounded=is_ok,
            grounded_atoms=grounded,
            invalid_citations=invalid,
            unresolved_hazards=hazards,
            grounding_score=round(score, 3),
            status=status,
            details=f"Verified citations: {grounded}; Invalid: {invalid}; Conflict hazards: {hazards}"
        )


@dataclass
class LogicNode:
    node_id: str
    operation: str
    handler: Optional[Callable[[Dict[str, Any], HardwareBudget], Any]] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    result: Any = None
    execution_time_ms: float = 0.0


@dataclass
class ExecutionTrace:
    executed_nodes: List[str] = field(default_factory=list)
    node_timings_ms: Dict[str, float] = field(default_factory=dict)
    total_time_ms: float = 0.0
    budget_tier: str = "UNKNOWN"
    node_count: int = 0
    halted_early: bool = False
    halt_reason: str = ""


class ExecutionGraph:
    """
    Directed Acyclic Graph (DAG) for deterministic logic execution.
    Bounded by HardwareBudget depth and concurrency ceilings.
    """
    TIER_DEPTH_CAPS = {
        "COMPRESSED": 4,
        "BALANCED": 8,
        "HIGH": 16,
    }

    def __init__(self):
        self.nodes: Dict[str, LogicNode] = {}
        self.execution_order: List[str] = []

    def add_node(self, node: LogicNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_id not in self.execution_order:
            self.execution_order.append(node.node_id)

    def validate_acyclic(self) -> List[str]:
        """Kahn's algorithm to verify DAG and return topological ordering."""
        in_degree: Dict[str, int] = {nid: 0 for nid in self.nodes}
        adj: Dict[str, List[str]] = {nid: [] for nid in self.nodes}

        for nid, node in self.nodes.items():
            for dep in node.dependencies:
                if dep in self.nodes:
                    adj[dep].append(nid)
                    in_degree[nid] += 1

        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        topo_order: List[str] = []

        while queue:
            curr = queue.pop(0)
            topo_order.append(curr)
            for neighbor in adj[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(topo_order) != len(self.nodes):
            raise ValueError("ExecutionGraph contains a cycle or unresolved dependency")

        return topo_order

    def execute(self, budget: HardwareBudget) -> Tuple[Dict[str, Any], ExecutionTrace]:
        """
        Executes DAG nodes deterministically up to the budget depth cap.
        Enforces Invariant I2 (Termination), I3 (Budget Containment), and I4 (Zero Residual State).
        """
        topo_order = self.validate_acyclic()
        cap = self.TIER_DEPTH_CAPS.get(budget.compute_tier, 6)

        trace = ExecutionTrace(budget_tier=budget.compute_tier)
        context: Dict[str, Any] = {}
        t_start = time.perf_counter()

        for idx, nid in enumerate(topo_order):
            if idx >= cap:
                trace.halted_early = True
                trace.halt_reason = f"Depth cap {cap} reached for tier {budget.compute_tier}"
                break

            node = self.nodes[nid]
            t_node0 = time.perf_counter()

            if node.handler is not None:
                res = node.handler(context, budget)
                node.result = res
                context[node.node_id] = res
            else:
                context[node.node_id] = node.parameters

            t_node_dur = (time.perf_counter() - t_node0) * 1000.0
            node.execution_time_ms = t_node_dur
            trace.executed_nodes.append(nid)
            trace.node_timings_ms[nid] = round(t_node_dur, 3)

        trace.node_count = len(trace.executed_nodes)
        trace.total_time_ms = round((time.perf_counter() - t_start) * 1000.0, 3)
        return context, trace

    def purge_registers(self) -> int:
        """Zeros and clears all node results in memory post-execution (Invariant I4)."""
        wiped = 0
        for node in self.nodes.values():
            if node.result is not None:
                if isinstance(node.result, (bytearray, bytes)):
                    wiped += len(node.result)
                else:
                    wiped += 64
                node.result = None
            node.parameters.clear()
        return wiped


class SymbolicCore:
    """
    Stateless Neuro-Symbolic Logic Deduction Engine.
    Operates in ephemeral memory with zero persistent weights.
    """

    CODE_KEYWORDS = {"code", "function", "implement", "script", "program", "rust", "python", "c++", "class", "algorithm"}
    OPTIMIZE_KEYWORDS = {"optimize", "speed up", "compress", "refactor", "improve", "bottleneck", "rsi"}
    EXPLAIN_KEYWORDS = {"explain", "what is", "how does", "summarize", "describe", "meaning", "concept"}

    def __init__(self):
        self.conflict_detector = ConflictDetector()
        self.grounding_validator = GroundingValidator()

    def classify_intent(self, query: str) -> IntentKind:
        q_lower = query.lower()
        words = set(re.findall(r"\b\w+\b", q_lower))

        if words & self.OPTIMIZE_KEYWORDS:
            return IntentKind.OPTIMIZE_ALGORITHM
        if words & self.CODE_KEYWORDS and any(w in words for w in {"write", "implement", "create", "generate", "code"}):
            return IntentKind.GENERATE_CODE
        if words & self.EXPLAIN_KEYWORDS or "what is" in q_lower or "how does" in q_lower:
            return IntentKind.EXPLAIN_CONCEPT
        if "verify" in words or "proof" in words or "check" in words:
            return IntentKind.VERIFY_CLAIM

        return IntentKind.GENERAL_QUERY

    def extract_atoms(self, context: Optional[str], default_trust: float = 0.5) -> List[EvidenceAtom]:
        """Extracts structured EvidenceAtoms from raw or fenced context."""
        if not context:
            return []

        atoms: List[EvidenceAtom] = []
        atom_counter = 1

        lines = [line.strip() for line in context.split("\n") if line.strip()]
        for line in lines:
            if line.startswith("<<") or line.startswith(">>"):
                continue

            # Tagged property lines: e.g. "TOPIC: Rust", "DESCRIPTION: Fast systems language"
            if ":" in line and not line.startswith("http"):
                parts = line.split(":", 1)
                tag, val = parts[0].strip(), parts[1].strip()
                if tag.upper() in {"TOPIC", "DESCRIPTION", "SUMMARY", "DETAILS", "PROPERTY", "AUTHOR", "VERSION"}:
                    atom = EvidenceAtom(
                        atom_id=f"ATOM-{atom_counter:03d}",
                        subject=tag.lower(),
                        predicate="is",
                        object=val,
                        polarity=True,
                        source_trust=default_trust,
                        raw_text=line,
                    )
                    atoms.append(atom)
                    atom_counter += 1
                    continue

            # Free-form sentence extraction
            sentences = re.split(r"(?<=[.!?])\s+", line)
            for s in sentences:
                s_clean = s.strip()
                if len(s_clean) < 15:
                    continue

                # Simple triple parsing: Subject Verb Object
                # Check for negation
                is_negated = any(neg in s_clean.lower() for neg in [" not ", " never ", " neither ", " cannot ", " isn't "])
                polarity = not is_negated

                # Identify predicate verb
                predicate = "is"
                for p_cand in ["is a", "is", "has", "requires", "implements", "supports", "provides", "conflicts with"]:
                    if f" {p_cand} " in s_clean.lower():
                        predicate = p_cand
                        break

                parts = re.split(rf"\b{re.escape(predicate)}\b", s_clean, flags=re.IGNORECASE, maxsplit=1)
                if len(parts) == 2 and len(parts[0].strip()) > 1 and len(parts[1].strip()) > 1:
                    subj = parts[0].strip().rstrip(",")
                    obj = parts[1].strip().lstrip(",").rstrip(".")
                else:
                    subj = "concept"
                    obj = s_clean.rstrip(".")

                atom = EvidenceAtom(
                    atom_id=f"ATOM-{atom_counter:03d}",
                    subject=subj[:50],
                    predicate=predicate,
                    object=obj[:80],
                    polarity=polarity,
                    source_trust=default_trust,
                    raw_text=s_clean,
                )
                atoms.append(atom)
                atom_counter += 1
                if atom_counter > 12:
                    break

            if atom_counter > 12:
                break

        return atoms

    def deduce_premises(self, context: Optional[str]) -> List[str]:
        """
        Legacy premise extractor for backwards-compatibility.
        Transforms extracted atoms into human-readable premise statements.
        """
        atoms = self.extract_atoms(context)
        if not atoms:
            # Fallback to direct line splitting if no structured triples found
            if not context:
                return []
            lines = [l.strip() for l in context.split("\n") if l.strip() and not l.startswith("<<")]
            return lines[:6]

        premises = []
        for a in atoms:
            premises.append(f"{a.subject} {a.predicate} {a.object}")
        return premises[:6]

    def build_execution_graph(
        self,
        query: str,
        context: Optional[str],
        budget: HardwareBudget,
        synthesizer: Optional[Any] = None
    ) -> ExecutionGraph:
        """
        Builds an executable DAG of logical deduction steps bounded by budget.
        Each node is wired with an executable handler.
        """
        graph = ExecutionGraph()
        intent = self.classify_intent(query)

        # Node 1: Parse Query and Intent
        def handle_intent(ctx: Dict[str, Any], b: HardwareBudget) -> Dict[str, Any]:
            return {"query": query, "intent": intent}

        graph.add_node(LogicNode(
            node_id="step_1_intent",
            operation="ANALYZE_INTENT",
            handler=handle_intent,
            parameters={"query": query, "intent": intent.name}
        ))

        # Node 2: Extract Evidence Atoms
        def handle_atoms(ctx: Dict[str, Any], b: HardwareBudget) -> List[EvidenceAtom]:
            return self.extract_atoms(context)

        graph.add_node(LogicNode(
            node_id="step_2_premises",
            operation="EXTRACT_ATOMS",
            handler=handle_atoms,
            dependencies=["step_1_intent"],
            parameters={"has_context": str(context is not None)}
        ))

        # Depth control based on HardwareBudget
        if budget.compute_tier == "COMPRESSED":
            # Direct synthesis under memory/cpu constraints
            def handle_direct_synth(ctx: Dict[str, Any], b: HardwareBudget) -> str:
                atoms: List[EvidenceAtom] = ctx.get("step_2_premises", [])
                premises = [f"[{a.atom_id}] {a.subject} {a.predicate} {a.object}" for a in atoms]
                if synthesizer:
                    return synthesizer.synthesize(intent, query, premises, b.compute_tier, atoms=atoms)
                return f"Direct synthesis for {query} with {len(atoms)} atoms."

            graph.add_node(LogicNode(
                node_id="step_3_synthesis",
                operation="DIRECT_SYNTHESIS",
                handler=handle_direct_synth,
                dependencies=["step_2_premises"]
            ))
        else:
            # Full dialectic deduction branch
            def handle_conflicts(ctx: Dict[str, Any], b: HardwareBudget) -> ConflictReport:
                atoms: List[EvidenceAtom] = ctx.get("step_2_premises", [])
                return self.conflict_detector.detect_and_resolve(atoms)

            graph.add_node(LogicNode(
                node_id="step_3_deduction",
                operation="CONFLICT_RESOLUTION",
                handler=handle_conflicts,
                dependencies=["step_2_premises"]
            ))

            def handle_structured_synth(ctx: Dict[str, Any], b: HardwareBudget) -> str:
                report: ConflictReport = ctx.get("step_3_deduction", ConflictReport())
                atoms = list(report.resolved_atoms.values())
                premises = [f"[{a.atom_id}] {a.subject} {a.predicate} {a.object}" for a in atoms]
                if synthesizer:
                    return synthesizer.synthesize(
                        intent,
                        query,
                        premises,
                        b.compute_tier,
                        atoms=atoms,
                        unresolved_conflicts=report.unresolved_conflicts
                    )
                return f"Structured synthesis for {query} with {len(atoms)} resolved atoms."

            graph.add_node(LogicNode(
                node_id="step_4_synthesis",
                operation="STRUCTURED_SYNTHESIS",
                handler=handle_structured_synth,
                dependencies=["step_3_deduction"]
            ))

            # Grounding validation audit node
            def handle_grounding_audit(ctx: Dict[str, Any], b: HardwareBudget) -> GroundingReport:
                synth_text = ctx.get("step_4_synthesis", "")
                report: ConflictReport = ctx.get("step_3_deduction", ConflictReport())
                return self.grounding_validator.validate(
                    synth_text,
                    report.resolved_atoms,
                    report.unresolved_conflicts
                )

            graph.add_node(LogicNode(
                node_id="step_5_grounding_audit",
                operation="GROUNDING_AUDIT",
                handler=handle_grounding_audit,
                dependencies=["step_4_synthesis"]
            ))

        return graph
