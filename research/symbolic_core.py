"""
Symbolic Core Engine (Neuro-Symbolic Reasoning Pillar)
Part of Personal Agentic AI (PAI) - Custom Architecture from Scratch.

Transforms natural language queries into Formal Intent Graphs (DAGs)
and executes deterministic, budget-aware logic deduction without massive weights.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

from hardware_telemetry import HardwareBudget


class IntentKind(Enum):
    EXPLAIN_CONCEPT = auto()
    GENERATE_CODE = auto()
    OPTIMIZE_ALGORITHM = auto()
    VERIFY_CLAIM = auto()
    GENERAL_QUERY = auto()


@dataclass
class LogicNode:
    node_id: str
    operation: str  # e.g., 'PARSE', 'RETRIEVE_PREMISES', 'DEDUCE', 'SYNTHESIZE'
    parameters: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    result: Optional[str] = None


@dataclass
class ExecutionGraph:
    nodes: Dict[str, LogicNode] = field(default_factory=dict)
    execution_order: List[str] = field(default_factory=list)

    def add_node(self, node: LogicNode) -> None:
        self.nodes[node.node_id] = node
        self.execution_order.append(node.node_id)


class SymbolicCore:
    """
    Grammar & Logic Deduction Engine.
    Operates statelessly in memory with zero external weights.
    """

    # Keyword rules for intent classification
    CODE_KEYWORDS = {"code", "function", "implement", "script", "program", "rust", "python", "c++", "class", "algorithm"}
    OPTIMIZE_KEYWORDS = {"optimize", "speed up", "compress", "refactor", "improve", "bottleneck", "rsi"}
    EXPLAIN_KEYWORDS = {"explain", "what is", "how does", "summarize", "describe", "meaning", "concept"}

    def __init__(self):
        pass

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

    def build_execution_graph(self, query: str, context: Optional[str], budget: HardwareBudget) -> ExecutionGraph:
        """
        Decomposes query into a Directed Acyclic Graph (DAG) of logical inference steps.
        Graph complexity is dynamically bounded by the HardwareBudget tier.
        """
        intent = self.classify_intent(query)
        graph = ExecutionGraph()

        # Step 1: Input Analysis & Token Extraction
        graph.add_node(LogicNode(
            node_id="step_1_intent",
            operation="ANALYZE_INTENT",
            parameters={"query": query, "intent": intent.name}
        ))

        # Step 2: Context & Premise Extraction
        graph.add_node(LogicNode(
            node_id="step_2_premises",
            operation="EXTRACT_PREMISES",
            parameters={"has_context": str(context is not None)},
            dependencies=["step_1_intent"]
        ))

        # Depth control based on HardwareBudget
        if budget.compute_tier == "COMPRESSED":
            # Linear direct execution under memory pressure
            graph.add_node(LogicNode(
                node_id="step_3_synthesis",
                operation="DIRECT_SYNTHESIS",
                dependencies=["step_2_premises"]
            ))
        else:
            # Full logical deduction & verification branch
            graph.add_node(LogicNode(
                node_id="step_3_deduction",
                operation="LOGICAL_DEDUCTION",
                dependencies=["step_2_premises"]
            ))
            graph.add_node(LogicNode(
                node_id="step_4_synthesis",
                operation="STRUCTURED_SYNTHESIS",
                dependencies=["step_3_deduction"]
            ))

        return graph

    def deduce_premises(self, context: Optional[str]) -> List[str]:
        """Extracts atomic factual premises from fenced external context."""
        if not context:
            return []

        premises = []
        lines = [line.strip() for line in context.split("\n") if line.strip()]
        for line in lines:
            if line.startswith(("TOPIC:", "DESCRIPTION:", "SUMMARY:", "DETAILS:")):
                premises.append(line)
            elif len(line) > 30 and not line.startswith("<<"):
                # Meaningful sentence segment
                sentences = re.split(r"(?<=[.!?])\s+", line)
                for s in sentences:
                    s_clean = s.strip()
                    if len(s_clean) > 25 and s_clean not in premises:
                        premises.append(s_clean)
                        if len(premises) >= 6:  # Bounded premise count
                            break
            if len(premises) >= 6:
                break
        return premises
