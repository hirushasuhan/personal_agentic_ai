# ADR-001 — Reasoner strategy (risk R1)

**Status:** Accepted (default) · **Owner decision D1** · **Date:** 2026-10-05

## Context
The architecture assumes a very small, knowledge-free "reasoning core". Following instructions, understanding free text and writing code needs a model with many parameters; training such a model from scratch needs large datasets, GPU time and evaluation infrastructure. Meanwhile the rest of the system (ingestion, purge, safety) can be built and verified independently of the model.

## Decision
1. **Product path (Option A):** use an existing open-weights small model served **locally** (llama.cpp `llama-server`, Ollama, LM Studio, vLLM — any OpenAI-compatible `/v1/chat/completions` endpoint) behind the `Reasoner` interface. Implemented: `research/reasoner.py::LocalLLMReasoner`.
2. **Research path (Option B):** a custom architecture is a separate track with its own benchmarks. It becomes a candidate `Reasoner` only if it beats the adopted model on a fixed evaluation suite at equal or lower RAM.
3. The model is **a replaceable component**, never the identity of the project: the stateless loop, hardware budgeting, ingestion safety and RSI containment are the project.

## Safety constraints built into the adapter (all tested)
Loopback-only endpoint (the model can never be an exfiltration hop) · no redirects or proxies · no tool/function-calling parameters ever sent · untrusted context fenced, and fence markers inside it neutralised · token cap follows the hardware tier · response size cap · failures surface as errors and the purge still runs.

## Consequences
* A real answer path exists now: `python main.py --ask "Explain X" --model-url http://127.0.0.1:11434/v1 --model <name>`.
* RAM/latency per tier can be measured with real inference before Phase 3 begins.
* The "tiny core" claim is dropped from the docs until measured.

## If reversed (choose B only)
Keep the `Reasoner` interface and conformance tests; budget GPU/data work explicitly in the roadmap and move Phase 3's engine work in parallel, using the adopted model as the baseline to beat.
