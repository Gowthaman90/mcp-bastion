# mcp-bastion Security Checks → NIST AI RMF / OWASP Mapping

_Each security check mcp-bastion performs, mapped to the frameworks it exercises. The mappings are
drawn from the [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) threat–control
crosswalk and reflect what the benchmark **measured** mcp-bastion doing (14 of 24 attack vectors), at
zero false positives. Last updated 2026-07-14._

> **How the mapping is defined.** The checks are **threat-driven** — the vectors come from the
> 2025–2026 MCP-security research literature (see References) — and each is **crosswalked to recognized
> security frameworks**: the U.S. NIST AI Risk Management Framework, the OWASP Top 10 for LLM (2025)
> and Agentic (2026) Applications, and STRIDE. NIST AI RMF is a U.S. federal (Department of Commerce)
> framework; OWASP is an international open standard; STRIDE is the classic threat-modeling taxonomy.

## The mapping

|   # | Threat / check                              | Bastion mechanism                  | Action         | Layer              | STRIDE                              | NIST AI RMF          | OWASP LLM 2025 | OWASP Agentic 2026 |
| --: | ------------------------------------------- | ---------------------------------- | -------------- | ------------------ | ----------------------------------- | -------------------- | -------------- | ------------------ |
|   1 | Tool poisoning                              | Description scanning (`scanTool`)  | 🟡 detect      | tool               | Tampering, EoP                      | MAP, MEASURE, MANAGE | LLM01, LLM06   | ASI01, ASI02       |
|   2 | Tool shadowing / name collision             | Cross-server name-collision check  | 🟡 detect      | client             | Spoofing, Tampering                 | MAP, MANAGE          | LLM01, LLM03   | ASI01, ASI04       |
|   3 | Rug pull (definition mutation)              | Definition pinning + hash compare  | 🟢 **enforce** | tool               | Tampering                           | MEASURE, MANAGE      | LLM03, LLM06   | ASI04              |
|   4 | Out-of-scope parameter injection            | Argument schema validation         | 🟡 detect      | tool               | Tampering, EoP                      | MEASURE, MANAGE      | LLM05, LLM06   | ASI02              |
|   5 | Prompt injection via tool results           | Response content scanning          | 🟡 detect      | tool               | Tampering                           | MEASURE, MANAGE      | LLM01, LLM05   | ASI01              |
|   6 | Indirect / retrieval injection              | Response content scanning          | 🟡 detect      | tool               | Tampering                           | MEASURE, MANAGE      | LLM01          | ASI01              |
|   7 | Cross-tool exfiltration (confused deputy)   | Sensitive-argument scanning        | 🟡 detect      | client             | InfoDisclosure, EoP                 | MAP, MEASURE, MANAGE | LLM02, LLM06   | ASI02, ASI03       |
|   8 | Schema / validation bypass                  | Argument schema validation         | 🟡 detect      | server             | Tampering, EoP                      | MEASURE, MANAGE      | LLM05          | ASI02              |
|   9 | Man-in-the-middle (transport)               | Plaintext-HTTP transport check     | 🟡 detect      | transport          | Tampering, InfoDisclosure, Spoofing | MANAGE               | LLM02          | ASI03              |
|  10 | DNS rebinding (local servers)               | Origin allowlist on loopback (403) | 🟢 **enforce** | transport          | Spoofing, EoP                       | MANAGE               | LLM06          | ASI03              |
|  11 | Excessive permission / privilege escalation | Least-privilege scope check        | 🟡 detect      | host-orchestration | EoP                                 | GOVERN, MAP, MANAGE  | LLM06          | ASI03              |
|  12 | Credential / token theft via passthrough    | Response + secret scanning         | 🟡 detect      | host-orchestration | InfoDisclosure, EoP                 | GOVERN, MANAGE       | LLM02, LLM06   | ASI03              |
|  13 | System-prompt / context leakage             | Response content scanning          | 🟡 detect      | client             | InfoDisclosure                      | MEASURE, MANAGE      | LLM07, LLM02   | ASI01              |
|  14 | Mid-session tool injection (MSTI)           | Definition pinning + hash compare  | 🟢 **enforce** | client             | Tampering, Spoofing                 | MEASURE, MANAGE      | LLM01, LLM06   | ASI01, ASI04       |

🟢 **enforce** = blocks the call · 🟡 detect = flags/warns (blocking is opt-in via config) · EoP = Elevation of Privilege

**Known gap (not covered):** _Multi-tool split poisoning (ShareLock, arXiv:2606.27027)_ splits a
malicious payload across several benign-looking tool descriptions, defeating per-tool scanning by
design. mcp-bastion scans each tool individually, so it does not catch this today — and neither does
any other measured tool. Cross-tool correlation is on the roadmap.

## Legend

**NIST AI RMF functions** — GOVERN (policies & accountability) · MAP (context & risk identification) ·
MEASURE (analyze & track risks) · MANAGE (act on & mitigate risks).

**OWASP Top 10 for LLM Applications (2025)** — LLM01 Prompt Injection · LLM02 Sensitive Information
Disclosure · LLM03 Supply Chain · LLM05 Improper Output Handling · LLM06 Excessive Agency ·
LLM07 System Prompt Leakage.

**OWASP Top 10 for Agentic Applications (2026)** — ASI01 Agent Goal Hijack · ASI02 Tool Misuse and
Exploitation · ASI03 Identity and Privilege Abuse · ASI04 Agentic Supply Chain Vulnerabilities.

## References

### Security frameworks

- **NIST AI Risk Management Framework (AI RMF 1.0)** — U.S. National Institute of Standards and
  Technology (Dept. of Commerce), NIST.AI.100-1:
  https://www.nist.gov/itl/ai-risk-management-framework · PDF:
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- **OWASP Top 10 for LLM Applications (2025)** — https://genai.owasp.org/llm-top-10/
- **OWASP Top 10 for Agentic Applications (2026)** —
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- **STRIDE threat model** (Microsoft) —
  https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats

### MCP security issues (primary literature the vectors are drawn from)

- **SoK: Security and Safety in the MCP Ecosystem** — arXiv:2512.08290 —
  https://arxiv.org/abs/2512.08290
- **A Formal Security Framework for MCP-Based AI Agents** (7 categories / 23 vectors) — arXiv:2604.05969
  — https://arxiv.org/abs/2604.05969
- **MCP Threat Modeling: Prompt Injection with Tool Poisoning** (STRIDE/DREAD) — arXiv:2603.22489 —
  https://arxiv.org/abs/2603.22489
- **MCP-DPT: Defense-Placement Taxonomy** — arXiv:2604.07551 — https://arxiv.org/abs/2604.07551
- **MCP Security Bench (MSB)** (ICLR 2026) — arXiv:2510.15994 — https://arxiv.org/abs/2510.15994
- **MCPTox: Tool Poisoning Benchmark** — arXiv:2508.14925 — https://arxiv.org/abs/2508.14925
- **ETDI: Mitigating Tool Squatting and Rug-Pull Attacks in MCP** — arXiv:2506.01333 —
  https://arxiv.org/abs/2506.01333
- **The Trustworthy MCP Registry** (Future Internet 2026) — https://doi.org/10.3390/fi18050243
- **WebMCP Tool Surface Poisoning / Mid-Session Tool Injection (MSTI)** — arXiv:2606.06387 —
  https://arxiv.org/abs/2606.06387
- **ShareLock: A Stealthy Multi-Tool Threshold Poisoning Attack Against MCP** — arXiv:2606.27027 —
  https://arxiv.org/abs/2606.27027

### MCP protocol

- **Model Context Protocol — specification** (incl. security considerations) —
  https://modelcontextprotocol.io/specification
- **MCP Registry (about)** — https://modelcontextprotocol.io/registry/about

---

_Mappings are indicative and reviewable, not a certification — they evidence which framework controls
each check exercises. Source of record: the mcp-defense-bench crosswalk
(`rubric/crosswalk.json`, CC-BY-4.0)._
