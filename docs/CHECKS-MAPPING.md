# mcp-bastion Security Checks → NIST AI RMF / OWASP Mapping

_Each security check mcp-bastion performs, mapped to the frameworks it exercises. The mappings are
drawn from the [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) threat–control
crosswalk and reflect what the benchmark **measured** mcp-bastion doing (19 of 24 attack vectors), at
zero false positives. Last updated 2026-07-15._

> **How the mapping is defined.** The checks are **threat-driven** — the vectors come from the
> 2025–2026 MCP-security research literature (see References) — and each is **crosswalked to recognized
> security frameworks**: the U.S. NIST AI Risk Management Framework, the OWASP Top 10 for LLM (2025)
> and Agentic (2026) Applications, and STRIDE. NIST AI RMF is a U.S. federal (Department of Commerce)
> framework; OWASP is an international open standard; STRIDE is the classic threat-modeling taxonomy.
> The vectors also align with the **NSA MCP Security guidance** (NSA AI Security Center, May 2026) —
> another U.S. federal source — whose recommendation areas (Authentication & Access Control,
> Monitoring & Logging, Data Classification & Segmentation, Runtime Controls) are crosswalked in the
> full rubric. mcp-bastion's checks map primarily to the NSA **Runtime Controls**, **Authentication &
> Access Control**, and **Monitoring & Logging** areas.

## The mapping

|   # | Threat / check                              | Bastion mechanism                   | Action         | Layer                 | STRIDE                              | NIST AI RMF          | OWASP LLM 2025 | OWASP Agentic 2026 |
| --: | ------------------------------------------- | ----------------------------------- | -------------- | --------------------- | ----------------------------------- | -------------------- | -------------- | ------------------ |
|   1 | Tool poisoning                              | Description scanning (`scanTool`)   | 🟡 detect      | tool                  | Tampering, EoP                      | MAP, MEASURE, MANAGE | LLM01, LLM06   | ASI01, ASI02       |
|   2 | Tool shadowing / name collision             | Cross-server name-collision check   | 🟡 detect      | client                | Spoofing, Tampering                 | MAP, MANAGE          | LLM01, LLM03   | ASI01, ASI04       |
|   3 | Rug pull (definition mutation)              | Definition pinning + hash compare   | 🟢 **enforce** | tool                  | Tampering                           | MEASURE, MANAGE      | LLM03, LLM06   | ASI04              |
|   4 | Out-of-scope parameter injection            | Argument schema validation          | 🟡 detect      | tool                  | Tampering, EoP                      | MEASURE, MANAGE      | LLM05, LLM06   | ASI02              |
|   5 | Prompt injection via tool results           | Response content scanning           | 🟡 detect      | tool                  | Tampering                           | MEASURE, MANAGE      | LLM01, LLM05   | ASI01              |
|   6 | Indirect / retrieval injection              | Response content scanning           | 🟡 detect      | tool                  | Tampering                           | MEASURE, MANAGE      | LLM01          | ASI01              |
|   7 | Cross-tool exfiltration (confused deputy)   | Sensitive-argument scanning         | 🟡 detect      | client                | InfoDisclosure, EoP                 | MAP, MEASURE, MANAGE | LLM02, LLM06   | ASI02, ASI03       |
|   8 | Schema / validation bypass                  | Argument schema validation          | 🟡 detect      | server                | Tampering, EoP                      | MEASURE, MANAGE      | LLM05          | ASI02              |
|   9 | Man-in-the-middle (transport)               | Plaintext-HTTP transport check      | 🟡 detect      | transport             | Tampering, InfoDisclosure, Spoofing | MANAGE               | LLM02          | ASI03              |
|  10 | DNS rebinding (local servers)               | Origin allowlist on loopback (403)  | 🟢 **enforce** | transport             | Spoofing, EoP                       | MANAGE               | LLM06          | ASI03              |
|  11 | Excessive permission / privilege escalation | Least-privilege scope check         | 🟡 detect      | host-orchestration    | EoP                                 | GOVERN, MAP, MANAGE  | LLM06          | ASI03              |
|  12 | Credential / token theft via passthrough    | Response + secret scanning          | 🟡 detect      | host-orchestration    | InfoDisclosure, EoP                 | GOVERN, MANAGE       | LLM02, LLM06   | ASI03              |
|  13 | System-prompt / context leakage             | Response content scanning           | 🟡 detect      | client                | InfoDisclosure                      | MEASURE, MANAGE      | LLM07, LLM02   | ASI01              |
|  14 | Mid-session tool injection (MSTI)           | Definition pinning + hash compare   | 🟢 **enforce** | client                | Tampering, Spoofing                 | MEASURE, MANAGE      | LLM01, LLM06   | ASI01, ASI04       |
|  15 | Multi-tool split poisoning (ShareLock)      | Cross-tool correlation (v0.4)       | 🟡 detect      | tool                  | Tampering                           | MEASURE, MANAGE      | LLM01, LLM03   | ASI01, ASI04       |
|  16 | Command injection in tool execution         | Argument command-injection scan     | 🟡 detect      | server                | Tampering, EoP                      | MEASURE, MANAGE      | LLM05          | ASI02, ASI05       |
|  17 | Configuration drift                         | Config-snapshot TOFU pin + diff     | 🟡 detect      | server                | Tampering                           | MAP, MEASURE, MANAGE | LLM06          | ASI04              |
|  18 | Server impersonation / identity spoofing    | Server-identity pin (TOFU) + verify | 🟢 **enforce** | registry-supply-chain | Spoofing, Tampering                 | MANAGE               | LLM03          | ASI03, ASI04       |
|  19 | Tool-transfer / cross-server exfiltration   | Cross-server data-flow (taint)      | 🟡 detect      | host-orchestration    | InfoDisclosure, EoP                 | MEASURE, MANAGE      | LLM02, LLM06   | ASI02, ASI03       |

🟢 **enforce** = blocks the call · 🟡 detect = flags/warns (blocking is opt-in via config) · EoP = Elevation of Privilege

**Note on ShareLock (multi-tool split poisoning, arXiv:2606.27027).** v0.4 adds **cross-tool
correlation**: because bastion sees a server's whole tool set, it scans the combined descriptions and
flags coordinated `share`/`checksum`/`tool_id` staging metadata across tools — the pattern this attack
uses. This is a **heuristic for the staging signal**, not a cryptographic defeat of threshold
secret-sharing, so a sufficiently disguised variant can still evade it. When we added this vector,
**no** measured tool covered it; bastion is the first to detect it.

**Note on the v0.5 checks (rows 16–19).** Command injection, configuration drift, server-identity
pinning, and cross-server data-flow (taint) tracking each closed a vector that **no** measured tool on
the mcp-defense-bench leaderboard covered, taking bastion from 38% to **48% (11.5/24)** at zero false
positives. Cross-server taint uses **exact-token propagation** — a credential returned by one server
reappearing in an argument to a different server — which only an aggregating proxy can observe; it is
a heuristic for the staging-and-egress signal, not a proof. Server-identity change **enforces** (blocks
by default, like rug-pull); the others default to warn.

## Legend

**NIST AI RMF functions** — GOVERN (policies & accountability) · MAP (context & risk identification) ·
MEASURE (analyze & track risks) · MANAGE (act on & mitigate risks).

**OWASP Top 10 for LLM Applications (2025)** — LLM01 Prompt Injection · LLM02 Sensitive Information
Disclosure · LLM03 Supply Chain · LLM05 Improper Output Handling · LLM06 Excessive Agency ·
LLM07 System Prompt Leakage.

**OWASP Top 10 for Agentic Applications (2026)** — ASI01 Agent Goal Hijack · ASI02 Tool Misuse and
Exploitation · ASI03 Identity and Privilege Abuse · ASI04 Agentic Supply Chain Vulnerabilities ·
ASI05 Unexpected Code Execution (RCE).

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
- **NSA MCP Security — Security Design Considerations for AI-Driven Automation** (NSA AI Security
  Center, CSI, May 2026, U/OO/6030316-26) —
  https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf

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
