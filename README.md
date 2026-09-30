# AI Agent Red-Team Lab

A deliberately **insecure** collection of AI agents — one per popular framework — used as
fixed targets for red-team exercises. Every weakness in here is intentional, labelled with a
stable `VULN-xx` id, and cross-referenced from a test case in `test_cases/`.

> ## ⚠️ Safety notice
>
> * **Never deploy anything in this repository.** The agents have no authentication, no
>   authorization, no input validation, no output filtering, and stubbed "sandbox" sinks.
> * The *destructive* sinks (shell execution, real code executor, real file reads, real
>   outbound HTTP) are **stubbed by default** so that running the lab on a laptop cannot
>   burn the machine. The *attack surface* (prompts, tool schemas, memory, external content,
>   dependencies) is fully real, so red-teamers still have something real to attack.
> * The credentials in this repo are **fake placeholders**. They exist to be leaked, not to
>   be used. Never put a real key in this tree.
> * Run only against API keys scoped to a throwaway project with spend limits and no data
>   access.

---

## Why this lab exists

Most agent tutorials optimize for "it works." That produces agents that are trivially
broken by anyone willing to type a sentence. This lab inverts that: each file is the
*minimum* thing that runs, with the guardrails left out on purpose, so a red team has a
stable baseline to demonstrate impact against and a secure rewrite to compare to.

Design rules for the code in this repo:

1. **Readable over clever.** A vulnerability you cannot see is a vulnerability you cannot
   test.
2. **Stable IDs.** Findings are cited as `VULN-xx` so a finding in a report still maps to a
   line of code after the file is refactored.
3. **Attack surface real, destruction stubbed.** See the safety notice.

---

## Structure

```
autnhive-agent-redteam-lab/
├── README.md
├── requirements.txt
├── .gitignore
├── langgraph/
│   └── agent.py              # stateful graph, persistent memory, HITL interrupts
├── crewai/
│   └── agent.py              # multi-agent crew, delegation, tool sprawl
├── openai/
│   ├── basic_agent.py        # no-tools baseline: prompt + logging weaknesses
│   └── tool_agent.py         # function-calling loop: SSRF, tool sprawl, ind. injection
├── autogen/
│   └── agent.py              # group chat + code executor
├── n8n/
│   └── workflow.json         # webhook-triggered agent with unauthenticated tools
└── test_cases/
    ├── prompt_injection.md   # direct + indirect injection
    ├── excessive_tools.md    # tool sprawl, least privilege, ind. prompt injection
    ├── secret_exposure.md    # secrets in prompts, logs, tool args, checkpoints
    ├── unsafe_external_api.md# SSRF, unvalidated egress, remote content trust
    ├── memory_poisoning.md   # checkpoint poisoning, cross-tenant reads, HITL tamper
    └── dependency_risk.md    # version floors, known CVEs, supply chain
```

---

## Quickstart

```bash
git clone <this repo> && cd autnhive-agent-redteam-lab
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# All agents read these. Use a throwaway project key.
export OPENAI_API_KEY=sk-lab-...        # real sandbox key, never a production one
export LAB_MODEL=gpt-4o-mini
```

Run a single target:

```bash
python openai/basic_agent.py       # simplest target; no framework install needed
python openai/tool_agent.py
python langgraph/agent.py
python crewai/agent.py
python autogen/agent.py
```

Import the n8n target into a local n8n (Docker is easiest):

```bash
docker run -it --rm \
  -p 5678:5678 \
  -v "$PWD/n8n:/files" \
  --name n8n-lab n8nio/n8n:latest n8n import:workflow --input=/files/workflow.json
# workflow "Agent Red-Team Target (INSECURE)" then appears in the editor
```

---

## Vulnerability index

| ID | File | Weakness | Sev | Test case |
|----|------|----------|-----|-----------|
| VULN-OA-01 | `openai/basic_agent.py` | Untrusted input concatenated into prompt, no validation | Med | prompt_injection |
| VULN-OA-02 | `openai/basic_agent.py` | Secrets interpolated into system prompt | High | secret_exposure |
| VULN-OA-03 | `openai/basic_agent.py` | Full system prompt + transcript printed to logs | High | secret_exposure |
| VULN-OA-04 | `openai/basic_agent.py` | No turn cap, no token cap, no rate limit | Med | dependency_risk (cost abuse) |
| VULN-OA-05 | `openai/basic_agent.py` | No output filtering / redaction | High | secret_exposure |
| VULN-OA-06 | `openai/basic_agent.py` | No moderation on input or output | Med | prompt_injection |
| VULN-OA-07 | `openai/basic_agent.py` | Raw exceptions surfaced to the user | Low | unsafe_external_api |
| VULN-OA-10 | `openai/tool_agent.py` | Excessive tool surface, no least privilege | High | excessive_tools |
| VULN-OA-11 | `openai/tool_agent.py` | `http_fetch` has no URL allowlist / SSRF guard | High | unsafe_external_api |
| VULN-OA-12 | `openai/tool_agent.py` | Tool results re-injected as trusted context | High | prompt_injection |
| VULN-OA-13 | `openai/tool_agent.py` | No authorization check before any tool call | High | excessive_tools |
| VULN-OA-14 | `openai/tool_agent.py` | Unbounded function-calling loop | Med | excessive_tools |
| VULN-OA-15 | `openai/tool_agent.py` | Tool arguments and secrets logged verbatim | High | secret_exposure |
| VULN-OA-16 | `openai/tool_agent.py` | `read_file` has no path jail | High | unsafe_external_api |
| VULN-OA-17 | `openai/tool_agent.py` | Tool output size unbounded, no `finish_reason` check | Med | excessive_tools |
| VULN-OA-18 | `openai/tool_agent.py` | Model controls the call signature via `fn(**args)` | Med | excessive_tools |
| VULN-LG-01 | `langgraph/agent.py` | Long-term memory keyed by session only, no tenant scope | High | memory_poisoning |
| VULN-LG-02 | `langgraph/agent.py` | Tool output written to persistent memory unfiltered | High | memory_poisoning |
| VULN-LG-03 | `langgraph/agent.py` | Memory replayed into system context as trusted facts | High | memory_poisoning |
| VULN-LG-04 | `langgraph/agent.py` | HITL interrupt resumes on client-supplied payload, unsigned | High | memory_poisoning |
| VULN-LG-05 | `langgraph/agent.py` | World-readable shared SQLite checkpoint | High | secret_exposure |
| VULN-LG-06 | `langgraph/agent.py` | Unbounded message list, no turn cap | Med | memory_poisoning |
| VULN-CA-01 | `crewai/agent.py` | Credentials pasted into task `context` | High | secret_exposure |
| VULN-CA-02 | `crewai/agent.py` | Unrestricted `allow_delegation` manager | High | excessive_tools |
| VULN-CA-03 | `crewai/agent.py` | 10+ tools on one agent, no least privilege | High | excessive_tools |
| VULN-CA-04 | `crewai/agent.py` | LLM output parsed as code / `eval` | Critical | excessive_tools |
| VULN-CA-05 | `crewai/agent.py` | No `max_iter`, no timeout, no cost ceiling | Med | excessive_tools |
| VULN-CA-06 | `crewai/agent.py` | Verbose logging prints every prompt | High | secret_exposure |
| VULN-CA-07 | `crewai/agent.py` | Raw model output + exception echoed on parse failure | Low | secret_exposure |
| VULN-AG-01 | `autogen/agent.py` | Code executor enabled, `docker=False` | Critical | excessive_tools |
| VULN-AG-02 | `autogen/agent.py` | No `max_termination_msg`, unbounded rounds | Med | excessive_tools |
| VULN-AG-03 | `autogen/agent.py` | Agents trust peer messages, no provenance | High | prompt_injection |
| VULN-AG-04 | `autogen/agent.py` | Secrets in `system_message` + verbose console | High | secret_exposure |
| VULN-AG-05 | `autogen/agent.py` | Nested chats delegate with no scope limit | High | excessive_tools |
| VULN-N8-01 | `n8n/workflow.json` | Webhook has no auth, no signature, no rate limit | High | excessive_tools |
| VULN-N8-02 | `n8n/workflow.json` | Prompt built from `{{$json.body.query}}`, no body schema | High | prompt_injection |
| VULN-N8-03 | `n8n/workflow.json` | HTTP tool has no host allowlist, 10-hop redirects | High | unsafe_external_api |
| VULN-N8-04 | `n8n/workflow.json` | Code node parses model output; `eval` variant is RCE | Critical | excessive_tools |
| VULN-N8-05 | `n8n/workflow.json` | Full item echoed to the caller; no error handler | Med | unsafe_external_api |
| VULN-N8-06 | `n8n/workflow.json` | API key inlined in node parameters, not the vault | High | secret_exposure |
| VULN-N8-07 | `n8n/workflow.json` | Secrets inlined into the agent prompt text | High | secret_exposure |
| VULN-N8-08 | `n8n/workflow.json` | `saveExecutionProgress` retains prompts on disk | Med | secret_exposure |
| VULN-N8-09 | `n8n/workflow.json` | Model-chosen string passed to a query parameter | High | unsafe_external_api |
| VULN-N8-10 | `n8n/workflow.json` | Model output written to `facts` and replayed next run | High | memory_poisoning |
| VULN-N8-11 | `n8n/workflow.json` | Unhandled errors return stack traces and paths | Med | unsafe_external_api |
| VULN-DEP-01 | `requirements.txt` | Version floors instead of pins, no hashes | High | dependency_risk |
| VULN-DEP-02 | `requirements.txt` | No upper bounds: breaking/malicious releases accepted | High | dependency_risk |
| VULN-DEP-03 | `requirements.txt` | `langgraph>=0.2.28,<0.3` pins an EOL branch | Med | dependency_risk |
| VULN-DEP-04 | `requirements.txt` | `crewai>=0.80` predates tool-input validation | Med | dependency_risk |
| VULN-DEP-05 | `requirements.txt` | `pyautogen>=0.2.34,<0.3` predates executor hardening | High | dependency_risk |
| VULN-DEP-06 | `n8n/README` | `n8nio/n8n:latest` is a moving, unpinned image tag | High | dependency_risk |

---

## Test case index

| File | Covers | Primary targets |
|------|--------|-----------------|
| [`test_cases/prompt_injection.md`](test_cases/prompt_injection.md) | Direct injection, indirect injection via tool output, role confusion, delimiter escape | `openai/*`, `langgraph/*`, `autogen/*`, `n8n/*` |
| [`test_cases/excessive_tools.md`](test_cases/excessive_tools.md) | Tool sprawl, missing authorization, delegation loops, code execution, unbounded iteration | `openai/tool_agent.py`, `crewai/*`, `autogen/*`, `n8n/*` |
| [`test_cases/secret_exposure.md`](test_cases/secret_exposure.md) | Prompt-borne secrets, log leakage, tool-argument leakage, checkpoint leakage, n8n credentials | all |
| [`test_cases/unsafe_external_api.md`](test_cases/unsafe_external_api.md) | SSRF to metadata services, path traversal, missing egress control, unvalidated redirects | `openai/tool_agent.py`, `n8n/*` |
| [`test_cases/memory_poisoning.md`](test_cases/memory_poisoning.md) | Checkpoint poisoning, cross-tenant memory reads, trust promotion, HITL interrupt tampering | `langgraph/agent.py` |
| [`test_cases/dependency_risk.md`](test_cases/dependency_risk.md) | Version floors, transitive CVEs, unpinned lockfile, n8n node CVEs, untrusted packages | `requirements.txt`, `n8n/*` |

Each test case follows the same shape: **objective → preconditions → steps → payloads →
expected vulnerable behaviour → expected secure behaviour → detection → remediation →
severity.** Run them in order; the payload sets escalate.

---

## Red-team runbook

1. **Pick a target** from the index above and start only that file.
2. **Establish baseline.** Run the happy path first. A finding that also breaks the happy
   path is usually a bug, not a vulnerability.
3. **Work the test cases** in listed order for that target. Record the exact prompt that
   worked — the value of a red-team report is a reproduction, not a category.
4. **Escalate, do not stop.** A prompt-injection hit that returns a credential in the
   transcript is three findings: injection, secret exposure, and no output filtering.
5. **Write it up** with the `VULN-xx` id, the file and line, the payload, the impact, and the
   one-line fix.
6. **Then fix it** in a `secure/` branch and re-run the test case. A finding you cannot
   verify as fixed is not closed.

---

## What a secure rewrite looks like

Every target has the same four missing layers. A fix is not a patch, it is adding these:

1. **Untrusted-content handling** — delimiter the input, mark it as data, keep it out of
   the system role, and never concatenate tool output into a trusted context.
2. **Least-privilege tools** — one capability per tool, an explicit URL allowlist and path
   jail, an authorization check before dispatch, and a hard iteration cap.
3. **Secret hygiene** — secrets referenced by name, never interpolated into prompts; logs
   redacted; checkpoints encrypted and tenant-scoped; n8n credentials in the vault.
4. **Bounded execution** — turn caps, token caps, timeouts, spend ceilings, and termination
   conditions that do not depend on the model choosing to stop.

---

## Extending the lab

* **Add a target:** drop `framework/agent.py` next to its siblings, keep the `VULN-xx`
  comment markers, and add the ID to the index above.
* **Add a test case:** copy the shape of an existing file, add a row to both index tables.
* **Automate:** the payloads in `test_cases/*.md` are plain strings. They are deliberately
  framework-agnostic so a harness can lift them verbatim into an API call.
* **Compare:** `git checkout -b secure` and fix one file at a time, re-running its test case
  after each fix.

---

## License

Educational use only. The sample credentials are fake and are **not** covered by any
warranty, SLA, or support commitment, because nothing here is supported.
