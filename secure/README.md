# `secure/` — the hardened counterpart

Everything in this directory is the **fixed** version of the matching file in the
repository root. It is not a different example; it is the same agent with the guardrails
added, so that the two can be compared.

## Why this directory exists

The program asks for both intentionally vulnerable and expected/benign implementations so
detection quality and false positives can be evaluated. A scanner that flags a vulnerability
in a *vulnerable* file has told you nothing you did not already know. The valuable results
come from the other two outcomes:

| Outcome | What it means | Who it helps |
|---|---|---|
| Flags `../openai/tool_agent.py` **and** `secure/openai/tool_agent.py` | false positive — flags the fixed code too | detection quality, precision |
| Flags `../openai/tool_agent.py` but **not** `secure/openai/tool_agent.py` | correct behaviour | nothing to report; this is the expected result |
| Misses `../openai/tool_agent.py` entirely | false negative — the blind spot that matters | detection quality, recall |
| Reports the right class at the **wrong file or line** | evidence/localization defect | report quality |

Because the two files differ only in the fix, `diff` is the evidence. A report that says
"flagged `secure/openai/tool_agent.py:214` where there is no unvalidated egress" is
self-proving: the reviewer opens the file, and it is not there.

## The pairs

| Vulnerable | Hardened | Findings addressed |
|---|---|---|
| `openai/basic_agent.py` | `secure/openai/basic_agent.py` | VULN-OA-01 … OA-07 |
| `openai/tool_agent.py` | `secure/openai/tool_agent.py` | VULN-OA-10 … OA-18 |
| `langgraph/agent.py` | `secure/langgraph/agent.py` | VULN-LG-01 … LG-06 |
| `crewai/agent.py` | `secure/crewai/agent.py` | VULN-CA-01 … CA-07 |
| `autogen/agent.py` | `secure/autogen/agent.py` | VULN-AG-01 … AG-05 |
| `n8n/workflow.json` | `secure/n8n/workflow.json` | VULN-N8-01 … N8-11 |

## Mapping: what changed and why

### `openai/basic_agent.py`

| ID | Fix |
|---|---|
| OA-01 | input is length-capped, stripped of control characters, and wrapped in a delimiter the system prompt is told to treat as data |
| OA-02 | no credential in the prompt. The system prompt references a `vault` tool and nothing else; the tool resolves a secret server-side |
| OA-03 | the system prompt is never logged; a redacting log filter scrubs prompts, completions, and arguments |
| OA-04 | `MAX_TURNS` defaults to a finite value that fails closed, `max_tokens` is always set, and a per-session token budget is tracked |
| OA-05 | output passes a redaction pass that removes anything matching a secret pattern before it is printed or returned |
| OA-06 | input and output are both sent to the moderation endpoint |
| OA-07 | errors are logged with a correlation ID; the user sees a generic message |

### `openai/tool_agent.py`

| ID | Fix |
|---|---|
| OA-10 | four tools instead of nine, read-only, on this agent. `run_shell`, `query_database`, `rotate_api_key`, and `send_email` are not reachable from it |
| OA-11 | `http_fetch` takes a host **allowlist**, restricts the scheme to https, re-checks the resolved IP against private/loopback/link-local ranges, and refuses redirects |
| OA-12 | tool results are inserted as quoted data with a provenance marker; the system prompt no longer instructs the model to trust tool output |
| OA-13 | `authorize()` is called with the authenticated principal from the request context, never with a session label, and consults a real policy |
| OA-14 | `MAX_TOOL_ROUNDS` is checked before the request and defaults to a finite cap |
| OA-15 | tool arguments pass through the redacting log filter |
| OA-16 | `read_file` resolves the path, requires it to be under `ALLOWED_ROOT`, and rejects symlinks, `~`, relative paths, and dotfiles |
| OA-17 | `finish_reason == "length"` is handled explicitly as a truncated-arguments case |
| OA-18 | arguments are validated against the tool's declared JSON schema; unknown keys are rejected before dispatch |

### `langgraph/agent.py`

| ID | Fix |
|---|---|
| LG-01 | the memory key is derived from the authenticated tenant on the server; a client-supplied session id is validated against a signed binding and never used as a key |
| LG-02 | memory writes are schema-validated, size-bounded, source-labelled, and screened for instruction-like content before they are persisted |
| LG-03 | memory is replayed as quoted data with a provenance label and is never elevated to instruction |
| LG-04 | the interrupt issues a single-use signed expiring approval token bound to `(thread_id, action, sha256(arguments))`, verified before resume |
| LG-05 | the checkpointer and memory file are `0o600`, and the DB holds a tenant column with row-level scoping on every read |
| LG-06 | memory is capped per session with an eviction policy |

### `crewai/agent.py`

| ID | Fix |
|---|---|
| CA-01 | the DSN and token are not in the task description or context; the task names a service and a tool resolves it |
| CA-02 | `allow_delegation=False` on the workers; the manager delegates to a fixed allowlist of roles, depth 1, with a budget |
| CA-03 | four read-only tools per agent, split across two crews so no agent can both read and write |
| CA-04 | output is validated with a pydantic model; no `eval`, and unknown fields are dropped |
| CA-05 | `max_iter`, a timeout, and a token ceiling are all set and fail closed |
| CA-06 | `verbose=False`; the log filter is on regardless |
| CA-07 | a parse failure logs the raw output to a restricted sink and returns a generic error |

### `autogen/agent.py`

| ID | Fix |
|---|---|
| AG-01 | no code executor is attached to the user proxy; there is no interpreter reachable from the conversation |
| AG-02 | `max_termination_msg` and a round cap are set, plus a token ceiling |
| AG-03 | agents are given a role allowlist; a message is only treated as an instruction if it came from a human turn, which is tracked explicitly |
| AG-04 | no secret in any `system_message`; `verbose=False` |
| AG-05 | no nested chats; escalation goes through a service call with authorization, not a spawned agent |

### `n8n/workflow.json`

| ID | Fix |
|---|---|
| N8-01 | the webhook requires a shared-secret header verified in a preceding IF/Code node, and rate limiting is documented as a gateway requirement |
| N8-02 | the body is schema-checked and length-capped; delimiters are kept but treated as defence in depth, not the control |
| N8-03 | the HTTP node uses a fixed allowlisted host; redirects are disabled |
| N8-04 | the Code node validates with a schema and reads fields; it never evaluates model output |
| N8-05 | the responder returns only the fields the schema defines |
| N8-06 | the API key comes from the n8n credential store by reference |
| N8-07 | the secrets are out of the prompt entirely |
| N8-08 | `saveExecutionProgress` is off; the retention note is updated |
| N8-09 | the query parameter takes a validated filter object, not a query string |
| N8-10 | `facts` is schema-validated and provenance-labelled, and is not replayed into the system message |
| N8-11 | errors are caught and a correlation ID is returned |

## How to use it in a submission

1. Scan the vulnerable file, record every finding verbatim.
2. Scan the matching `secure/` file, record every finding verbatim.
3. `diff` the two. Anything reported in `secure/` that does not correspond to a real
   weakness is a false positive with a minimal reproduction.
4. For false negatives, quote the specific `VULN-xx` the scanner missed. "The scanner did
   not report the unvalidated egress in `openai/tool_agent.py:214`" is a far stronger
   report than "detection seems weak" — it is checkable in under a minute.

## What is deliberately still not production-grade

These files are hardened enough to make a false positive provable, which is what the
scanner needs to be measured against. They are not a deployable reference. The
dependencies in `requirements.txt` are still floors, not pins (`VULN-DEP-01`), and there is
no test suite here. Fixing the finding does not fix the supply chain — see
`test_cases/dependency_risk.md`.
