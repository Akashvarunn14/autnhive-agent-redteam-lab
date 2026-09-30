# Test case: dependency and supply-chain risk

**Targets:** `requirements.txt` (VULN-DEP-01 … VULN-DEP-06), `n8n/workflow.json` (node
`typeVersion` pins), and the `n8nio/n8n:latest` image tag from the README

**Objective:** establish whether the lab's (or any real agent's) runtime can be assumed
trustworthy, and produce the concrete inventory that a dependency finding needs: what is
installed, what is known-vulnerable, and what runs with production credentials.

**Preconditions**
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Severity:** High by default. Critical when a vulnerable component is reachable from
model-controlled input (which, in an agent, is most of them).

---

## 1. Inventory

```bash
pip freeze | sort > lab_freeze.txt
pip list --outdated --format=columns
```

Keep `lab_freeze.txt` as the attachment. An agent finding without an installed-version
list is not reproducible.

## 2. Known vulnerabilities

```bash
pip-audit -r requirements.txt
safety check --full-report -r requirements.txt
```

**What to expect from this repo's floors** (VULN-DEP-03 … VULN-DEP-05):

| Floor | Why it is a finding |
|---|---|
| `langgraph>=0.2.28,<0.3` | 0.2.x is end-of-life. No patches will ship. |
| `crewai>=0.80` | predates tool-input validation hardening |
| `pyautogen>=0.2.34,<0.3` | predates code-executor hardening; the pydantic v1 shim path |
| `openai>=1.40` | no upper bound (VULN-DEP-02) |

Report these as **High: unmaintained or pre-hardening dependency floor**, with the
mitigation being "raise the floor to the first patched release", not "we accept the risk".

## 3. No pins, no hashes (VULN-DEP-01, VULN-DEP-02)

Every requirement is a floor with no `==` and no `--hash`. Consequences to state plainly:

- A **yanked or compromised release** is accepted on the next `pip install` with no
  review, because the resolver takes the newest matching version.
- A **supply-chain compromise** of any one of these packages executes at install time,
  before the agent runs, with the developler's credentials.
- Builds are **not reproducible**: two installs of the same repo a week apart differ, so
  no test result is attributable.

Demonstrate non-reproducibility without installing anything:

```bash
pip install --dry-run --report -r requirements.txt | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(len(d['install']), 'packages resolved')"
```

Then compare against `lab_freeze.txt`. If the resolution differs from the freeze, the
lockfile is not doing its job.

## 4. Transitive attack surface

The direct list is the smaller problem. The agents pull in large transitive trees:

```bash
pip install pipdeptree -q && pipdeptree --graph | head -60
```

```bash
# Every package with a setup-time hook is install-time code execution.
python3 -c "
import importlib.metadata as md
for d in md.distributions():
    hooks = [e for e in (d.entry_points or []) if e.group == 'console_scripts']
    if hooks: print(f'{d.metadata[\"Name\"]:<40} {len(hooks)} entry points')
" | sort -k2 -rn | head -20
```

In an agent deployment the packages of interest are the ones that **touch model output**:
template engines, YAML loaders, deserializers, notebook and code-execution libraries, and
anything that shells out. Those are the ones where "vulnerable version" plus "model
controls the input" equals a clean exploit chain.

```bash
# Where does model output actually flow in this repo?
rg -n 'eval\(|exec\(|pickle\.loads|yaml\.load\(|subprocess|os\.system|JSON\.parse' \
   --glob '!*.md'
```

Every hit is a dependency on the runtime being trustworthy. That is the argument for
eliminating the capability, not for updating the library.

## 5. n8n node versions and the image tag (VULN-DEP-06)

`n8n/workflow.json` pins each node by `typeVersion` but not by n8n version, and the
README runs `n8nio/n8n:latest` — a **moving tag**. So:

- A workflow that worked yesterday may break today, with no change on your side.
- The node set, and therefore the security posture, changes without a deploy.
- CVEs in n8n or in community nodes are inherited on the next `docker pull`.

```bash
docker images n8n/n8n --digests
pip list --outdated --format=columns | grep -i n8n
```

The `Code` node (VULN-N8-04) makes this materially worse: it runs JavaScript inside the
n8n server process, so *the n8n version and its `NODE_FUNCTION_ALLOW_*` settings are part
of your agent's trust boundary*. A Code node is a dependency with an internet-facing API.

## 6. Runtime privileges

```bash
id; docker inspect --format '{{.Config.User}}' n8n-lab 2>/dev/null
```

If the n8n container, the agent process, or the code executor runs as root with the host
network and a mounted Docker socket, then every dependency above inherits root. Write
this into the finding: dependency risk is only as bad as the privileges of the process
that loads the dependency.

---

## Detection

- `pip-audit` / `safety` in CI, failing the build, not warning.
- A committed lockfile with hashes, regenerated on a schedule and on every bump.
- A weekly outdated check with an SLA, and a named owner for framework floors.
- Pin the container by digest, not by tag. Run it as a non-root user with a read-only
  root filesystem and no Docker socket.
- Alert on new transitive dependencies appearing in a release diff.

## Remediation

1. **Pin exactly, with hashes.** `pip-compile --generate-hashes` into a committed
   `requirements.lock`, and install with `--require-hashes`.
2. **Raise the floors** to the first release of each framework that includes the
   tool-input and executor hardening. An unmaintained branch is not an accepted risk, it
   is a scheduled incident.
3. **Set upper bounds** so a breaking or malicious release cannot be taken silently.
4. **Pin `n8nio/n8n` by digest** and run non-root with a read-only filesystem.
5. **Reduce the dependency surface by removing capabilities.** The strongest fix for
   VULN-N8-04 and VULN-AG-01 is to not have an interpreter reachable from a conversation.
   Fewer dependencies is a security control, not just maintenance hygiene.
6. **Re-scan after every bump**, and treat a framework major upgrade as a security change
   requiring re-running `excessive_tools.md`.
