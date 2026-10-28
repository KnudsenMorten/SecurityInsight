# Pre-publish gate — Pester tests

Comprehensive Pester v5 test suite that gates `securityinsight-v2.2.0-preview*` releases. Runs locally before commit, runs in GitHub Actions on every PR that touches `SOLUTIONS/SecurityInsight/`.

## Run locally

```powershell
# One-shot, with summary + verdict (v3: PowerShell 7 only -- started from 5.1 it re-runs itself under pwsh)
pwsh -NoProfile -File .\Invoke-PrePublishGate.ps1

# With per-test output (debugging failures)
pwsh -NoProfile -File .\Invoke-PrePublishGate.ps1 -Detailed

# Direct Pester invocation (full Pester output)
Import-Module Pester -MinimumVersion 5.0
Invoke-Pester -Path .\SI-v2.2.PrePublish.Tests.ps1 -Output Detailed
```

Exit codes from `Invoke-PrePublishGate.ps1`:

- **0** — all green, publish gate **READY**
- **1** — one or more failures, publish gate **BLOCKED**
- **2** — setup failure (Pester missing, test file missing, etc.)

## What gets tested (9 categories)

| Category | What it gates | Fix when red |
|---|---|---|
| `RepoHygiene` | No customer-only / secret files tracked in git | `git rm --cached` the leak; verify `.gitignore` covers it |
| `YamlValidity` | Every `*.locked.yaml` + `*.custom.sample.yaml` parses | Fix the YAML; common cause = unquoted colon in a value |
| `JsonValidity` | Every JSON under `v2.2/` parses; locked JSON has required keys | Fix syntax; verify `$schema` declared |
| `PowerShellSyntax` | Every `.ps1` tokenizes without parse errors (PS 5.1) | Fix syntax; remember PS 5.1 has no `?.` / `??` |
| `RAReportStructure` | Every Report has required fields, ReportName unique, SecurityDomain in allowed set, ReportPurpose >= 80 chars | Add missing fields; enrich purpose; fix duplicate names |
| `TemplateCoverage` | Every Report appears in some ReportTemplate; no ghost references | Add to template's `ReportsIncluded`; remove ghost name |
| `DocConsistency` | README report counts match YAML; every `[link](docs/X.md)` resolves | Update README count; create missing doc |
| `SampleQuality` | No empty `.custom.sample.json` stubs; every `.locked.json` schema has a sample sibling | Hand-craft a representative sample |
| `WorkflowSyntax` | `.github/workflows/publish.yml` parses as YAML | Fix workflow YAML |

## Prereqs

- PowerShell 5.1 OR pwsh 7+
- `Pester` >= 5.0 — `Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser`
- `powershell-yaml` — OPTIONAL. SecurityInsight reads YAML with its own reader (`engine/_shared/SI-Yaml.ps1`);
  powershell-yaml is only the reference for the parity check in `SIv3-SIYaml.Tests.ps1`, which is skipped without it.
- `git` available on PATH (RepoHygiene tests use `git ls-files`)

## CI integration

`.github/workflows/si-v22-prepublish.yml` runs this gate on every PR to `main`/`preview/v2.2` that touches `SOLUTIONS/SecurityInsight/`. PRs cannot merge while the gate is BLOCKED. Customize the trigger paths in that workflow.

## Adding new tests

Add a new `Context` or `Describe` block to `SI-v2.2.PrePublish.Tests.ps1`. Pester v5 auto-discovers them. The runner aggregates by top-level Describe name -- so create a new Describe to get a new summary line, or reuse an existing one to fold into an existing category.

If you add a test that exercises a new category, also update the table above.
