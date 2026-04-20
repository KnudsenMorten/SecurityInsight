# Release notes for SecurityInsight

## v2.1.118

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- fix(SI _shared): emit 'Checking N modules...' banner so customers don't think it hung (a463dd2b)
- feat(SI): daily auto-refresh via scheduled Step 0 task (8c9a00f8)
- fix(SI _shared): suppress Ensure-SecurityInsightModules hashtable output (b6d75cea)
- refactor(SI): single-source module set -- Ensure-SecurityInsightModules (88cd89b1)
- refactor(SI): centralize module guards -- every engine uses _shared/Ensure-Module (ab435826)
- feat(SI): centralize Ensure-Module helper under SCRIPTS/_shared/ (6ccf68f9)
- feat(SI YAML): merge Custom queries into Locked (ship curated defaults) (28662620)
- fix(SI Step0 bootstrap): resolve latest tag then fetch tag-pinned raw (9810c130)
- fix(SI Step0): banner reads 'Step 0' not 'Step 1' (post-renumber leftover) (eb655c70)
- fix(SI Step0): per-file [UPDATE]/[PRESERVE] log so policy is visible (508bb2ce)
- docs(SI README): add v2.1.88..v2.1.108 highlights to changelog (f26470df)
- fix(SI Step0): use Invoke-WebRequest -OutFile in bootstrap, not irm | Out-File (160bffa1)
- docs(SI README): cleaner override pattern in real-world sample (0c394553)
- docs(SI README): add real-world RiskAnalysis .custom.ps1 sample (redacted) (d710a888)
- feat(SI mail): add $global:SMTPFrom for verified-sender From header (v2.1.108) (8e770613)
- fix(SI workbook): preselect '*' to dodge empty-list KQL parse error (v2.1.107) (b7658920)
- fix(SI Workbook): filters use "empty = no filter" semantics -- no default value needed (9e12fea6)
- docs(SI SetupConfigurator): add "Built by Morten Knudsen" branding (c0a1e0d2)
- feat(SI SetupConfigurator): copy-to-clipboard "run-command" button (855d0923)
- refactor(SI): renumber Steps -- install=Step0, Permissions=Step1, LA=Step2, OpenAI=Step3, PowerBI=Step4 (636efc49)
- fix(SI Workbook): use built-in value::all sentinel so "All" pre-selects reliably (da634d58)
- feat(SI IdentityAssets + Workbook): stamp SolutionVersion on identity rows too (39ec5e31)
- feat(SI RiskAnalysis + Workbook): version stamping end-to-end (929b6435)
- fix(SI Workbook): resource picker needs explicit ARG filter query (27c81fff)
- fix(SI Workbook): resource picker -- use Azure Resource Graph (queryType 1) (d8f2f81f)
- fix(SI Workbook): workspace picker at top + '*' sentinel for multi-select "All" (deccb5b7)
- feat(SI Workbook): ship Azure Monitor Workbook JSON + import doc (0a366e0b)
- docs(SI README): extend §1 Introduction with Outputs + Use-cases sections (2d898254)
- docs(SI Step5): Setup Configurator tab + PowerBI-Prerequisites doc + README (ed381c2f)
- feat(SI Step5): launcher infra (4 flavours) + SendToPowerBI per-run refresh (51b83727)

---


