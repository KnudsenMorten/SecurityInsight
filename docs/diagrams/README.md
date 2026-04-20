# SecurityInsight — Diagrams for Slides & Docs

The 7 Mermaid diagrams from the main README, extracted as standalone `.mmd` files so you can render them to PNG / SVG / PDF for slide decks, blog posts, or whitepapers — without copy-pasting from the README every time.

| File | What it shows | README section |
|---|---|---|
| `01-attack-path.mmd` | A 4-hop attacker path (user device → app server → service account → DC). Why we use a graph instead of a list. | § 2.1 |
| `02-risk-score-formula.mmd` | The Risk Score math: Severity × (Criticality + Risk Factors). | § 2.2 |
| `03-high-level-overview.mmd` | The 7-step implementation workflow, from GitHub download to running Risk Analysis. | § 3.1 |
| `04-yaml-merge-flow.mmd` | How the engine merges Locked + Custom YAML files (Custom wins on name collision). | § 6.2 |
| `05-yaml-upgrade-before-after.mmd` | What a release upgrade does to your YAML files (Locked replaced; Custom untouched). | § 6.5 |
| `06-layered-config-flow.mmd` | The 5-layer launcher config waterfall (defaults → platform → solution-wide → per-engine → CLI args). | § 7.7 |
| `07-end-to-end-architecture.mmd` | End-to-end architecture: data sources → engines → outputs. | § 7.8 |

## Render to PNG / SVG / PDF

### Easiest — Mermaid Live Editor (browser, no install)

1. Open <https://mermaid.live>
2. Open the `.mmd` file → copy the contents → paste into the editor
3. Click **Actions → PNG / SVG / PDF**

### Local — Mermaid CLI (`mmdc`)

For batch renders or CI pipelines.

**One-time install** (Node.js 18+ required):

```powershell
npm install -g @mermaid-js/mermaid-cli
mmdc --version
```

**Render all diagrams to PNG** (1920px wide, transparent background):

```powershell
cd SOLUTIONS\SecurityInsight\DOCS\diagrams
Get-ChildItem -Filter '*.mmd' | ForEach-Object {
    $out = $_.FullName -replace '\.mmd$', '.png'
    mmdc -i $_.FullName -o $out -w 1920 -b transparent
}
```

**Render a single diagram to SVG** (scalable for slides):

```powershell
mmdc -i 07-end-to-end-architecture.mmd -o 07-end-to-end-architecture.svg
```

**Render to PDF** (for whitepapers):

```powershell
mmdc -i 02-risk-score-formula.mmd -o 02-risk-score-formula.pdf
```

### VS Code preview (no export)

Install the **Markdown Preview Mermaid Support** extension (`bierner.markdown-mermaid`). Open any `.mmd` file → `Ctrl+Shift+V` for live preview.

## Color palette (for slide consistency)

The 7 diagrams use a consistent 5-colour palette so all slides look like they belong together:

| Role | Fill | Stroke | When |
|---|---|---|---|
| Source / shipped-by-us | `#e8f4fd` | `#2a6592` | Locked YAMLs, Layer 1, GitHub source |
| Customer-edited | `#e8ffe8` | `#1a7a1a` | Custom YAMLs, Layer 3, your overrides |
| Platform shared (internal) | `#fff4e1` | `#b07a00` | Layer 2 platform-defaults |
| Per-engine (internal customer state) | `#fce4ec` | `#a83275` | Layer 4 LauncherConfig.custom.ps1 |
| CLI args / last-word | `#ede7f6` | `#512da8` | Layer 5 invocation parameters |
| Final / effective state | `#fff9c4` | `#b07a00` (bold) | Risk Score output, effective config |

Reuse these in your own slide diagrams to keep brand consistency.

## License

Same as the parent solution — MIT. Use freely in customer presentations, conference talks, blog posts.
