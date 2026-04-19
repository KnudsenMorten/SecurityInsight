# SecurityInsight

Auto-published from upstream [AutomateIT](https://github.com/KnudsenMorten/AutomateIT).

> Want to try unreleased features? git checkout preview

## Layout

- scripts/    engine scripts
- launchers/ community launchers (one per engine, multiple host flavours)
- data/      data files (yaml/csv/json)
- docs/      solution documentation
- samples/   shareable templates / sample inputs

## Running

Each launcher folder contains LauncherConfig.sample.ps1. Copy to LauncherConfig.ps1 and fill
in your SPN credentials (or use the -azure variant with Managed Identity), then run the
matching launcher.community-*.template.ps1.

See the author's blog for walkthroughs:
- https://mortenknudsen.net
- https://aka.ms/morten

## Contributing

This repo is auto-generated from the upstream monorepo monorepo. See CONTRIBUTING.md for how PRs flow.
