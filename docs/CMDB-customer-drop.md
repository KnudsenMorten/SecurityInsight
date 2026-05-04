# Customer CMDB drop point

Drop your `CMDB.csv` file at `v2.2/asset-profiling-providers/servicenow-cmdb/CMDB.csv`. It is the **standard customer location** that `Refresh-CmdbCache.ps1` looks for by default.

## Lookup order

`v2.2/asset-profiling-providers/servicenow-cmdb/Refresh-CmdbCache.ps1` resolves the CSV path in this order:

1. **`$global:SI_CmdbCsvPath`** — explicit override set in your `config/SecurityInsight.custom.ps1`. Use this when your CMDB lives outside the SI repo (e.g. `\\fileshare\IT\cmdb-export.csv` or `D:\customer-data\cmdb.csv`).
2. **`v2.2/asset-profiling-providers/servicenow-cmdb/CMDB.csv`** — this location. Standard customer drop point. Gitignored, never committed back to the SI repo on `git pull`.
3. **`v2.2/asset-profiling-providers/servicenow-cmdb/sample/CMDB.csv`** — last-resort sample data shipped with the engine. Used when neither (1) nor (2) is set.

## Required CSV columns

```
cmdbID;cmdbName;DataSensitivity;Criticality;Owner;OwnerMail
```

Any additional columns you add (e.g. `BusinessUnit`, `Environment`, `SLA`, `CostCenter`) flow through automatically — `Refresh-CmdbCache.ps1` surfaces every column into the cmdbservices table, and the row builders surface them under `Properties.collect.cmdb` in each engine's profile table.

## Schedule

Run `Refresh-CmdbCache.ps1` whenever your CMDB changes. The engine reads the cached snapshot (Azure Table `sicmdbservices`); it never reads this CSV directly during an engine run.

```powershell
& '<repo>\v2.2\asset-profiling-providers\servicenow-cmdb\Refresh-CmdbCache.ps1'
```
