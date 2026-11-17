# Plain-language guard mails -- before and after

Owner 2026-11-16: "Customers dont understand this mail". Rendered on the Azure test runner from the REAL functions
(`tests/fixtures/plain-mails/Render-PlainMailPreview.ps1 -Base e25f7def6...`), with realistic numbers: contoso-like
(3 numbers higher than usual, biggest +40 %), example A (devices 990 -> 697, held), example B (Defender data 2 days old).
Same data and the same mail layout (MAIL-2); only wording and order change.

Not in SecurityInsight: the support ticket titled "Source <name> has fallen behind" is written by Invardia
(`packages/core/src/statealerts.ts`), not by SI, and SI sends no mail of that name. Its SI side -- the note on every
mail and the web app's banner while a data source is on its last good read, and the run-report line -- is section 2.

The Guards page NAME of the hold check is unchanged on purpose: it feeds the generated settings catalog (a rename
needs the catalog rebuilt); only the texts a customer reads about the hold changed.

### BEFORE (the code at e25f7def6)

#### 1. The daily data-quality mail

#### contoso-like: 3 numbers higher than usual, the biggest +40 %

**Subject:** `[PROD] contoso-prod - Warning: More than usual in the latest data -- nothing was lost [SecurityInsight]`

**First lines (as the mail text reads):**

```text
SecurityInsight

More than usual in the latest data -- nothing was lost

in the run of 2026-11-16 02:00 UTC, 3 numbers were clearly different from the last 3 runs. The biggest: Active CIs of type workstation -- 1,400 now, usually 1,000 (+40 % of all active CIs).

In short

What happened: in the run of 2026-11-16 02:00 UTC, 3 numbers were clearly different from the last 3 runs. The biggest: Active CIs of type workstation -- 1,400 now, usually 1,000 (+40 % of all active CIs).

Is anything lost: no. This is a check only -- nothing was blocked or deleted. An asset a source no longer lists is kept for its grace period, never removed at once.

Does anyone have to act: usually not. If you know why (for example devices or Azure resources were removed on purpose), nothing is needed -- the usual range follows the new level after three runs. If you do not know why, see "What you can do" below.

```

**Section headings:** "More than usual in the latest data -- nothing was lost" / "In short" / "Why this mail" / "What you can do" / "The numbers" / "Run summary"

**Rest of the mail (the reasons, what you can do, the numbers):**

```text
Why this mail
No setting was changed since the previous run, so the source data itself changed -- or a collection was incomplete.
What you can do
- If a setting was changed just before (named under "Why this mail"), and the change was not meant to do this, correct the setting.
- Then open the Data quality panel (Details below) and use Re-run from here on the warning -- or on the step it names in Operations > Jobs -- so the numbers are measured again.
- If the change is expected (for example assets were removed on purpose), nothing needs doing: the usual range follows the new numbers after three runs.
Nothing was blocked: every step ran and delivered as usual. This is a warning only.
The numbers
Active CIs of type workstation: 1,400 now, expected 990 / 1,000 / 1,010 (last 3 runs), change +40 % of all active CIs
Active CIs in tier 2: 850 now, expected 590 / 600 / 610 (last 3 runs), change +25 % of all active CIs
CIs not seen any more (to retire): 235 now, expected 30 / 25 / 20 (last 3 runs), change +21 % of all active CIs
Run summary
Run: 2026-11-16 02:00 UTC
Anomaly detected: Yes
Key numbers outside the range: 3
Largest delta vs expected: +40 % of all active CIs (Active CIs of type workstation)
Compared with: The median of the last 3 runs
Details (https://si.example.test/Admin/DataQuality?run=run-1)
A data-quality mail goes out only when the key numbers outside their expected range change -- a new one, or one that is back within its range -- and at most once a day. The limits: Settings > Guards (safety checks) > Data-quality warnings.
```

#### example A: devices 990 -> 697

**Subject:** `[PROD] contoso-prod - Warning: Fewer than usual in the latest data -- nothing was lost [SecurityInsight]`

**First lines (as the mail text reads):**

```text
SecurityInsight

Fewer than usual in the latest data -- nothing was lost

in the run of 2026-11-16 02:00 UTC, 1 number was clearly different from the last 3 runs. The biggest: Assets from Defender for Endpoint (endpoint profiler) -- 697 now, usually 990 (-30 %).

In short

What happened: in the run of 2026-11-16 02:00 UTC, 1 number was clearly different from the last 3 runs. The biggest: Assets from Defender for Endpoint (endpoint profiler) -- 697 now, usually 990 (-30 %).

Is anything lost: no. This is a check only -- nothing was blocked or deleted. An asset a source no longer lists is kept for its grace period, never removed at once.

Does anyone have to act: usually not. If you know why (for example devices or Azure resources were removed on purpose), nothing is needed -- the usual range follows the new level after three runs. If you do not know why, see "What you can do" below.

```

**Section headings:** "Fewer than usual in the latest data -- nothing was lost" / "In short" / "Why this mail" / "What you can do" / "The numbers" / "Run summary"

**Rest of the mail (the reasons, what you can do, the numbers):**

```text
Why this mail
No setting was changed since the previous run, so the source data itself changed -- or a collection was incomplete.
What you can do
- If a setting was changed just before (named under "Why this mail"), and the change was not meant to do this, correct the setting.
- Then open the Data quality panel (Details below) and use Re-run from here on the warning -- or on the step it names in Operations > Jobs -- so the numbers are measured again.
- If the change is expected (for example assets were removed on purpose), nothing needs doing: the usual range follows the new numbers after three runs.
Nothing was blocked: every step ran and delivered as usual. This is a warning only.
The numbers
Assets from Defender for Endpoint (endpoint profiler): 697 now, expected 985 / 990 / 995 (last 3 runs), change -30 %
Run summary
Run: 2026-11-16 02:00 UTC
Anomaly detected: Yes
Key numbers outside the range: 1
Largest delta vs expected: -30 % (Assets from Defender for Endpoint (endpoint profiler))
Compared with: The median of the last 3 runs
Details (https://si.example.test/Admin/DataQuality?run=run-1)
A data-quality mail goes out only when the key numbers outside their expected range change -- a new one, or one that is back within its range -- and at most once a day. The limits: Settings > Guards (safety checks) > Data-quality warnings.
```

#### 2. A data source is behind (example B: Defender data 2 days old)

**The note every SecurityInsight mail carries while a data source is on its last good read (and the banner on every web page):**

> Endpoint data is from 2026-11-14 07:12 UTC -- the last collection from that source did not complete.

**The line in the run report (Operations > Jobs):**

> endpoint has had no good collection for 2 day(s) -- its data is from 2026-11-14 07:12 UTC

#### 3. The hold when a data source sends far fewer assets (example A: devices 990 -> 697, held)

**Guards page name:** Collection: far fewer assets from one source

**Guards page (what happened / why / what it means for you / what to do):**

```text
What happened: A source returned far fewer assets than in its last good collection, so the assets it no longer lists were kept as they were.
Why: This check stops a source that answered only in part from making healthy assets look gone. mde device records: 697 in this collection against 990 in the last good one (-29.6 %) -- the last good collection is kept until the next complete collection shows the same level.
What it means for you: Nothing is lost: the run went on, the assets the source no longer lists stay active with their last known data, and no CI is retired and no finding is closed because of the drop. A real clean-up takes effect one run later.
1. Check the source if the drop is not expected (for example a lost permission, a changed scope or a failed sign-in).
2. If the drop is real, do nothing: the next complete collection that shows the same level is accepted by itself.
3. To accept such drops at once from now on, choose accept for this check under Control on the Guards page.
```

**The line in the run report and the run log:**

> A source returned far fewer assets than in its last good collection, so the assets it no longer lists were kept as they were. Cause: mde device records: 697 in this collection against 990 in the last good one (-29.6 %) -- the last good collection is kept until the next complete collection shows the same level. Where: job si-endpoint, mde device. Numbers: Assets in the last good collection: 990; Assets in this collection: 697; Change: -29.6 % (limit -15 %); 293 held. What to do: 1. Check the source if the drop is not expected (for example a lost permission, a changed scope or a failed sign-in). 2. If the drop is real, do nothing: the next complete collection that shows the same level is accepted by itself. 3. To accept such drops at once from now on, choose accept for this check under Control on the Guards page.

(This check sends no mail of its own -- catalog "mail": "never".)



### AFTER (this branch)

#### 1. The daily data-quality mail

#### contoso-like: 3 numbers higher than usual, the biggest +40 %

**Subject:** `[PROD] contoso-prod - Notice: Some numbers are higher than usual - no action needed [SecurityInsight]`

**First lines (as the mail text reads):**

```text
SecurityInsight

Some numbers are higher than usual - no action needed

In the run of 2026-11-16 02:00 UTC, 3 numbers were higher than usual. The biggest change: active assets of type workstation -- 1,400 now, usually 1,000 (+40 % of all active assets).

In short

What happened: In the run of 2026-11-16 02:00 UTC, 3 numbers were higher than usual. The biggest change: active assets of type workstation -- 1,400 now, usually 1,000 (+40 % of all active assets).

Is anything lost: No. Nothing was deleted or blocked. An asset that a data source no longer lists is kept for some days. It is not removed at once.

Do you need to do anything: No, unless you did not add devices, users or Azure resources and did not change a setting. Then see "What you can do" below.

```

**Section headings:** "Some numbers are higher than usual - no action needed" / "In short" / "Why this can happen" / "What you can do" / "The numbers in detail" / "Run summary"

**Rest of the mail (the reasons, what you can do, the numbers):**

```text
Why this can happen
No setting was changed since the previous run. So the change most likely comes from the data itself (for example devices or resources that were added or removed), or a data source answered only in part.
What you can do
- If you added or removed devices, users or Azure resources on purpose, do nothing. SecurityInsight learns the new level after three runs.
- If a setting was changed just before (see "Why this can happen") and it was not meant to do this, correct the setting.
- Then open the Data quality page (the Details button below) and choose Re-run from here -- or re-run the step it names in Operations > Jobs. The numbers are then measured again.
Nothing was blocked: every step ran and delivered as usual. This is a notice only.
The numbers in detail
Active CIs of type workstation: 1,400 now, usually 990 / 1,000 / 1,010 (last 3 runs), change +40 % of all active CIs
Active CIs in tier 2: 850 now, usually 590 / 600 / 610 (last 3 runs), change +25 % of all active CIs
CIs not seen any more (to retire): 235 now, usually 30 / 25 / 20 (last 3 runs), change +21 % of all active CIs
Run summary
Run: 2026-11-16 02:00 UTC
Unusual numbers found: Yes
Numbers outside the usual range: 3
Biggest change: +40 % of all active CIs (Active CIs of type workstation)
Compared with: The middle value of the last 3 runs
Details (https://si.example.test/Admin/DataQuality?run=run-1)
A data-quality mail goes out only when the key numbers outside their expected range change -- a new one, or one that is back within its range -- and at most once a day. The limits: Settings > Guards (safety checks) > Data-quality warnings.
```

#### example A: devices 990 -> 697

**Subject:** `[PROD] contoso-prod - Notice: Fewer assets than usual - no action if expected [SecurityInsight]`

**First lines (as the mail text reads):**

```text
SecurityInsight

Fewer assets than usual - no action if expected

In the run of 2026-11-16 02:00 UTC, 1 number was lower than usual. The biggest change: assets from Defender for Endpoint -- 697 now, usually 990 (-30 %).

In short

What happened: In the run of 2026-11-16 02:00 UTC, 1 number was lower than usual. The biggest change: assets from Defender for Endpoint -- 697 now, usually 990 (-30 %).

Is anything lost: No. Nothing was deleted or blocked. An asset that a data source no longer lists is kept for some days. It is not removed at once.

Do you need to do anything: No, unless you did not remove devices, users or Azure resources on purpose. Then see "What you can do" below.

```

**Section headings:** "Fewer assets than usual - no action if expected" / "In short" / "Why this can happen" / "What you can do" / "The numbers in detail" / "Run summary"

**Rest of the mail (the reasons, what you can do, the numbers):**

```text
Why this can happen
No setting was changed since the previous run. So the change most likely comes from the data itself (for example devices or resources that were added or removed), or a data source answered only in part.
What you can do
- If you added or removed devices, users or Azure resources on purpose, do nothing. SecurityInsight learns the new level after three runs.
- If a setting was changed just before (see "Why this can happen") and it was not meant to do this, correct the setting.
- Then open the Data quality page (the Details button below) and choose Re-run from here -- or re-run the step it names in Operations > Jobs. The numbers are then measured again.
Nothing was blocked: every step ran and delivered as usual. This is a notice only.
The numbers in detail
Assets from Defender for Endpoint (endpoint profiler): 697 now, usually 985 / 990 / 995 (last 3 runs), change -30 %
Run summary
Run: 2026-11-16 02:00 UTC
Unusual numbers found: Yes
Numbers outside the usual range: 1
Biggest change: -30 % (Assets from Defender for Endpoint (endpoint profiler))
Compared with: The middle value of the last 3 runs
Details (https://si.example.test/Admin/DataQuality?run=run-1)
A data-quality mail goes out only when the key numbers outside their expected range change -- a new one, or one that is back within its range -- and at most once a day. The limits: Settings > Guards (safety checks) > Data-quality warnings.
```

#### 2. A data source is behind (example B: Defender data 2 days old)

**The note every SecurityInsight mail carries while a data source is on its last good read (and the banner on every web page):**

> Endpoint data is from 2026-11-14 07:12 UTC. The last read did not finish, so SecurityInsight keeps the last good data.

**The line in the run report (Operations > Jobs):**

> Endpoint data is 2 day(s) old (from 2026-11-14 07:12 UTC): the last read did not finish, so SecurityInsight keeps the last good data

#### 3. The hold when a data source sends far fewer assets (example A: devices 990 -> 697, held)

**Guards page name:** Collection: far fewer assets from one source

**Guards page (what happened / why / what it means for you / what to do):**

```text
What happened: A data source sent far fewer assets than last time (697 now, 990 last time). SecurityInsight keeps the last good data for the missing assets.
Why: This protects you when a data source answers only in part: healthy assets must not look gone. Defender for Endpoint devices: 697 now, 990 last time (-29.6 %). SecurityInsight keeps the last good data for the missing ones until the next complete read shows the same level.
What it means for you: Nothing is lost. The run went on. The missing assets stay active with their last known data. No asset is retired and no finding is closed because of the drop. A real clean-up shows one run later.
1. You do not need to do anything if you removed these assets on purpose. The next complete read at the same level is accepted by itself.
2. If you did not expect the drop, check the data source (for example a lost permission, a changed scope or a failed sign-in).
3. To accept such drops at once from now on, choose accept for this check under Control on the Guards page.
```

**The line in the run report and the run log:**

> A data source sent far fewer assets than last time (697 now, 990 last time). SecurityInsight keeps the last good data for the missing assets. Cause: Defender for Endpoint devices: 697 now, 990 last time (-29.6 %). SecurityInsight keeps the last good data for the missing ones until the next complete read shows the same level. Where: job si-endpoint, mde device. Numbers: Assets in the last good collection: 990; Assets in this collection: 697; Change: -29.6 % (limit -15 %); 293 held. What to do: 1. You do not need to do anything if you removed these assets on purpose. The next complete read at the same level is accepted by itself. 2. If you did not expect the drop, check the data source (for example a lost permission, a changed scope or a failed sign-in). 3. To accept such drops at once from now on, choose accept for this check under Control on the Guards page.

(This check sends no mail of its own -- catalog "mail": "never".)


