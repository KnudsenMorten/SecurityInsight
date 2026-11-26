# Releases, rings and waves

How a new SecurityInsight release travels from the vendor to your install, how a release is watched once it is out, and
what decides whether it may go further. The update itself is described in [Updates and upgrades](upgrade).

## Rings

Every install takes its releases from one update channel. Before a version reaches a channel, SecurityInsight builds,
tests and verifies it on its own installs.

| Channel | Who |
|---|---|
| Early release (ring 2) | Customers who take releases early and give feedback |
| Standard (ring 3) | Every other customer (the default) |

SecurityInsight decides which version goes to which ring; Invardia's update platform relays it and signs, per ring, a
manifest that names the release and its SHA-256. Your updater asks for the manifest of **its own** ring only, and
refuses a manifest signed for another ring.

![A release is built and verified by SecurityInsight, then reaches the early-release and standard channels in order; both need a recorded release approval and wait while an install that runs the version on a lower ring is Unhealthy; a wave serves named installs a version early; every install reports counts the release is judged on](images/release-rings.png)

## What a release must pass

| Gate | Rule |
|---|---|
| Rings 2 and 3 | Need the **APPROVED** state on the release: a recorded release approval with a reason. Invardia refuses a ring 2 or 3 release, or a wave, of a version without it. |
| The health gate | A version is not promoted to the next ring while an install that runs it turned Unhealthy after taking it (see [Data health](data-health)), or stopped reporting for 48 hours. An override needs a recorded release approval with a reason. |
| Setup-only releases | A release that changes only setup or install scripts, and no engine code, needs no APPROVED and goes to rings 1 and 2 as before, so a fix for a customer waiting on an install is not delayed. It is shown and logged on the release. |

Withdrawing APPROVED stops further promotion. It never rolls an install back.

## Waves: an early release for chosen installs

A **wave** lets a few named installs take a version early, before the rest of their ring, without moving them to
another ring:

- The vendor names the installs of a wave. A wave can only serve a version already released to a lower ring.
- A member's updater receives the wave's signed manifest instead of its ring's. Nothing else changes.
- The header shows `Ring 2 - Pre-release (<wave name>)`, and the Invardia support link says the same.
- **Never moved back.** Leaving or stopping a wave never downgrades an install: it keeps its version until its ring
  catches up. The wave ends when the ring gets that version.
- A member that turns Unhealthy, or stops reporting, after taking the wave's version stops the wave. There is no
  automatic rollback.

## Release mode: watching a new release closely

After a release that changed engine code, every install that takes it reports more often for a while:

| | |
|---|---|
| How often | Every 30 minutes, for 12 hours from the update |
| What | Counts only, on the Invardia support link: users, guests, devices, the guard mode, the wave and the release-mode period |
| At the same time | Every numbered safety check is twice as strict for 24 hours. See [Guards and guard modes](guards). |

## Components: Testing and Stable

A release names the parts of SecurityInsight it changed. Each part is one **component**:

- the collection of each source (identity, endpoint, Azure, public IP, the privilege-tier classifier, asset
  properties);
- correlation (the CI build);
- Risk Analysis, per report;
- data out, per channel (CMDB, vulnerabilities, mail, SQL, outputs, tagging).

A changed component is **Testing** at your install until it has had **3 good daily runs** with no further code change;
then it is **Stable**. A failed run starts the count again. *Settings > Updates* shows how many components are testing
and which. A change to shared core code makes every component Testing.

## The evidence a release is judged on

1. **Every install checks itself, every day, on every ring**, with its own read-only engine identity, and sends counts
   and verdicts: its data health, the safety checks that tripped since the release compared with before, and the
   progress of long runs. This is the main evidence.
2. **A spot check, only on rings 0-2 and only in release mode.** Invardia's support reads, read only, through the
   Invardia Support app, and only where you have that app enabled. Each read is recorded before it runs with the reason
   `release review SecurityInsight <version>` and shown in your activity log at Invardia. Only counts and verdicts are
   kept, never names, ids or values. Your environment's switch **"release spot checks allowed"** (on by default for
   rings 0-2) turns it off without leaving the ring. A spot check never holds a release by itself.
3. **The release review.** Invardia's support writes its findings on the release, SecurityInsight answers, and a
   proposal (approve, wait or stop, with the reason) goes to the release approval, which decides.

## What you control

| You want to ... | How |
|---|---|
| Take releases early | Ask to join the early-release channel (ring 2) or a wave |
| Take releases late | Stay on ring 3 (Broad), the default |
| Stop spot checks | Switch "release spot checks allowed" off for your environment at Invardia |
| Stop updates for a while | Switch *Pro updates from Invardia* off in *Settings* |
| Hold a release that needs a manual step | It is held by itself until you accept it. See [Updates and upgrades](upgrade). |
