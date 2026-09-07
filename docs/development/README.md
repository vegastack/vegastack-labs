# Development planning

Status: operating mandate adopted as working v1 and full-scope roadmap approved by the user on 26-08-2026. Phase 0 issues [0.1 (#3)](https://github.com/vegastack/vegastack-labs/issues/3) through [0.6 (#22)](https://github.com/vegastack/vegastack-labs/issues/22) are merged and closed, and (omkarmohanta09) accepted the Phase 0 exit on 07-09-2026. [Phase 1](phases/01-portable-executable-and-generated-contracts.md) is active: Issues [1.1 (#24)](https://github.com/vegastack/vegastack-labs/issues/24) and [1.2 (#25)](https://github.com/vegastack/vegastack-labs/issues/25) are merged, and [1.3 (#28)](https://github.com/vegastack/vegastack-labs/issues/28) owns the remaining release-manifest/offline-verification slice and combined exit. Pull requests, merges, release, repository administration, and live operations remain separately gated.

This directory holds VegaStack Labs development planning. Executable work will be tracked in GitHub Issues in the implementation repository; development phases will use GitHub milestones. These documents are in the public repository and must contain only publication-safe development information.

## Start here

- [Operating mandate](operating-mandate.md): how requirements become approved issues, how agents execute them, and what proves completion.
- [Issue template](issue-template.md): the product-and-engineering contract for one executable issue, including completion and blocker comments.
- [Full-scope roadmap](roadmap.md): approved development phases, coverage of the existing specifications, and the separate live-deployment sequence.
- [Development-to-lab delivery path](roadmap.md#delivery-path-from-development-to-the-lab): complete and verify v1 first, then configure the actual inventory through the existing deployment gates.
- [Phase 0 plan](phases/00-development-foundation.md): requirements, solution, issue outcomes and readiness conditions for the first development phase.
- [Phase 1 plan](phases/01-portable-executable-and-generated-contracts.md): approved generated-contract and portable-executable boundaries, issue order, checks, and exit demonstration.
- [Repository contract](../../AGENTS.md): platform invariants and live-operation authority, which this mandate does not relax.
- [Specification map](../../README.md#documentation-map): canonical architecture, behavior, safety, and deployment requirements.

[Phase 0 issues 0.1 (#3)](https://github.com/vegastack/vegastack-labs/issues/3) through [Issue 0.6 (#22)](https://github.com/vegastack/vegastack-labs/issues/22) are merged and closed. Issue 0.5 records the integrated evidence and bounded Phase 1 handoff; Issue 0.6 reconciles the verified PR #21 hosted check and merge shape; PR #23 then merged the correction and the operator accepted the phase exit. The completed 0.3/0.4 packages pin the Slack-only acknowledgement and host-security admission contracts but authorize no runtime or live change. Phase 1 delivery is [Issue 1.1 (#24)](https://github.com/vegastack/vegastack-labs/issues/24), [Issue 1.2 (#25)](https://github.com/vegastack/vegastack-labs/issues/25), then [Issue 1.3 (#28)](https://github.com/vegastack/vegastack-labs/issues/28); capability modules remain ownership maps, not a competing implementation order. The user selected completion of the entire v1 platform before the first lab onboarding rehearsal on 26-08-2026; isolated implementation tests remain required throughout development.

## Reconciled product requirements

The [portable lifecycle](../platform-lifecycle.md) owns generic local control-plane setup, account-free read/preparation and recovery over local or constrained-SSH access, Slack-only v1 human acknowledgement, profile/gate selection and safe exit. Read it before converting the roadmap to issues. The Labs walkthrough is a selected deployment, not a core prerequisite. Each issue records layer, generic and dogfood behavior, unsupported cases and concrete proof. See the [readiness distinctions](roadmap.md#implementation-readiness); requirements approval does not make every future issue executable or authorize GitHub/live changes.

## Planning structure

Use one `roadmap.md` and add one document per development phase under `phases/` as its requirements and solution are planned. Development phases are numbered `0`, `1`, `2`, and so on. Issues use `<phase>.<issue>`: `0.1`, `0.2`, then `1.1`, `1.2`, and so on. Issue numbering starts at `1` within each phase and does not restart for each approval batch. Do not confuse development phases with the lab deployment phases in the root README.

| Item | Display / reference | Sortable filename or tracker title |
|---|---|---|
| Development phase | `Phase 0`, `Phase 1` | `phases/00-<phase-name>.md`, `phases/01-<phase-name>.md` |
| Issue within a phase | `0.1`, `0.2`, `1.1`, `1.2` | GitHub title: `[1.1] <observable outcome>` |
| Development branch | `<type>/<issue-id>-<short-slug>` | `feat/2.1-inventory-read-api`, `fix/4.3-reject-stale-plans`, or `chore/0.1-development-route` |
| Optional standalone issue draft, before publication | `1.1` | `01.01-<issue-name>.md`; after publication, GitHub is authoritative |
| GitHub tracking number | `#23` | Link as `1.1 (#23)`; it is not the development issue ID |

Use at least two digits per filename component for ordinary filename sorting, but no padding in displayed phase/issue IDs. If a component exceeds two digits, widen that component consistently in filenames only. Sort issue lists by the two integer components: `1.2` precedes `1.10`; these IDs are not decimal numbers. Shared documents such as this index, the mandate, the template, and the roadmap are not phases or executable issues and keep descriptive filenames.

Branch prefixes follow the issue's one type label: `feature` maps to `feat/`, `bug` to `fix/`, and `chore` to `chore/`. Do not use agent-name prefixes such as `codex/` or `claude/`; see the canonical [branch-name rule](../../AGENTS.md#development-branch-names).

Each phase document starts with `# Development phase <phase> — <name>` and has an ordered issue index with columns for issue ID, outcome, dependencies, and GitHub link. Use the same ID in issue headings, approval records, PR references, and implementation comments. The examples here define naming only; they do not approve phase content or create issues.

Number issues in their planned dependency order before approval/publication. Once an ID is approved or published, do not renumber or reuse it, even after cancellation. Add later issues using the next unused number in their phase; explicit dependencies govern execution when plans change.

The roadmap assigns every in-scope v1 requirement to a phase and records dependencies. Each phase document contains approved requirements and solution, ordered issue batches, shared execution defaults, and integrated exit criteria with a named acceptance issue. That owner can be the final delivery issue or a separate integration issue when useful. Short batch approval records belong in the phase document; no additional approval ledger, manual revision counter, or issue-body hash is required.

GitHub owns execution status, discussion, review evidence, and implementation summaries. Phase documents link to issues instead of copying their changing status or full descriptions. Published issue bodies are living execution plans: update affected open issues whenever the agreed plan changes. Comments explain meaningful changes, but current instructions belong in the body. Material changes need user confirmation; routine implementation-plan updates do not. Local drafts are preparation, not a second editable database. Remove a published draft or clearly mark it as historical with its GitHub link.

No phase plan, executable issue, GitHub milestone, label, or live activation is created or authorized merely by this directory's existence.

## Privacy and authority

Keep private inventory, credentials, operational declarations, provider identifiers, recovery material, and restricted evidence out of these documents and GitHub issues/comments. Use synthetic fixtures and logical references. Runtime desired state, operational plans/approvals, and evidence retain their existing control-plane authority.

## Established development foundation

Issues 0.1 and 0.2 established these one-time prerequisites; later issues verify rather than recreate them:

- The root contract separates approved named-repository development from fleet operations, repository-policy changes and releases; authority outside a named batch remains separately gated.
- Mandatory repository entry points link this mandate.
- Public, reproducible checks and the permitted review/merge route have been exercised on real approved issues.
- The dated audit register remains a protected historical artifact; current evidence uses separately owned validators and never rewrites that snapshot.

Each later issue still proves its own prerequisites, checks, review and delivery. An established development route does not grant release, repository-administration or infrastructure authority.
