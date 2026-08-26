# Development planning

Status: operating mandate adopted as working v1 and full-scope roadmap approved by the user on 26-08-2026. Detailed phase solutions and issue batches still require their own approval.

This directory holds VegaStack Labs development planning. Executable work will be tracked in GitHub Issues in the implementation repository; development phases will use GitHub milestones. These documents are in the public repository and must contain only publication-safe development information.

## Start here

- [Operating mandate](operating-mandate.md): how requirements become approved issues, how agents execute them, and what proves completion.
- [Issue template](issue-template.md): the product-and-engineering contract for one executable issue, including completion and blocker comments.
- [Full-scope roadmap](roadmap.md): approved development phases, coverage of the existing specifications, and the separate live-deployment sequence.
- [Development-to-lab delivery path](roadmap.md#delivery-path-from-development-to-the-lab): complete and verify v1 first, then configure the actual inventory through the existing deployment gates.
- [Phase 0 draft](phases/00-development-foundation.md): proposed requirements, solution, issue outcomes and readiness conditions for the first development phase.
- [Repository contract](../../AGENTS.md): platform invariants and live-operation authority, which this mandate does not relax.
- [Specification map](../../README.md#documentation-map): canonical architecture, behavior, safety, and deployment requirements.

Next: review the phase 0 draft and develop its first complete issue batch. Include the mandatory [Ansible onboarding requirement and researched hardening/tool profiles](../host-onboarding-and-hardening.md) in that solution review; approving the roadmap did not approve those detailed profile choices or authorize live changes. The user selected completion of the entire v1 platform before the first lab onboarding rehearsal on 26-08-2026; isolated implementation tests remain required throughout development.

## Reconciled product requirements

The [portable lifecycle](../platform-lifecycle.md) owns generic local control-plane setup, account-free SSH operations, profile/gate selection and safe exit. Read it before converting the roadmap to issues. The Labs walkthrough is a selected deployment, not a core prerequisite. Each issue records layer, generic and dogfood behavior, unsupported cases and concrete proof. See the [readiness distinctions](roadmap.md#implementation-readiness); requirements approval does not make every future issue executable or authorize GitHub/live changes.

## Planning structure

Use one `roadmap.md` and add one document per development phase under `phases/` as its requirements and solution are planned. Development phases are numbered `0`, `1`, `2`, and so on. Issues use `<phase>.<issue>`: `0.1`, `0.2`, then `1.1`, `1.2`, and so on. Issue numbering starts at `1` within each phase and does not restart for each approval batch. Do not confuse development phases with the lab deployment phases in the root README.

| Item | Display / reference | Sortable filename or tracker title |
|---|---|---|
| Development phase | `Phase 0`, `Phase 1` | `phases/00-<phase-name>.md`, `phases/01-<phase-name>.md` |
| Issue within a phase | `0.1`, `0.2`, `1.1`, `1.2` | GitHub title: `[1.1] <observable outcome>` |
| Optional standalone issue draft, before publication | `1.1` | `01.01-<issue-name>.md`; after publication, GitHub is authoritative |
| GitHub tracking number | `#23` | Link as `1.1 (#23)`; it is not the development issue ID |

Use at least two digits per filename component for ordinary filename sorting, but no padding in displayed phase/issue IDs. If a component exceeds two digits, widen that component consistently in filenames only. Sort issue lists by the two integer components: `1.2` precedes `1.10`; these IDs are not decimal numbers. Shared documents such as this index, the mandate, the template, and the roadmap are not phases or executable issues and keep descriptive filenames.

Each phase document starts with `# Development phase <phase> — <name>` and has an ordered issue index with columns for issue ID, outcome, dependencies, and GitHub link. Use the same ID in issue headings, approval records, PR references, and implementation comments. The examples here define naming only; they do not approve phase content or create issues.

Number issues in their planned dependency order before approval/publication. Once an ID is approved or published, do not renumber or reuse it, even after cancellation. Add later issues using the next unused number in their phase; explicit dependencies govern execution when plans change.

The roadmap assigns every in-scope v1 requirement to a phase and records dependencies. Each phase document contains approved requirements and solution, ordered issue batches, shared execution defaults, and integrated exit criteria with a named acceptance issue. That owner can be the final delivery issue or a separate integration issue when useful. Short batch approval records belong in the phase document; no additional approval ledger, manual revision counter, or issue-body hash is required.

GitHub owns execution status, discussion, review evidence, and implementation summaries. Phase documents link to issues instead of copying their changing status or full descriptions. Published issue bodies are living execution plans: update affected open issues whenever the agreed plan changes. Comments explain meaningful changes, but current instructions belong in the body. Material changes need user confirmation; routine implementation-plan updates do not. Local drafts are preparation, not a second editable database. Remove a published draft or clearly mark it as historical with its GitHub link.

No phase plan, executable issue, GitHub milestone, label, or live activation is created or authorized merely by this directory's existence.

## Privacy and authority

Keep private inventory, credentials, operational declarations, provider identifiers, recovery material, and restricted evidence out of these documents and GitHub issues/comments. Use synthetic fixtures and logical references. Runtime desired state, operational plans/approvals, and evidence retain their existing control-plane authority.

## Before autonomous execution

These are one-time setup requirements, not steps to repeat in every issue:

- Integrate the user-approved root-contract clarification separating named-repository development from fleet operations, repository-policy changes, and releases. The broad GitHub restriction still applies outside specifically authorized actions.
- Link the mandate from the mandatory repository entry point so future agents discover it.
- Establish reproducible checks and a permitted review/merge route, including required identities and automation side effects. Prove that route with a small approved issue before dispatching a larger batch.
- Address reproducible audit generation. The dated audit register is a historical artifact; do not hand-edit generated data or claim its hashes verify later changes.

The initial development plan must assign this setup work. Local bootstrap may establish prerequisites before autonomous GitHub admission; each bootstrap issue needs validation and delivery independent of the component it creates. A written mandate does not prove the environment or permissions are ready.
