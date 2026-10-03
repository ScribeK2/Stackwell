# Stackwell

A local desktop workbench a Tier-2 support rep uses to work a support ticket's
technical side: run diagnostics against domains, hosts and mail, analyse pasted
evidence, and produce a ticket-ready write-up.

## Language

**Case**:
One support ticket's worth of diagnostic work — its targets, everything run or pasted for it, the findings, and the write-up. The central unit of Stackwell; a single quick lookup is a Case with one step.
_Avoid_: Investigation, session, ticket (the ticket lives in the external helpdesk; a Case only references it)

**Open** / **Resolved**:
The only two states of a Case. Resolved Cases drop out of the default list but stay searchable.
_Avoid_: Closed, done, archived

**Rep**:
The person running Stackwell. Each rep runs their own copy; there is no shared server.
_Avoid_: User, agent, operator

**Target**:
A thing a Case examines — a domain, hostname, IP, URL or email address. A Case can hold several; targets discovered mid-Case (an MX host, an origin IP) can be added to it.
_Avoid_: Input, subject

**Suggested target**:
A Target Stackwell spotted in a Step's result or in Evidence and offers to add to the Case; it is not part of the Case until the rep accepts it.
_Avoid_: Discovered target, related target

**Ticket reference**:
The optional external helpdesk ticket ID a Case is attached to.
_Avoid_: Ticket ID, case number

### Diagnostics

**Check**:
One kind of diagnostic Stackwell can perform, such as DNS lookup, SSL inspection or blacklist lookup.
_Avoid_: Tool, probe, test

**Step**:
One execution of a Check inside a Case, with its result. Never changes once recorded: re-running a Check adds a new Step, and Stackwell shows what changed since the previous one.
_Avoid_: Run, tool run, probe

**Evidence**:
Material the rep pasted into a Case (email headers, mail logs) rather than something Stackwell fetched.
_Avoid_: Paste, input, attachment

**Finding**:
A conclusion with a severity, derived from one or more Steps or pieces of Evidence, citing which ones. Only the latest Step of each Check per Target produces Findings; earlier Steps feed the before/after history.
_Avoid_: Issue, result, alert

**Playbook**:
A named, data-defined sequence of Checks (with dependencies between them) plus boundary notes, run against a Case's Target. Stackwell ships default Playbooks; reps can add or override them. Running a Playbook adds the Targets it derives (e.g. the primary MX host) to the Case.
_Avoid_: Track, investigation, workflow, recipe

**Saved query**:
A named, parameterised read-only database query, defined as data, that runs as a Check against a Target (e.g. look up a domain in an internal database).
_Avoid_: SQL workbench, recipe, report

**Boundary note**:
A Playbook's statement of what the rep cannot see from outside (e.g. registry back-end, container internals), carried into the write-up.
_Avoid_: Visibility boundary, black box

### Output

**Write-up**:
The ticket-ready text generated from a Case's Findings, Steps and Boundary notes plus the rep's notes, copied out to the helpdesk.
_Avoid_: Report, summary, export

**Rep notes**:
Free text the rep adds to a Case; saved with it and included in the Write-up.
_Avoid_: Comments, annotations
