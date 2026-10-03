# Playbooks are data; Finding rules stay in code

Team-specific knowledge (which Checks to run, their order and dependencies, boundary notes) lives in Playbook data files that ship as defaults and can be overridden per rep, so Stackwell serves teams other than ToolHarness's original one without code changes. The logic that turns Step results into Findings stays in Go: a rules language would be a large, hard-to-test build for flexibility nobody has asked for yet.
