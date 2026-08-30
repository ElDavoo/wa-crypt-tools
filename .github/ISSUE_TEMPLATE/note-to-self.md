---
name: Note to self (no agent)
about: Park an idea without the agent pipeline picking it up and building it.
title: ''
labels: no-agent
assignees: ''
---

<!--
  This template exists for one reason: it applies the `no-agent` label AT CREATION.

  agent-plan.yml fires on `issues: opened`, so a label added a moment after filing loses the
  race and the pipeline is already planning. Applied by the template, the label is on the issue
  in the payload that triggers the workflow, and nothing starts.

  If you did file an ordinary issue and want to stop the pipeline mid-flight, the label to use
  is `agent:stop` — that one works at any point. See README.md.
-->
