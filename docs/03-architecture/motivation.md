# ZASK — Motivation

This document explains why ZASK exists. 

## Why ZASK exists

Attackers are already using AI to generate novel exploits, [obfuscated payloads](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools), and unusual execution patterns faster than any human can write rules to catch them. A static policy system can only block what its authors have already seen.

ZASK is built on one premise: **the only practical response to AI-assisted offense is AI-assisted defense**. Will this be effective? That is the question this project explores.

## The projects ZASK learns from

The production-ready projects below are much more mature and widely deployed. ZASK is not trying to replace them — it is exploring a specific gap they all share: [integrating AI into the enforcement](../02-configuration/ai-integration.md).

**[SELinux](https://github.com/SELinuxProject/selinux)** assigns security labels to every process and file, then enforces a policy matrix over those labels. It is the gold standard for Linux confinement. Its weakness is operational cost — writing and maintaining correct policy requires deep expertise.

**[AppArmor](https://gitlab.com/apparmor/apparmor)** works similarly to SELinux but uses file paths instead of labels, which makes it easier to write profiles. It ships enabled by default on Ubuntu and Debian. It has the same fundamental limitation: profiles are static and must be written before deployment.

**[Falco](https://falco.org/)** uses [eBPF](https://ebpf.io/) to watch syscalls and emit alerts when something looks suspicious. It covers a wide range of known attack patterns out of the box and is widely used in Kubernetes environments. It is detection-only by design — it alerts but does not block.

**[Tetragon](https://tetragon.io/)** is a CNCF project from Cilium. It uses eBPF to both observe and enforce at the kernel level. It is the closest existing project to what ZASK is attempting, and it is substantially more complete and production-ready.

## The gap ZASK is exploring

All four projects share one constraint: **policy is written by humans before the fact**. They are excellent at enforcing known rules. None of them can reason about a binary or behavior they have never been told about.

ZASK asks one question: **can an LLM meaningfully reason about an unknown exec chain at runtime, and can that be made reliable enough to use as a fallback in a security enforcement engine?**. This is genuinely unknown.

In the future, when **AI bots will be used by attackers** to generate novel exploits on the fly, this capability may be critical.

## Risks and open questions

The AI approach has real risks and open questions:

- **Latency & execution window** — LLM inference takes seconds. While the process is queued for AI analysis, it continues running — a [TOCTOU](https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use) window an attacker could exploit. A fast ML tier (ONNX-based) is planned to shrink this window; subsequent attempts are blocked at the kernel level regardless.
- **Reliability** — LLMs are probabilistic. A security control that gives different answers to identical inputs is hard to audit. Whether two AI tiers can reliably catch novel threats (e.g., base64-encoded payloads, anomalous parent-child chains like `curl` spawned by `nginx`) remains an open question.
- **ML training data** — The fast classifier tier requires labelled datasets of malicious and benign execution patterns. The current assumption is to use NDJSON audit logs from monitor-mode deployments as a labelling pipeline, with human analysts tagging verdicts feeding back into training. This is a complex operational challenge that may require rethinking.
- **Cost** — API calls at production syscall rates may be economically impractical, even with the kernel fast-path and CEL tiers absorbing most events. Mitigations: run a local open-weight LLM, or aggregate events to escalate only the most ambiguous cases.

The experiment may show that ML and LLMs are not the right tool for this. That would be a valid and useful result.
