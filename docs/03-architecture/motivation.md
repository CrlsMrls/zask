# ZASK — Motivation

This document explains why ZASK exists. The projects below are much more mature and widely deployed. ZASK is not trying to replace them — it is exploring a specific gap they all share: [integrating AI into the enforcement](../02-configuration/ai-integration.md).

---

## The projects ZASK learns from

**[SELinux](https://github.com/SELinuxProject/selinux)** assigns security labels to every process and file, then enforces a policy matrix over those labels. It is the gold standard for Linux confinement. Its weakness is operational cost — writing and maintaining correct policy requires deep expertise.

**[AppArmor](https://gitlab.com/apparmor/apparmor)** works similarly to SELinux but uses file paths instead of labels, which makes it easier to write profiles. It ships enabled by default on Ubuntu and Debian. It has the same fundamental limitation: profiles are static and must be written before deployment.

**[Falco](https://falco.org/)** uses [eBPF](https://ebpf.io/) to watch syscalls and emit alerts when something looks suspicious. It covers a wide range of known attack patterns out of the box and is widely used in Kubernetes environments. It is detection-only by design — it alerts but does not block.

**[Tetragon](https://tetragon.io/)** is a CNCF project from Cilium. It uses eBPF to both observe and enforce at the kernel level. It is the closest existing project to what ZASK is attempting, and it is substantially more complete and production-ready.

---

## The gap ZASK is exploring

All four projects share one constraint: **policy is written by humans before the fact**. They are excellent at enforcing known rules. None of them can reason about a binary or behavior they have never been told about.

ZASK asks one question: **can an LLM meaningfully reason about an unknown exec chain at runtime, and can that be made reliable enough to use as a fallback in a security enforcement engine?**

In the future, when **AI bots may be used by attackers** to generate novel exploits on the fly, this capability may be critical.

This is genuinely unknown. The approach has real risks:

- **Latency** — LLM inference takes seconds, which is a long time in a security enforcement path. [TOCTOU](https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use) issues may arise if the LLM is too slow to keep up with the attacker's pace. A mitigation approach is to introduce a fast, traditional machine learning (ML) tier for classifying threats in milliseconds, adding semantic understanding before deciding to escalate to the LLM.
- **Reliability** — LLMs are probabilistic. A security control that gives different answers to identical inputs is hard to audit.
- **Cost** — API calls at production syscall rates may be economically impractical, even with the [kernel fast-path and CEL tiers](architecture.md) absorbing most events. An approach would be to either run a local open-weight LLM (adding complexity and operational costs), or to collectively aggregate events to minimize API calls to the most critical ones.

The experiment may show that ML and LLMs are not the right tool for this. That would be a valid and useful result.

