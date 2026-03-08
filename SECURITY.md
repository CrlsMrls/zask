# Security Policy

## Reporting a Vulnerability

At this stage, ZASK is an experimental project and although it is successfuly running in a home lab environment, the maintainer considers it is not yet a production-ready EDR.

In the future, the project will adopt a more formal responsible disclosure policy, including a private reporting channel and a defined timeline for fixes and public disclosure. For now, please reach out directly to the maintainer with any security concerns.

## Known Limitations

- **`AI_QUEUE` execution window** — processes routed to the LLM continue running while the AI deliberates (>5s). This is a deliberate design tradeoff, not a [time-to-check to time-of-use](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) bug. The ONNX fast path should shrink the window to near-zero for common threats. **This topic keeps awakening the maintainer at night, so if you have ideas for mitigating this risk, please share them.**
- **ZASK is experimental** — it is not yet a production-ready EDR. Do not rely on it as a sole security control.
