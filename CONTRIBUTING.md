# Contributing to ZASK

Thanks for your interest. ZASK is in active development and feedback is welcome — bug reports, design questions, and pull requests are all appreciated.


## Development Setup

ZASK requires a Linux kernel with eBPF LSM support. The verified development setup is macOS + Lima VM. See [docs/04-development/README.md](docs/04-development/README.md) for full setup instructions.


## Guidelines

- **Follow Go conventions** — `gofmt`, `go vet`, `golangci-lint` must all pass before committing. `make lint` runs all checks locally.
- **No commits without tests and documentation** — all new features and bug fixes must include tests and documentation updates. `make test` runs unit tests locally.
- **No unstructured logging** — use `zerolog`, never `fmt.Println` or `log.*`.
- **Wrap errors** — `fmt.Errorf("context: %w", err)`, never discard errors with `_`.
- **eBPF changes require `make generate`** — if you touch anything in `bpf/`, regenerate the Go bindings before committing. Those files must not be edited directly.
- **All exported symbols need doc comments.**


## Submitting Changes Checklist

- If the change is large, let's discuss it first.
- Open a pull request with a clear description of what changed and why.
- Include tests for new features or bug fixes. 
- Include documentation updates if applicable (which is usually the case).
- Remind to follow self-contained commits and explanatory commit messages.
- Although at this stage the project can introduce breaking changes, let's discuss them first. After the first release, breaking changes will be avoided at all costs and will require a backwards-compatible migration path.


## Questions

Open a GitHub Discussion or an issue — there are no dumb questions.


## Code of Conduct

Respectful communication is expected and mandatory. Ideas are welcome, egos are not. Be kind and constructive.
