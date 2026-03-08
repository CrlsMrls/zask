# Development

At this stage, ZASK is in active development. If you are considering testing/contributing, use the following commands:

| Command | Description |
|---------|-------------|
| `make generate` | Run `bpf2go` to generate Go bindings from eBPF C source |
| `make build` | Compile the `zaskd` Go binary |
| `make test` | Run all Go tests (`go test ./...`) |
| `make lint` | Run `golangci-lint` with project configuration |
| `make clean` | Remove build artifacts and generated files |
| `make vm-build` | *(macOS)* Copy project to the Lima VM, generate, build, and sync back |
| `make vm-test` | *(macOS)* Run the kernel-level test suite inside the Lima VM |
| `make vm-run` | *(macOS)* Run `zaskd` in the Lima VM (requires `vm-build` first) |
| `make start-vm` | *(macOS)* Create the shared mount directory and start the Lima VM |
| `make vuln` | Run `govulncheck` for dependency vulnerability detection |
| `make tidy` | Run `go mod tidy` to clean up dependencies |

**Note:** The development is focused on MacOS as a development environment, using Lima to run a Linux VM with the necessary kernel features for eBPF LSM. The [Lima Development Guide](lima-dev-guide.md) provides detailed instructions on setting up this environment.
