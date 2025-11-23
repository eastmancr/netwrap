# Project Overview for Agents

**netwrap** is a lightweight, single-binary tool written in Go that runs a program in an isolated network namespace with optional port forwarding.

## Project Structure

- **`main.go`**: The complete source code. No external dependencies allowed (standard library only).
- **`tests/`**: Regression and performance tests.
  - `suite.sh`: The primary functional test suite. **Must pass** before any changes are finalized.
  - `perf_test.sh`: Throughput benchmark.
- **`netwrap.1`**: The man page. This is the canonical documentation for flags and behavior.
- **`README.md`**: User-facing documentation. It should mirror the content of the man page but formatted for Markdown.
- **`PKGBUILD`**: Arch Linux packaging script.

## Coding Guidelines

- **Language**: Go.
- **Dependencies**: Zero. Do not import external packages. Use `syscall` only when `os` or `net` packages are insufficient.
- **Style**:
  - Keep code concise and readable.
  - Avoid extraneous comments. Comment only on complex logic or non-obvious design decisions.
  - **Indentation**: Follow the existing file convention (4 spaces or tabs).
- **Architecture**:
  - The program must be a single binary.
  - Privileges: The program should detect if it needs root. If `setcap` or `sudoers` allow it, it should run without prompting. If not, it should re-execute itself with `sudo`. See man page about permissions and removing the `sudo` prompt.
  - Cleanup: Robustly handle signals (SIGINT/SIGTERM) to kill child processes and remove namespaces.

## Testing Strategy

- **Suite**: Run `./tests/suite.sh` (requires `sudo` access for namespace operations).
- **Philosophy**:
  - Tests are shell scripts calling the binary.
  - Tests must verify success paths (connectivity) and failure paths (isolation, invalid args).
  - **Cleanup**: Tests must leave no artifacts (zombie processes, leaked namespaces). Use `trap` or explicit cleanup steps.
- **Performance**: Use `perf_test.sh` to ensure proxy overhead remains low.

## Workflow

1. **Modify** `main.go`.
2. **Build** (`go build -o netwrap`).
3. **Test** (`sudo ./tests/suite.sh`).
4. **Update Docs**: If behavior changes, update `netwrap.1` AND `README.md`.
5. **Verify**: Check for orphans or leaks.
