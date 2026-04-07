# Documentation

This tree is split by audience, not by implementation detail. Public caller docs live in `docs/reference/`, maintainer-facing design notes live in `docs/design/`, and contributor workflow lives in `docs/developer/`.

## Start Here

- External callers: [reference/loongshield-cli.md](./reference/loongshield-cli.md)
- SEHarden operators and profile authors: [reference/seharden-cli.md](./reference/seharden-cli.md)
- AgentOS baseline automation: [skill/agent-sec-seharden.md](./skill/agent-sec-seharden.md)
- RPM verification users: [reference/rpm-cli.md](./reference/rpm-cli.md)
- Contributors: [developer/build-and-test.md](./developer/build-and-test.md)
- Maintainer roadmap: [developer/roadmap.md](./developer/roadmap.md)
- Community and process: [../CONTRIBUTING.md](../CONTRIBUTING.md), [../SECURITY.md](../SECURITY.md), [../SUPPORT.md](../SUPPORT.md), [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md), [../CHANGELOG.md](../CHANGELOG.md), [../RELEASING.md](../RELEASING.md)
- Maintainer-facing design notes: [design/runtime-architecture.md](./design/runtime-architecture.md), [design/boot-and-runtime-flow.md](./design/boot-and-runtime-flow.md), [design/clean-architecture.md](./design/clean-architecture.md), [design/agentos-seharden-design.md](./design/agentos-seharden-design.md), [design/seharden-enforcer-guidelines.md](./design/seharden-enforcer-guidelines.md)

## Information Architecture

```text
docs/
  README.md
  reference/
    loongshield-cli.md
    seharden-cli.md
    seharden-profile-format.md
    rpm-cli.md
  skill/
    agent-sec-seharden.md
  design/
    runtime-architecture.md
    boot-and-runtime-flow.md
    clean-architecture.md
    agentos-seharden-design.md
    seharden-enforcer-guidelines.md
    rpm-verification-design.md
  developer/
    README.md
    build-and-test.md
    docker-development.md
    roadmap.md
```

## Rules For Future Docs

- Put the caller contract first. CLI syntax, inputs, outputs, exit codes, and examples belong in `reference/`.
- Keep implementation details out of caller docs. Engine flow, module layout, and build internals belong in `design/`.
- Keep local workflow separate from product usage. Docker, build, test, and packaging steps belong in `developer/`.
- Prefer one command or one concept per page. Do not mix `loongshield`, `seharden`, and `rpm` behavior into one long file.
