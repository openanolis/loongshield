# Docker Development

Use Docker when you need a clean Linux build environment or a reproducible packaging path.

## Common Commands

```sh
make docker-dev
make docker-run-dev
make rpm-in-docker
```

## Recommended Flow

1. On the host, initialize vendored dependencies with `git submodule update --init --recursive`.
2. Build the development image with `make docker-dev`.
3. Start an interactive container with `make docker-run-dev`.
4. Inside the container, run `make` and `make test`. The container defaults to `O=build-docker`, so it does not reuse host CMake caches from `build/`.
5. If you also need an RPM package, run `make rpm-in-docker`.

Use `make bootstrap` on a local RPM-based host. Inside the development container, the dependency layer is already baked into the image, so the normal build and test commands are sufficient.

## When To Use It

- Host system is not compatible with the project’s RPM- and system-library-heavy dependencies.
- You need a disposable CentOS Stream 9 environment for builds, tests, or RPM packaging.
- You want a disposable build/test sandbox.
