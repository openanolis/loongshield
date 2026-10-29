# File Distribution CLI

`loongshield filedist` transfers files between a management host and managed
hosts. It is intentionally a transport only: LoongShield does not parse, sign,
verify, install, or execute the files.

Use it when the operator wants to distribute a policy file or another artifact
and apply it manually on the client.

## Syntax

```sh
loongshield filedist <command> [options]
```

## Commands

- `server --dir <path>`: serve every regular file below a directory. `GET /`
  returns the file index; `GET /<name>` returns one file.
- `pull <url>`: pull one file, or the whole index when the URL ends with `/`,
  into `--dir`.

## Options

- `--dir <path>`: directory to serve for `server`, or output directory for
  `pull` (default `/var/lib/loongshield/filedist`).
- `--host <address>`: listen address for `server` (default `0.0.0.0`).
- `--port <number>`: listen port for `server` (default 8080).
- `--log-level <level>`: set log level.
- `-h`, `--help`: show command help.

## Example

On the management host:

```sh
loongshield filedist server \
  --dir /srv/loongshield/files \
  --port 8080
```

On a managed host:

```sh
loongshield filedist pull http://management:8080/ \
  --dir /var/lib/loongshield/filedist
```

A single file can also be pulled. The file is saved using the last path
component:

```sh
loongshield filedist pull http://management:8080/policies/ima-policy \
  --dir /etc/loongshield/received
```

## Safety And Limits

- Only regular files are served; symlinks are rejected.
- Path traversal, absolute paths, duplicate separators, and control characters
  are rejected by both server and client.
- The server exposes every regular file below the configured directory. Put
  only intended distribution files in that directory.
- Files are transferred without LoongShield-level signatures. The client is
  responsible for validating content before using it.
- The index is unsigned; a compromised server can replay or omit files.
- A failed directory pull is not atomic.
- Plain HTTP has no confidentiality. The bundled downloader does not verify
  TLS certificates by default, so treat HTTPS as confidentiality only.
- LoongShield never executes or installs a pulled file.

For signed Lua-LSM policies, use `filedist server` and `filedist pull` to
transfer the files, then run `loongshield lua-lsm load --appraise enforce`.
