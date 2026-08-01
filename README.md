# DigitalSign

A Rust service that produces legally-verifiable digital signatures on PDF documents,
targeting PAdES / ISO 32000 compliance (Adobe "Signature Valid" verifiable).

For the full project scope — in/out of scope features, architecture, tech stack, policy
decisions, root CA / cert trust, known limitations, and working conventions — see
**[SCOPE.md](SCOPE.md)**. Read it before proposing architecture changes or new dependencies.

## Quick start

```sh
cp .env.example .env   # then fill in the root CA vars — see .env.example / SCOPE.md
make run               # cargo run --bin digitalsign
```

Other common targets: `make check`, `make lint`, `make test`, `make fmt` — see the
[Makefile](Makefile).

## Container image

```sh
make setup   # one-time, enables cross-arch emulation
```

See [docker/dockerfile](docker/dockerfile) for build details and required runtime env vars.
