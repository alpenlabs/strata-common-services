# Strata Common Services

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![lint](https://github.com/alpenlabs/strata-common-services/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/strata-common-services/actions/workflows/lint.yml)
[![unit](https://github.com/alpenlabs/strata-common-services/actions/workflows/unit.yml/badge.svg?event=push)](https://github.com/alpenlabs/strata-common-services/actions/workflows/unit.yml)

Services shared by [Alpen](https://github.com/alpenlabs/alpen) and Alpen EE.
The crates here were moved out of the Alpen workspace so that both nodes can
depend on one copy. This workspace does not depend on Alpen or Alpen EE.

## Crates

| Crate | Path | What it does |
| --- | --- | --- |
| `strata-prover-core` | [`crates/prover-core`](crates/prover-core/README.md) | Durable proof tasks: input assembly, native or remote proving, receipt storage, retries and crash recovery. |
| `strata-paas` | [`crates/paas`](crates/paas/README.md) | Runs a `Prover` as a service-framework service with a command handle and periodic ticks. |

## Development

The toolchain is pinned in `rust-toolchain.toml`. Run `just setup` once to
enable the pre-commit hook, then:

```sh
just lints   # taplo, rustfmt and clippy
just test    # nextest and doctests
```

Building the docs needs the same rustdoc flag as CI:

```sh
RUSTDOCFLAGS="-Znext-solver=coherence -D warnings" cargo doc --workspace --all-features --no-deps
```

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
