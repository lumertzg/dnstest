# dnstest

A CLI for testing DNS with Lua. Write suites that query domains and assert on
their records, response codes, and DNSSEC validation. Get per-test results,
timings, and failure traces in a terminal report inspired by Vitest.

Built in Rust with Hickory and embedded Lua 5.4. No separate Lua installation
or Lua packages are needed to run tests.

- Nested suites with `describe` and `it`, plus readable assertions.
- Structured DNS records, filtering helpers, and forward/reverse lookups.
- Optional local DNSSEC validation and DS, DNSKEY, and RRSIG metadata.
- Concurrent test files with isolated Lua environments and ordered output.

## Install

```sh
cargo install --git https://github.com/lumertzg/dnstest --locked
```

## Usage

```sh
dnstest                     # Run tests/
dnstest path/to/tests        # Run a file or directory
dnstest --skill              # Print usage guidance for agents
dnstest --help
```

Files run concurrently, up to `--jobs 4` by default. Tests within each file run
in declaration order. Failed tests produce a nonzero exit status.

See [examples/](examples/) for queries, record helpers, reverse DNS, and DNSSEC.
