---
name: testing-dns
description: Writes and runs Lua DNS tests with the dnstest CLI. Use when checking DNS records, resolution, reverse DNS, or local DNSSEC validation.
---

# Testing DNS

Use dnstest to express DNS expectations as executable Lua tests.

## Workflow

1. Identify the domain, record types, and expected DNS behavior. Do not infer a
   policy from whatever records happen to be returned and then assert that policy.
2. Write a `.lua` file in `tests/`, or choose an explicit file/directory path.
3. Run `dnstest <path>`. Inspect failures and distinguish DNS outcomes from
   transport failures before changing expectations.
4. Report what was checked, which resolver/network was used, and any limitations.
   Live DNS can change. Do not claim an unexecuted test passed.

If the CLI is unavailable, install it with Cargo:

```sh
cargo install --git https://github.com/lumertzg/dnstest --locked
```

## Commands

```sh
dnstest                         # Discover tests/ recursively
dnstest tests/mail.lua           # Run one file
dnstest tests examples           # Run multiple paths
dnstest --jobs 1 tests           # Run files serially
dnstest --help
```

Exit status is 0 for success, 1 for test/load/discovery failures, and 2 for
argument syntax errors. Files are sorted and deduplicated. Symlinks are skipped.
Files run concurrently, up to `--jobs 4` by default. Tests within a file run
serially with a fresh Lua environment per file. `print` logs are grouped with
their file's results. Set `NO_COLOR=1` to disable terminal colors.

## Writing tests

Globals are available without imports. Register tests during file loading, not
inside another test. `describe` nests suites. `test` is an alias for `it`.
Put network requests inside test callbacks. Lua files are trusted code, not a
sandbox, so inspect unfamiliar tests before running them.

```lua
describe("example.com mail", function()
    it("explicitly rejects mail delivery", function()
        local response = dns.query("example.com", dns.type.MX)

        assert.equal(response.rcode, dns.rcode.NOERROR)
        assert.has_answer(response, { type = dns.type.MX, preference = 0, exchange = "." })
    end)
end)
```

## DNS API

- `dns.query(name, type?, options?)` returns a response. Type defaults to A.
- `dns.resolve(name, type?, options?)` returns address strings. Only A and AAAA.
- `dns.reverse(ip, options?)` returns a PTR response for IPv4 or IPv6.
- `dns.normalize_name(name)` returns a lowercase absolute name without networking.
- `dns.reverse_name(ip)` returns an absolute reverse-lookup name without networking.
- `dns.is_ipv4(value)` and `dns.is_ipv6(value)` check plain IP address strings
  without networking. Invalid addresses and nonstrings return false. Ports,
  brackets, and CIDR prefixes are not accepted.
- `dns.records(list)` copies a sequential list into a record collection. Record
  tables are shared, not deep-copied. Useful for offline fixtures.

Types are case insensitive in queries. Constants such as `dns.type.A`,
`dns.type.AAAA`, `dns.type.MX`, `dns.type.TXT`, `dns.type.DS`, and `dns.type.DNSKEY`
are strings. Other Hickory-supported types can also be supplied as strings.
`dns.rcode` includes NOERROR, NXDOMAIN, SERVFAIL, FORMERR, NOTIMP, and REFUSED.

Queries use system DNS, ignore hosts-file entries and search suffixes, and use
no shared resolver cache between calls. There is no custom-nameserver option.
The only query option is `{ validate = true }` for local DNSSEC validation,
disabled by default. The same options table is accepted by resolve and reverse.

Responses contain `name`, `type`, `rcode`, `duration_ms`, `answers`,
`validation_enabled`, and `answers_secure`. NXDOMAIN returns empty answers with
rcode NXDOMAIN. NODATA returns empty answers with rcode NOERROR. Other DNS error
codes are also response data. Invalid input, transport failures, and local
validation failures raise Lua errors. `dns.resolve` additionally raises on any
non-NOERROR code. Use `pcall` to inspect expected errors without accepting every
network failure as an expected DNS result.

Records have `name`, `type`, `ttl` in seconds, `data` in DNS presentation format,
and a local DNSSEC `proof`. Typed fields avoid parsing presentation text:

| Type | Fields |
| --- | --- |
| A, AAAA | `address` |
| CNAME, NS, PTR | `target` |
| MX | `preference`, `exchange` |
| TXT | `text` (joined chunks), `chunks` (original byte strings) |
| SRV | `priority`, `weight`, `port`, `target` |
| DS | `key_tag`, `algorithm`, `digest_type`, `digest` (uppercase hex) |
| DNSKEY | `flags`, `key_tag`, `algorithm`, `public_key` (base64) |
| RRSIG | `type_covered`, `algorithm`, `labels`, `original_ttl`, `inception`, `expiration`, `key_tag`, `signer_name`, `signature` (base64) |

Names in record fields are absolute. DNS answer order is not guaranteed.
Do not pin live TTLs, rotating addresses, key tags, or signature bytes unless
they are specifically the contract being tested.

## Record collections

Answers are normal indexed tables supporting `#answers` and `ipairs(answers)`:

```lua
local answers = dns.query("example.com", dns.type.MX).answers
local mail = answers:where({ type = dns.type.MX }):where({ preference = 0 })
assert.contains(mail:values("exchange"), ".")
assert.truthy(mail:contains({ exchange = "." }))
local first = mail:first() -- nil if empty
```

- `where(fields)` returns a new collection matching every supplied field.
- `first(fields?)` returns the first match, or nil. Without fields, the first record.
- `contains(fields)` checks partial-record membership, ignoring unspecified fields.
- `values(field?)` projects a field into a plain list, omitting absent fields.
  Defaults to `data`.

Filters preserve input order, share record tables, and do not mutate the source.
Field comparisons are exact, including name case. Normalize expected names when
appropriate. Use membership rather than positional assertions for live DNS.

## Assertions

Use dot calls, actual value first, and an optional final failure message:

- `assert.equal(actual, expected)` uses Lua equality, not deep table equality.
- `assert.same(actual, expected)` deeply compares table values, ignoring metatables.
- `assert.contains(actual, expected)` checks deep list membership or literal substring.
- `assert.matches(actual, pattern)` uses Lua patterns, not regular expressions.
- `assert.truthy(value)` and `assert.falsy(value)` follow Lua truthiness.
- `assert.ipv4(value)` and `assert.ipv6(value)` validate addresses using real IP
  parsing. Prefer these over address-shaped patterns or checking for a colon.
- `assert.has_answer(response, fields)` checks a partial answer record match.
- `assert.secure(response)` requires locally authenticated, nonempty answer data.
- Normal `assert(condition, message)` still works and preserves its return values.

## DNSSEC

```lua
it("authenticates signed answers", function()
    local response = dns.query("cloudflare.com", dns.type.A, { validate = true })

    assert.equal(response.rcode, dns.rcode.NOERROR)
    assert.secure(response)
    assert.has_answer(response, { type = dns.type.A, proof = dns.proof.SECURE })
end)
```

Hickory validates locally with built-in root trust anchors. Validation enabled
does not mean validation produced secure data. An unsigned delegation can be
accepted without authenticating its answers.

`dns.proof.SECURE`, INSECURE, BOGUS, and INDETERMINATE map to lowercase record
proof strings. Indeterminate is also the default for unvalidated records.
`answers_secure` requires validation to be enabled and a nonempty set of
non-RRSIG answers whose proofs are all secure. It does not authenticate every
section of a DNS message. Empty or RRSIG-only answers are never secure by this
definition. Negative responses do not expose authenticated-denial proofs.

Fetching DNSKEY/DS/RRSIG records or observing upstream AD is not local validation.
Bogus data normally raises an error. An upstream SERVFAIL is not proof of a local
DNSSEC rejection. Inspect signatures attached to validated answer data rather
than assuming direct RRSIG queries work through every system resolver.

See [examples](https://github.com/lumertzg/dnstest/tree/main/examples) for complete
query, collection, reverse-DNS, and DNSSEC suites. Do not invent hooks, watch mode,
raw-packet controls, or other APIs not listed here.
