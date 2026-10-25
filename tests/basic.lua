describe("assertions", function()
    it("compares values without coercing types", function()
        assert.equal(2 + 3, 5)
        assert.equal(nil, nil)
        assert.falsy(pcall(assert.equal, "5", 5))
        assert.falsy(pcall(assert.equal, false, nil))
    end)

    it("compares nested tables by value", function()
        assert.same(
            { answers = { "192.0.2.1", "192.0.2.9" } },
            { answers = { "192.0.2.1", "192.0.2.9" } }
        )
        assert.falsy(pcall(assert.same, { ttl = 30 }, { ttl = 60 }))
        assert.falsy(pcall(assert.same, {}, { extra = false }))
        assert.falsy(pcall(assert.same, { extra = false }, {}))
    end)

    it("finds values in lists and literal substrings", function()
        assert.contains({ "192.0.2.1", "192.0.2.9" }, "192.0.2.9")
        assert.contains({ { type = "MX", preference = 10 } }, { type = "MX", preference = 10 })
        assert.contains("v=spf1 -all", "spf1")
        assert.falsy(pcall(assert.contains, "abc", "."))
        assert.falsy(pcall(assert.contains, { "192.0.2.1" }, "192.0.2.9"))
    end)

    it("matches Lua patterns", function()
        assert.matches("192.0.2.9", "^192%.0%.2%.%d+$")
        assert.falsy(pcall(assert.matches, "198.51.100.9", "^192%."))
    end)

    it("preserves Lua truthiness and builtin assert return values", function()
        assert.truthy(0)
        assert.truthy("")
        assert.falsy(false)
        assert.falsy(nil)
        assert.falsy(pcall(assert.truthy, false))
        assert.falsy(pcall(assert.falsy, 0))
        local first, second = assert("answer", 42)
        assert.equal(first, "answer")
        assert.equal(second, 42)
    end)

    describe("nested suites", function()
        test("also accepts test as an alias for it", function()
            assert.equal(test, it)
        end)
    end)
end)

describe("DNS helpers", function()
    it("validates IP addresses by family without accepting lookalikes", function()
        assert.ipv4("0.0.0.0")
        assert.ipv4("255.255.255.255")
        assert.ipv6("::")
        assert.ipv6("2001:db8::1")
        assert.ipv6("::ffff:192.0.2.9")
        assert.truthy(dns.is_ipv4("192.0.2.9"))
        assert.truthy(dns.is_ipv6("2001:db8::9"))
        assert.falsy(dns.is_ipv4("256.0.0.1"))
        assert.falsy(dns.is_ipv4("192.0.2.9/24"))
        assert.falsy(dns.is_ipv4("::ffff:192.0.2.9"))
        assert.falsy(dns.is_ipv6("192.0.2.9"))
        assert.falsy(dns.is_ipv6("2001:db8::gg"))
        assert.falsy(dns.is_ipv6("[2001:db8::1]:53"))
        assert.falsy(dns.is_ipv4(nil))
        assert.falsy(dns.is_ipv4(1234))
        assert.falsy(dns.is_ipv6({}))

        local ok, err = pcall(assert.ipv4, "999.1.2.3", "invalid A answer")
        local ipv6_ok, ipv6_err = pcall(assert.ipv6, "2001:db8::gg")

        assert.falsy(ok)
        assert.contains(err, "invalid A answer")
        assert.contains(err, 'expected an IPv4 address, received "999.1.2.3"')
        assert.falsy(ipv6_ok)
        assert.contains(ipv6_err, "expected an IPv6 address")
    end)

    it("filters and projects records without changing the source", function()
        local source = {
            {
                name = "example.com.",
                type = dns.type.MX,
                ttl = 30,
                data = "10 mx.example.com.",
                preference = 10,
                exchange = "mx.example.com.",
            },
            {
                name = "example.com.",
                type = dns.type.A,
                ttl = 60,
                data = "192.0.2.9",
                address = "192.0.2.9",
            },
            {
                name = "example.com.",
                type = dns.type.MX,
                ttl = 90,
                data = "20 backup.example.com.",
                preference = 20,
                exchange = "backup.example.com.",
            },
        }
        local answers = dns.records(source)
        local mail = answers:where({ type = "MX" })

        assert.equal(#answers, 3)
        assert.equal(#source, 3)
        assert.equal(#mail, 2)
        assert.same(mail:values("preference"), { 10, 20 })
        assert.same(answers:values("address"), { "192.0.2.9" })
        assert.equal(mail:first({ preference = 20 }).exchange, "backup.example.com.")
        assert.equal(mail:where({ preference = 10 }):first().exchange, "mx.example.com.")
        assert.truthy(mail:contains({ type = "MX", preference = 10 }))
        assert.falsy(mail:contains({ type = "MX", preference = 15 }))
        assert.falsy(
            mail:contains({ type = "MX", preference = 10, exchange = "wrong.example.com." })
        )
        assert.equal(mail:first({ preference = 99 }), nil)
        assert.same(answers:where({ type = "AAAA" }):values(), {})
        assert.equal(dns.records({}):first(), nil)
        assert.falsy(dns.records({}):contains({}))
        local response = {
            name = "example.com.",
            type = "MX",
            rcode = "NOERROR",
            duration_ms = 0,
            answers = answers,
            validation_enabled = false,
            answers_secure = false,
        }
        assert.has_answer(response, { preference = 10 })
        assert.falsy(pcall(assert.has_answer, response, { preference = 15 }))
    end)

    it("normalizes names and builds IPv4 and IPv6 reverse names offline", function()
        assert.equal(dns.normalize_name("WWW.Example.COM"), "www.example.com.")
        assert.equal(dns.normalize_name("www.example.com."), "www.example.com.")
        assert.equal(dns.normalize_name("."), ".")
        assert.equal(dns.reverse_name("192.0.2.9"), "9.2.0.192.in-addr.arpa.")
        assert.equal(
            dns.reverse_name("2001:db8::1"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        )
        assert.falsy(pcall(dns.reverse_name, "999.2.0.1"))
        assert.falsy(pcall(dns.normalize_name, "bad..name"))
    end)
end)
