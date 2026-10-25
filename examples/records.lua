describe("DNS record collections", function()
    describe("live example.com records (network required)", function()
        it("recognizes a null MX without depending on answer order", function()
            local response = dns.query("example.com", dns.type.MX)
            local null_mx = response.answers:where({ type = dns.type.MX, preference = 0 })
            local mail = assert(null_mx:first(), "expected a null MX")

            assert.equal(response.rcode, dns.rcode.NOERROR)
            assert.has_answer(response, { type = dns.type.MX, preference = 0, exchange = "." })
            assert.equal(mail.exchange, ".")
            assert.contains(null_mx:values(), "0 .") -- Default projection is presentation data.
            assert.contains(null_mx:values("exchange"), ".")
            assert.truthy(null_mx:contains({ exchange = "." }))
        end)

        it("reads TXT text and preserves its wire-format chunks", function()
            local response = dns.query("example.com", dns.type.TXT)
            local spf = assert(
                response.answers:first({ type = dns.type.TXT, text = "v=spf1 -all" }),
                "expected example.com's no-mail SPF policy"
            )

            assert.equal(response.rcode, dns.rcode.NOERROR)
            assert.has_answer(response, { type = dns.type.TXT, text = "v=spf1 -all" })
            assert.contains(response.answers:values("text"), "v=spf1 -all")
            for _, record in ipairs(response.answers:where({ type = dns.type.TXT })) do
                assert.truthy(#record.chunks > 0)
                assert.equal(table.concat(record.chunks), record.text)
            end
            print("SPF:", spf.text, "chunks:", #spf.chunks)
        end)
    end)

    describe("offline fixtures (no DNS requests)", function()
        it("selects service endpoints without changing the source collection", function()
            -- Reserved example names make this reproducible without a public SRV service.
            local source = dns.records({
                {
                    name = "_ldap._tcp.example.test.",
                    type = dns.type.SRV,
                    ttl = 300,
                    data = "10 60 389 primary.example.test.",
                    priority = 10,
                    weight = 60,
                    port = 389,
                    target = "primary.example.test.",
                },
                {
                    name = "_ldap._tcp.example.test.",
                    type = dns.type.SRV,
                    ttl = 300,
                    data = "20 0 389 backup.example.test.",
                    priority = 20,
                    weight = 0,
                    port = 389,
                    target = "backup.example.test.",
                },
                {
                    name = "example.test.",
                    type = dns.type.TXT,
                    ttl = 300,
                    data = '"part one" " and two"',
                    text = "part one and two",
                    chunks = { "part one", " and two" },
                },
            })
            local endpoints = source:where({ type = dns.type.SRV, port = 389 })
            local preferred = endpoints:where({ priority = 10 })
            local service = assert(preferred:first(), "expected a preferred LDAP endpoint")
            local backup = assert(source:first({ type = dns.type.SRV, priority = 20 }))

            assert.equal(service.target, "primary.example.test.")
            assert.equal(service.weight, 60)
            assert.equal(backup.target, "backup.example.test.")
            assert.same(preferred:values("target"), { "primary.example.test." })
            assert.truthy(source:contains({ type = dns.type.SRV, priority = 20, weight = 0 }))
            assert.falsy(source:contains({ type = dns.type.SRV, port = 636 }))
            assert.falsy(source:first({ type = dns.type.AAAA }))
            assert.equal(#source:where({ type = dns.type.AAAA }), 0)
            assert.same(source:values("address"), {}) -- Missing fields are skipped.
            assert.equal(#source, 3)
            assert.equal(#endpoints, 2)
            assert.equal(#preferred, 1)
            assert.equal(source:first(), service)
            -- Filtering creates a new list, but records themselves are shared, not copied.
            assert.truthy(preferred ~= source)
            assert.same(source:values(), {
                "10 60 389 primary.example.test.",
                "20 0 389 backup.example.test.",
                '"part one" " and two"',
            })

            local txt = assert(source:first({ type = dns.type.TXT }))
            assert.same(txt.chunks, { "part one", " and two" })
            assert.equal(table.concat(txt.chunks), txt.text)
            assert.truthy(source:contains({ chunks = { "part one", " and two" } }))
        end)
    end)
end)
