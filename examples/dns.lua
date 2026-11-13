-- Live examples: require network access and example.com's current public DNS.
describe("example.com", function()
    describe("address queries", function()
        it("defaults to A and exposes response and record metadata", function()
            local response = dns.query("example.com")
            local address = assert(response.answers:first({ type = dns.type.A }), "expected IPv4")

            assert.equal(response.name, "example.com.")
            assert.equal(response.type, dns.type.A)
            assert.equal(response.rcode, dns.rcode.NOERROR)
            assert.truthy(response.duration_ms >= 0)
            assert.falsy(response.validation_enabled)
            assert.falsy(response.answers_secure)
            assert.equal(address.name, response.name)
            assert.truthy(address.ttl >= 0) -- Cached TTLs may reach zero.
            assert.equal(address.data, address.address)
            assert.equal(address.proof, dns.proof.INDETERMINATE)
            assert.ipv4(address.address)
            print(response.type, response.name, response.duration_ms, "ms", address.address)
        end)

        -- test is an alias for it; both work inside nested suites.
        test("resolves IPv4 and IPv6 without parsing records", function()
            local ipv4 = dns.resolve("example.com")
            local ipv6 = dns.resolve("example.com", dns.type.AAAA)

            assert.truthy(#ipv4 > 0, "expected IPv4 addresses")
            assert.truthy(#ipv6 > 0, "expected IPv6 addresses")
            for _, address in ipairs(ipv4) do
                assert.ipv4(address)
            end
            for _, address in ipairs(ipv6) do
                assert.ipv6(address)
            end
            print("IPv4:", table.concat(ipv4, ", "), "IPv6:", table.concat(ipv6, ", "))
        end)
    end)

    describe("negative answers", function()
        it("distinguishes an absent name from an absent record type", function()
            local missing = dns.query("dnstest-does-not-exist.invalid")
            local nodata = dns.query("example.com", dns.type.SRV)

            assert.equal(missing.rcode, dns.rcode.NXDOMAIN)
            assert.same(missing.answers, {})
            -- example.com exists, but does not publish SRV records at its apex.
            assert.equal(nodata.rcode, dns.rcode.NOERROR)
            assert.same(nodata.answers, {})
            assert.falsy(nodata.answers:first())
        end)

        it("inspects resolve errors rather than accepting any failure", function()
            -- query returns DNS error codes; resolve raises for those same codes.
            local ok, err = pcall(dns.resolve, "dnstest-does-not-exist.invalid")

            assert.falsy(ok)
            assert.contains(tostring(err), "could not resolve dnstest-does-not-exist.invalid")
            assert.contains(tostring(err), dns.rcode.NXDOMAIN)
            print("Expected resolution failure:", tostring(err))
        end)
    end)

    describe("explicit servers", function()
        it("queries one server instead of resolv.conf", function()
            -- A bare IP uses port 53. Authoritative servers can be targeted the same way.
            for _, server in ipairs({ "1.1.1.1", "8.8.8.8:53" }) do
                local response = dns.query("example.com", dns.type.A, { server = server })

                assert.equal(response.rcode, dns.rcode.NOERROR)
                assert.has_answer(response, { type = dns.type.A })
                print(response.server, response.answers:values("address")[1])
            end
        end)

        it("sends a client subnet to an authoritative server", function()
            -- ns1.google.com tailors answers to the subnet and echoes the scope it used.
            local response = dns.query("www.google.com", dns.type.A, {
                server = "216.239.32.10",
                ecs = "198.51.100.7/24",
            })
            local ecs = assert(response.ecs, "expected the server to echo ECS")

            assert.equal(response.rcode, dns.rcode.NOERROR)
            assert.truthy(response.authoritative)
            assert.equal(ecs.address, "198.51.100.0") -- Bits past the prefix are cleared.
            assert.equal(ecs.source_prefix, 24)
            print("scope", ecs.scope_prefix, response.answers:values("address")[1])
        end)
    end)
end)
