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
end)
