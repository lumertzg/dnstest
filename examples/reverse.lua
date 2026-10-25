describe("DNS name helpers", function()
    describe("offline name conversion (no DNS requests)", function()
        it("normalizes names and builds IPv4 and IPv6 reverse names", function()
            assert.equal(dns.normalize_name("WWW.Example.COM"), "www.example.com.")
            assert.equal(dns.normalize_name("www.example.com."), "www.example.com.")
            assert.equal(dns.reverse_name("192.0.2.9"), "9.2.0.192.in-addr.arpa.")
            -- IPv6 reverses every hexadecimal nibble, including expanded zeroes.
            assert.equal(
                dns.reverse_name("2001:db8::1"),
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
            )
        end)

        it("reports invalid IP input before attempting a lookup", function()
            local ok, err = pcall(dns.reverse_name, "not-an-ip")

            assert.falsy(ok)
            assert.contains(tostring(err), "invalid IP address syntax")
            print("Expected address error:", tostring(err))
        end)
    end)

    describe("live Cloudflare PTR records (network required)", function()
        it("looks up both IP families and logs PTR targets", function()
            for _, address in ipairs({ "1.1.1.1", "2606:4700:4700::1111" }) do
                local response = dns.reverse(address)

                assert.equal(response.name, dns.reverse_name(address))
                assert.equal(response.type, dns.type.PTR)
                assert.equal(response.rcode, dns.rcode.NOERROR)
                assert.has_answer(response, { type = dns.type.PTR, target = "one.one.one.one." })
                print(
                    address,
                    response.name,
                    "PTR:",
                    table.concat(response.answers:values("target"), ", ")
                )
            end
        end)
    end)
end)
