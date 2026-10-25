-- Live examples: require DNSSEC-capable network access and these domains' current DNS.
-- Validation is local; merely receiving keys or an upstream AD bit is not authentication.
describe("DNSSEC", function()
    it("locally validates a signed domain", function()
        local response = dns.query("cloudflare.com", dns.type.A, { validate = true })

        assert.equal(response.rcode, dns.rcode.NOERROR)
        assert.secure(response)
        assert.has_answer(response, { type = dns.type.A, proof = dns.proof.SECURE })
        assert.truthy(response.validation_enabled)
        assert.truthy(response.answers_secure)
        for _, record in ipairs(response.answers:where({ type = dns.type.A })) do
            assert.equal(record.proof, dns.proof.SECURE)
        end
    end)

    it("does not confuse published keys with validated answers", function()
        local response = dns.query("cloudflare.com", dns.type.DNSKEY)
        local key = assert(response.answers:first({ type = dns.type.DNSKEY }), "expected a DNSKEY")

        assert.equal(response.rcode, dns.rcode.NOERROR)
        assert.truthy(key.key_tag >= 0 and key.key_tag <= 65535)
        assert.truthy(key.flags >= 0 and key.flags <= 65535)
        assert.truthy(key.algorithm > 0)
        assert.truthy(#key.public_key > 0)
        assert.equal(key.proof, dns.proof.INDETERMINATE)
        assert.falsy(response.validation_enabled)
        assert.falsy(response.answers_secure)
        local ok, err = pcall(assert.secure, response)

        assert.falsy(ok)
        assert.contains(tostring(err), "expected locally DNSSEC-authenticated answers")
        assert.contains(tostring(err), "validate = true")
        print("Published DNSKEY:", key.key_tag, "algorithm:", key.algorithm, "flags:", key.flags)
    end)

    it("exposes delegation digests and signature metadata", function()
        local delegation = dns.query("cloudflare.com", dns.type.DS)
        -- The validator attaches RRSIGs to answers; direct RRSIG queries may time out at stubs.
        local signatures = dns.query("cloudflare.com", dns.type.A, { validate = true })
        local ds = assert(delegation.answers:first({ type = dns.type.DS }), "expected a DS record")
        local signature = assert(
            signatures.answers:first({ type = dns.type.RRSIG, type_covered = dns.type.A }),
            "expected an A-covering RRSIG"
        )

        assert.equal(delegation.rcode, dns.rcode.NOERROR)
        assert.equal(signatures.rcode, dns.rcode.NOERROR)
        assert.secure(signatures)
        assert.truthy(ds.key_tag >= 0 and ds.key_tag <= 65535)
        assert.truthy(ds.algorithm > 0)
        assert.matches(ds.digest, "^[0-9A-F]+$")
        assert.truthy(ds.digest_type > 0)
        assert.truthy(signature.key_tag >= 0 and signature.key_tag <= 65535)
        assert.truthy(signature.algorithm > 0)
        assert.equal(signature.labels, 2)
        assert.truthy(signature.original_ttl >= 0)
        assert.equal(signature.signer_name, "cloudflare.com.")
        assert.truthy(signature.expiration > signature.inception)
        assert.truthy(#signature.signature > 0)
        -- Keys and signatures rotate; inspect their metadata, not fixed cryptographic bytes.
        print("DS:", ds.key_tag, "digest type:", ds.digest_type)
        print(
            "RRSIG:",
            signature.type_covered,
            signature.key_tag,
            signature.inception,
            signature.expiration
        )
    end)

    it("rejects a deliberately broken DNSSEC domain", function()
        local ok, result = pcall(dns.query, "dnssec-failed.org", dns.type.A, { validate = true })

        if ok then
            assert.equal(
                result.rcode,
                dns.rcode.SERVFAIL,
                "expected the upstream resolver to reject bad DNSSEC"
            )
            assert.truthy(result.validation_enabled)
            assert.falsy(result.answers_secure)
            assert.same(result.answers, {})
        else
            assert.contains(
                tostring(result),
                "DNSSEC",
                "expected a local validation failure, not a network error"
            )
        end
    end)
end)
