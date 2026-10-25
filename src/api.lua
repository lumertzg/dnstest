local builtin_assert = assert
local tests, suites = {}, {}
local logs = {}
local registering = true

---Common record types. Plain record type strings are also accepted.
dns.type = {
    A = "A",
    AAAA = "AAAA",
    CAA = "CAA",
    CNAME = "CNAME",
    DNSKEY = "DNSKEY",
    DS = "DS",
    HTTPS = "HTTPS",
    MX = "MX",
    NS = "NS",
    NSEC = "NSEC",
    NSEC3 = "NSEC3",
    PTR = "PTR",
    RRSIG = "RRSIG",
    SOA = "SOA",
    SRV = "SRV",
    SSHFP = "SSHFP",
    SVCB = "SVCB",
    TLSA = "TLSA",
    TXT = "TXT",
}

---Standard DNS response codes, matching response.rcode.
dns.rcode = {
    NOERROR = "NOERROR",
    FORMERR = "FORMERR",
    SERVFAIL = "SERVFAIL",
    NXDOMAIN = "NXDOMAIN",
    NOTIMP = "NOTIMP",
    REFUSED = "REFUSED",
}

---Local DNSSEC proof states, matching record.proof.
dns.proof = {
    SECURE = "secure",
    INSECURE = "insecure",
    BOGUS = "bogus",
    INDETERMINATE = "indeterminate",
}

function print(...)
    local values = {}
    for index = 1, select("#", ...) do
        values[index] = tostring(select(index, ...))
    end
    logs[#logs + 1] = table.concat(values, "\t")
end

local function registration(name, callback)
    builtin_assert(registering, "tests and suites must be declared while loading the file")
    builtin_assert(
        type(name) == "string" and name:match("%S"),
        "expected a non-empty test or suite name"
    )
    builtin_assert(type(callback) == "function", "expected a test or suite function")
end

function describe(name, callback)
    registration(name, callback)
    suites[#suites + 1] = name

    local ok, err = pcall(callback)
    suites[#suites] = nil
    if not ok then
        error(err, 0)
    end
end

function it(name, callback)
    registration(name, callback)
    local parts = { table.unpack(suites) }
    parts[#parts + 1] = name
    tests[#tests + 1] = { name = table.concat(parts, " > "), run = callback }
end

test = it

local function inspect(value, seen)
    if type(value) == "string" then
        return string.format("%q", value)
    end
    if type(value) ~= "table" then
        return tostring(value)
    end

    seen = seen or {}
    if seen[value] then
        return "<cycle>"
    end
    seen[value] = true

    local parts = {}
    for key, item in next, value do
        parts[#parts + 1] = "[" .. inspect(key, seen) .. "] = " .. inspect(item, seen)
    end
    table.sort(parts)
    seen[value] = nil

    return "{ " .. table.concat(parts, ", ") .. " }"
end

local function same(actual, expected, seen)
    if rawequal(actual, expected) then
        return true
    end
    if type(actual) ~= "table" or type(expected) ~= "table" then
        return false
    end

    seen = seen or {}
    if seen[actual] and seen[actual][expected] then
        return true
    end
    seen[actual] = seen[actual] or {}
    seen[actual][expected] = true

    for key, value in next, actual do
        if not same(value, rawget(expected, key), seen) then
            return false
        end
    end
    for key in next, expected do
        if rawget(actual, key) == nil then
            return false
        end
    end

    return true
end

local function check(ok, message, detail)
    if ok then
        return
    end
    error((message and (message .. "\n") or "") .. detail, 3)
end

assert = setmetatable({}, {
    __call = function(_, ...)
        return builtin_assert(...)
    end,
})

function assert.equal(actual, expected, message)
    check(
        actual == expected,
        message,
        "expected " .. inspect(expected) .. "\nreceived " .. inspect(actual)
    )
end

function assert.same(actual, expected, message)
    check(
        same(actual, expected),
        message,
        "expected deeply equal values\nexpected "
            .. inspect(expected)
            .. "\nreceived "
            .. inspect(actual)
    )
end

function assert.contains(actual, expected, message)
    local found = false
    if type(actual) == "string" and type(expected) == "string" then
        found = actual:find(expected, 1, true) ~= nil
    elseif type(actual) == "table" then
        for _, value in ipairs(actual) do
            if same(value, expected) then
                found = true
                break
            end
        end
    else
        error("assert.contains expects a list or two strings", 2)
    end

    check(found, message, "expected " .. inspect(actual) .. " to contain " .. inspect(expected))
end

function assert.matches(actual, pattern, message)
    builtin_assert(
        type(actual) == "string" and type(pattern) == "string",
        "assert.matches expects a string and a Lua pattern"
    )
    check(
        actual:find(pattern) ~= nil,
        message,
        "expected " .. inspect(actual) .. " to match " .. inspect(pattern)
    )
end

function assert.truthy(actual, message)
    check(
        actual ~= nil and actual ~= false,
        message,
        "expected a truthy value, received " .. inspect(actual)
    )
end

function assert.falsy(actual, message)
    check(
        actual == nil or actual == false,
        message,
        "expected false or nil, received " .. inspect(actual)
    )
end

---@param actual any
---@param message? string
function assert.ipv4(actual, message)
    check(dns.is_ipv4(actual), message, "expected an IPv4 address, received " .. inspect(actual))
end

---@param actual any
---@param message? string
function assert.ipv6(actual, message)
    check(dns.is_ipv6(actual), message, "expected an IPv6 address, received " .. inspect(actual))
end

---@class DNSRecord
---@field name string
---@field type string
---@field ttl integer
---@field data string
---@field address? string
---@field target? string
---@field preference? integer
---@field exchange? string
---@field text? string
---@field chunks? string[]
---@field priority? integer
---@field weight? integer
---@field port? integer
---@field proof? "secure"|"insecure"|"bogus"|"indeterminate"
---@field key_tag? integer
---@field algorithm? integer
---@field digest_type? integer
---@field digest? string
---@field flags? integer
---@field public_key? string
---@field type_covered? string
---@field signer_name? string
---@field inception? integer
---@field expiration? integer
---@field original_ttl? integer
---@field labels? integer
---@field signature? string

---@class DNSRecords: { [integer]: DNSRecord }
local records = {}
local records_mt = { __index = records }

---Create a sequential record collection. Records are shared, not deep-copied.
---@param values DNSRecord[]
---@return DNSRecords
function dns.records(values)
    builtin_assert(type(values) == "table", "dns.records expects a list of records")
    local result = {}
    for _, record in ipairs(values) do
        builtin_assert(type(record) == "table", "dns.records expects each record to be a table")
        result[#result + 1] = record
    end
    return setmetatable(result, records_mt)
end

local function matches_record(record, criteria)
    for key, expected in pairs(criteria) do
        if not same(record[key], expected) then
            return false
        end
    end
    return true
end

---Return records matching every supplied field. Does not mutate the source.
---@param criteria table<string, any>
---@return DNSRecords
function records:where(criteria)
    builtin_assert(type(criteria) == "table", "where expects a table of record fields")
    local result = {}
    for _, record in ipairs(self) do
        if matches_record(record, criteria) then
            result[#result + 1] = record
        end
    end
    return dns.records(result)
end

---@param criteria? table<string, any>
---@return DNSRecord?
function records:first(criteria)
    if criteria == nil then
        return self[1]
    end
    builtin_assert(type(criteria) == "table", "first expects a table of record fields")
    for _, record in ipairs(self) do
        if matches_record(record, criteria) then
            return record
        end
    end
end

---Partial record match. Unlike assert.contains, unspecified fields are ignored.
---@param criteria table<string, any>
---@return boolean
function records:contains(criteria)
    builtin_assert(type(criteria) == "table", "contains expects a table of record fields")
    return self:first(criteria) ~= nil
end

---Project a field, skipping records without it. Defaults to DNS presentation data.
---@param field? string
---@return any[]
function records:values(field)
    builtin_assert(field == nil or type(field) == "string", "values expects a field name string")
    local result = {}
    for _, record in ipairs(self) do
        local value = record[field or "data"]
        if value ~= nil then
            result[#result + 1] = value
        end
    end
    return result
end

---@class DNSResponse
---@field name string
---@field type string
---@field rcode string
---@field duration_ms number
---@field answers DNSRecords
---@field validation_enabled boolean
---@field answers_secure boolean

---@class DNSQueryOptions
---@field validate? boolean Local DNSSEC validation, disabled by default.

---@type fun(name: string, record_type: string?, validate: boolean): DNSResponse
local native_query = dns.query
local normalize_name, reverse_name = dns.normalize_name, dns.reverse_name
local is_ipv4, is_ipv6 = dns.is_ipv4, dns.is_ipv6

---Check a plain IPv4 address without making a network request. Other values return false.
---@param address any
---@return boolean
function dns.is_ipv4(address)
    return is_ipv4(address)
end

---Check a plain IPv6 address without making a network request. Other values return false.
---@param address any
---@return boolean
function dns.is_ipv6(address)
    return is_ipv6(address)
end

---Canonical lowercase, absolute DNS name. Does not make a network request.
---@param name string
---@return string
function dns.normalize_name(name)
    builtin_assert(
        type(name) == "string" and name ~= "",
        "normalize_name expects a non-empty domain name string"
    )
    return normalize_name(name)
end

---Build the in-addr.arpa or ip6.arpa name without making a network request.
---@param address string
---@return string
function dns.reverse_name(address)
    builtin_assert(type(address) == "string", "reverse_name expects an IP address string")
    return reverse_name(address)
end

---@param name string
---@param record_type? string
---@param options? DNSQueryOptions
---@return DNSResponse
function dns.query(name, record_type, options)
    builtin_assert(
        type(name) == "string" and name ~= "",
        "dns.query expects a non-empty domain name string"
    )
    builtin_assert(
        record_type == nil or type(record_type) == "string",
        "dns.query expects a record type string"
    )

    builtin_assert(options == nil or type(options) == "table", "query options must be a table")
    options = options or {}
    for key, value in pairs(options) do
        builtin_assert(key == "validate", "unknown query option: " .. tostring(key))
        builtin_assert(type(value) == "boolean", "validate must be a boolean")
    end

    local result = native_query(name, record_type, options.validate == true)
    result.answers = dns.records(result.answers)
    return result
end

---Resolve IPv4 by default, or IPv6 with "AAAA". DNS error codes raise an error.
---@param name string
---@param record_type? "A"|"AAAA"
---@param options? DNSQueryOptions
---@return string[]
function dns.resolve(name, record_type, options)
    builtin_assert(record_type == nil or type(record_type) == "string", "resolve expects A or AAAA")
    record_type = (record_type or "A"):upper()
    builtin_assert(
        record_type == "A" or record_type == "AAAA",
        "resolve expects A or AAAA. Use dns.query for other record types"
    )
    local result = dns.query(name, record_type, options)
    if result.rcode ~= "NOERROR" then
        error("could not resolve " .. name .. ": " .. result.rcode, 2)
    end
    return result.answers:values("address")
end

---Query PTR records for an IPv4 or IPv6 address.
---@param address string
---@param options? DNSQueryOptions
---@return DNSResponse
function dns.reverse(address, options)
    return dns.query(dns.reverse_name(address), "PTR", options)
end

---Match selected fields without specifying TTLs or depending on answer order.
---@param response DNSResponse
---@param criteria table<string, any>
---@param message? string
function assert.has_answer(response, criteria, message)
    check(
        response.answers:contains(criteria),
        message,
        "expected "
            .. response.type
            .. " query for "
            .. response.name
            .. " ("
            .. response.rcode
            .. ") to include "
            .. inspect(criteria)
            .. "\nreceived "
            .. inspect(response.answers)
    )
end

---Require nonempty, locally authenticated answer data. Not an upstream AD check.
---@param response DNSResponse
---@param message? string
function assert.secure(response, message)
    check(
        response.validation_enabled == true and response.answers_secure == true,
        message,
        "expected locally DNSSEC-authenticated answers for "
            .. response.name
            .. " ("
            .. response.rcode
            .. "). Query with { validate = true }.\nreceived "
            .. inspect(response.answers)
    )
end

return {
    tests = tests,
    logs = logs,
    seal = function()
        registering = false
    end,
}
