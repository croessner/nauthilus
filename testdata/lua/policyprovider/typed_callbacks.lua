local invocation_count = 0

_G["policy.facts.collect"] = function(request)
    assert(io == nil)
    assert(os == nil)
    assert(package == nil)
    assert(require == nil)
    assert(dofile == nil)
    assert(loadfile == nil)
    assert(load == nil)
    assert(loadstring == nil)

    assert(request.target.namespace == "mail")
    assert(request.target.action == "deliver")
    assert(request.caller.principal == "mail-gateway")
    assert(request.caller.client_id == "smtp-edge")
    assert(request.caller.authentication_kind == "private_key_jwt")
    assert(request.caller.scopes[1] == "policy.evaluate")
    assert(request.facts[1].id == "nauthilus.request.score")
    assert(request.facts[1].category == "environment")
    assert(request.facts[1].value.kind == "integer")
    assert(request.facts[1].value.value == "41")

    invocation_count = invocation_count + 1

    return {
        facts = {
            { name = "risk.label", value = { kind = "string", value = "trusted" } },
            { name = "risk.allowed", value = { kind = "boolean", value = true } },
            { name = "risk.score", value = { kind = "integer", value = "42" } },
            { name = "risk.ratio", value = { kind = "double", value = 0.5 } },
            { name = "risk.tags", value = { kind = "strings", value = { "mx", "trusted" } } },
            { name = "risk.digest", value = { kind = "bytes", value = "AAEC" } },
            { name = "risk.observed_at", value = { kind = "timestamp", value = "2026-08-25T08:30:00.123456789Z" } },
            { name = "runtime.invocations", value = { kind = "integer", value = tostring(invocation_count) } },
        },
    }
end

_G["policy.effects.execute"] = function(request)
    assert(request.effect == "mail/record-audit")
    assert(request.target.namespace == "mail")
    assert(request.target.action == "deliver")
    assert(request.parameters[1].name == "message")
    assert(request.parameters[1].value.kind == "string")
    assert(request.parameters[1].value.value == "accepted")

    return { state = "succeeded" }
end
