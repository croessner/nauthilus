_G["policy.facts.collect"] = function(_)
    return {
        facts = {
            { name = "risk.score", value = { kind = "integer", value = "42" } },
        },
        decision = "permit",
    }
end
