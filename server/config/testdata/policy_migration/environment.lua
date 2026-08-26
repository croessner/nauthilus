-- Frozen B001-C2 environment provider used by production generation tests.
function nauthilus_call_environment(_request)
    if _request.protocol == "imap" then
        error("the protocol scheduler guard failed to skip this provider")
    end

    return 0, 0, 0
end
