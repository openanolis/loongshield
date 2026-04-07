local probeloader = require('seharden.probeloader')
local enforcerloader = require('seharden.enforcerloader')

function test_probeloader_rejects_invalid_separator()
    local probe, err = probeloader.get("file/find_pattern")
    assert(probe == nil, "Expected invalid probe path to be rejected")
    assert(err:match("module%.function"), "Expected probe path format error")
end

function test_probeloader_rejects_non_string_path()
    local probe, err = probeloader.get(nil)
    assert(probe == nil, "Expected nil probe path to be rejected")
    assert(err:match("must be a string"), "Expected type error")
end

function test_enforcerloader_rejects_invalid_separator()
    local enforcer, err = enforcerloader.get("file/set_key_value")
    assert(enforcer == nil, "Expected invalid enforcer path to be rejected")
    assert(err:match("module%.function"), "Expected enforcer path format error")
end

function test_enforcerloader_rejects_non_string_path()
    local enforcer, err = enforcerloader.get(nil)
    assert(enforcer == nil, "Expected nil enforcer path to be rejected")
    assert(err:match("must be a string"), "Expected type error")
end
