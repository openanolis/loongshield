local loader = require('seharden.loader')

local function with_preloaded_module(name, value, fn)
    local saved = package.loaded[name]
    package.loaded[name] = value
    local ok, err = pcall(fn)
    package.loaded[name] = saved
    if not ok then
        error(err)
    end
end

function test_loader_get_probe_rejects_invalid_separator()
    local probe, err = loader.get_probe("file/find_pattern")
    assert(probe == nil, "Expected invalid probe path to be rejected")
    assert(err:match("module%.function"), "Expected probe path format error")
end

function test_loader_get_probe_rejects_non_string_path()
    local probe, err = loader.get_probe(nil)
    assert(probe == nil, "Expected nil probe path to be rejected")
    assert(err:match("must be a string"), "Expected type error")
end

function test_loader_get_enforcer_rejects_invalid_separator()
    local enforcer, err = loader.get_enforcer("file/set_key_value")
    assert(enforcer == nil, "Expected invalid enforcer path to be rejected")
    assert(err:match("module%.function"), "Expected enforcer path format error")
end

function test_loader_get_enforcer_rejects_non_string_path()
    local enforcer, err = loader.get_enforcer(nil)
    assert(enforcer == nil, "Expected nil enforcer path to be rejected")
    assert(err:match("must be a string"), "Expected type error")
end

function test_loader_get_probe_loads_preloaded_module_function()
    with_preloaded_module("seharden.probes._test_loader_probe", {
        ping = function() return "pong" end
    }, function()
        local probe, path = loader.get_probe("_test_loader_probe.ping")
        assert(type(probe) == "function", "Expected probe function to be returned")
        assert(path == "_test_loader_probe.ping", "Expected returned path to be normalized")
        assert(probe() == "pong", "Expected resolved probe function to remain callable")
    end)
end

function test_loader_get_enforcer_reuses_cached_module()
    local load_count = 0
    local module_name = "seharden.enforcers._test_loader_enforcer"
    local original_require = require

    with_preloaded_module(module_name, nil, function()
        require = function(name)
            if name == module_name then
                load_count = load_count + 1
                local mod = {
                    apply = function() return true end
                }
                package.loaded[name] = mod
                return mod
            end
            return original_require(name)
        end

        local first = assert(loader.get_enforcer("_test_loader_enforcer.apply"))
        local second = assert(loader.get_enforcer("_test_loader_enforcer.apply"))

        require = original_require

        assert(type(first) == "function", "Expected first load to resolve an enforcer")
        assert(first == second, "Expected cached enforcer function to be reused")
        assert(load_count == 1, "Expected loader to require the module only once")
    end)

    require = original_require
end
