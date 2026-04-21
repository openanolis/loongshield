local kmod_probe = require('seharden.probes.kmod')

local function make_ctx(opts)
    return {
        modules_from_loaded = function()
            local mods = opts.loaded or {}
            local i = 0
            return function()
                i = i + 1
                local name = mods[i]
                if not name then return nil end
                return { name = function() return name end }
            end
        end,
        config_blacklists = function()
            local list = opts.blacklisted or {}
            local i = 0
            return function()
                i = i + 1
                return list[i]
            end
        end,
        config_install_commands = function()
            local list = opts.install or {}
            local i = 0
            return function()
                i = i + 1
                local item = list[i]
                if not item then return nil end
                return item.name, item.cmd
            end
        end
    }
end

function test_is_loaded_true()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({ loaded = { "cramfs" } })
        end
    })
    local result = kmod_probe.is_loaded({ name = "cramfs" })
    assert(result.loaded == true, "Expected module to be loaded")
end

function test_is_loaded_false()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({ loaded = { "squashfs" } })
        end
    })
    local result = kmod_probe.is_loaded({ name = "cramfs" })
    assert(result.loaded == false, "Expected module to be not loaded")
end

function test_is_blacklisted_true()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({ blacklisted = { "cramfs" } })
        end
    })
    local result = kmod_probe.is_blacklisted({ name = "cramfs" })
    assert(result.blacklisted == true, "Expected module to be blacklisted")
end

function test_get_install_command_default_none()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({ install = {} })
        end
    })
    local result = kmod_probe.get_install_command({ name = "cramfs" })
    assert(result.command == "none", "Expected default command none")
end

function test_get_install_command_match()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({ install = { { name = "cramfs", cmd = "/bin/false" } } })
        end
    })
    local result = kmod_probe.get_install_command({ name = "cramfs" })
    assert(result.command == "/bin/false", "Expected command /bin/false")
end

function test_is_loaded_uses_fresh_context_each_call()
    local calls = 0

    kmod_probe._test_set_dependencies({
        ctx_new = function()
            calls = calls + 1
            if calls == 1 then
                return make_ctx({ loaded = { "cramfs" } })
            end
            return make_ctx({ loaded = {} })
        end
    })

    local first = kmod_probe.is_loaded({ name = "cramfs" })
    local second = kmod_probe.is_loaded({ name = "cramfs" })

    assert(first.loaded == true, "Expected first call to see loaded module")
    assert(second.loaded == false, "Expected second call to observe updated context")
    assert(calls == 2, "Expected kmod context to be recreated on each call")
end

function test_is_loaded_requires_name()
    local result, err = kmod_probe.is_loaded(nil)
    assert(result == nil, "Expected nil result when name is missing")
    assert(err:match("requires a 'name' parameter"), "Expected missing name error")
end
