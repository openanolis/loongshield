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
        end,
        module_from_name_lookup = function(_, name)
            local modules = opts.available or {}
            local item = modules[name]
            if not item then
                return nil, 2, "No such file or directory"
            end
            return {
                initstate = function() return item.state or "unknown" end,
                path = function() return item.path end,
            }
        end,
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

function test_get_availability_reports_unavailable_modules()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({ available = {} })
        end
    })

    local result = kmod_probe.get_availability({ name = "dccp" })
    assert(result.available == false, "Expected missing modules to be unavailable")
    assert(result.builtin == false, "Expected missing modules not to be treated as built in")
end

function test_get_availability_marks_builtin_modules_available()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({
                available = {
                    dccp = { state = "builtin", path = nil },
                },
            })
        end
    })

    local result = kmod_probe.get_availability({ name = "dccp" })
    assert(result.available == true, "Expected built-in modules to be available")
    assert(result.builtin == true, "Expected built-in modules to be flagged explicitly")
end

function test_get_disable_state_passes_unavailable_modules()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({ available = {} })
        end
    })

    local result = kmod_probe.get_disable_state({ name = "freevxfs" })

    assert(result.disabled == true, "Expected unavailable modules to satisfy CIS disable policy")
    assert(result.available == false, "Expected unavailable state to be exposed for diagnostics")
end

function test_get_disable_state_passes_disabled_loadable_modules()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({
                available = {
                    freevxfs = { state = "live", path = "/lib/modules/freevxfs.ko" },
                },
                blacklisted = { "freevxfs" },
                install = { { name = "freevxfs", cmd = "/bin/false" } },
            })
        end
    })

    local result = kmod_probe.get_disable_state({ name = "freevxfs" })

    assert(result.disabled == true, "Expected unloaded, blacklisted modules with disabled install command to pass")
    assert(result.loaded == false, "Expected load state to be reported")
    assert(result.blacklisted == true, "Expected blacklist state to be reported")
    assert(result.install_command_disabled == true, "Expected disabled install command state to be reported")
end

function test_get_disable_state_normalizes_hyphenated_module_names()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({
                available = {
                    usb_storage = { state = "live", path = "/lib/modules/usb_storage.ko" },
                },
                blacklisted = { "usb_storage" },
                install = { { name = "usb_storage", cmd = "/bin/false" } },
            })
        end
    })

    local result = kmod_probe.get_disable_state({ name = "usb-storage" })

    assert(result.disabled == true, "Expected hyphenated module names to match underscore kmod records")
    assert(result.available == true, "Expected availability lookup to try the canonical underscore form")
    assert(result.lookup_name == "usb_storage", "Expected diagnostics to expose the matched kmod lookup name")
    assert(result.blacklisted == true, "Expected underscore blacklist entries to satisfy hyphenated profile rules")
    assert(result.install_command_disabled == true,
        "Expected underscore install command entries to satisfy hyphenated profile rules")
end

function test_get_disable_state_detects_loaded_canonical_module_names()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({
                available = {
                    firewire_core = { state = "live", path = "/lib/modules/firewire_core.ko" },
                },
                loaded = { "firewire_core" },
                blacklisted = { "firewire_core" },
                install = { { name = "firewire_core", cmd = "/bin/false" } },
            })
        end
    })

    local result = kmod_probe.get_disable_state({ name = "firewire-core" })

    assert(result.disabled == false, "Expected loaded underscore module to fail a hyphenated CIS rule")
    assert(result.loaded == true, "Expected loaded module detection to normalize hyphen and underscore names")
end

function test_get_disable_state_fails_builtin_modules()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({
                available = {
                    freevxfs = { state = "builtin" },
                },
                blacklisted = { "freevxfs" },
                install = { { name = "freevxfs", cmd = "/bin/false" } },
            })
        end
    })

    local result = kmod_probe.get_disable_state({ name = "freevxfs" })

    assert(result.disabled == false, "Expected built-in modules to fail CIS disable policy")
    assert(result.builtin == true, "Expected built-in state to be reported")
end

function test_get_disable_state_fails_loaded_modules()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({
                available = {
                    freevxfs = { state = "live", path = "/lib/modules/freevxfs.ko" },
                },
                loaded = { "freevxfs" },
                blacklisted = { "freevxfs" },
                install = { { name = "freevxfs", cmd = "/bin/false" } },
            })
        end
    })

    local result = kmod_probe.get_disable_state({ name = "freevxfs" })

    assert(result.disabled == false, "Expected loaded modules to fail CIS disable policy")
    assert(result.loaded == true, "Expected loaded state to be reported")
end

function test_get_disable_state_fails_missing_blacklist_or_install_command()
    kmod_probe._test_set_dependencies({
        ctx_new = function()
            return make_ctx({
                available = {
                    freevxfs = { state = "live", path = "/lib/modules/freevxfs.ko" },
                },
            })
        end
    })

    local result = kmod_probe.get_disable_state({ name = "freevxfs" })

    assert(result.disabled == false, "Expected loadable modules without modprobe policy to fail")
    assert(result.blacklisted == false, "Expected missing blacklist to be reported")
    assert(result.install_command == "none", "Expected missing install command to be reported")
    assert(result.install_command_disabled == false, "Expected missing install command to fail")
end
