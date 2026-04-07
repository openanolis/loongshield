local services_probe = require('seharden.probes.services')

local Mocks = {}

local function setup(opts)
    Mocks = opts or {}

    local function fake_bus_default_system()
        if Mocks.bus_error then
            return nil, "no bus"
        end
        return {
            unit_filestate = function(_, unit)
                if Mocks.unit_not_found then
                    return nil
                end
                return {
                    read = function()
                        if Mocks.read_error then
                            return nil, "read error"
                        end
                        return Mocks.unit_state or "enabled"
                    end
                }
            end
        }
    end

    local function fake_io_popen(cmd)
        Mocks.popen_cmd = cmd
        Mocks.popen_cmds = Mocks.popen_cmds or {}
        table.insert(Mocks.popen_cmds, cmd)

        if cmd:match("systemctl show ") then
            if Mocks.show_handle_missing then
                return nil
            end
            return {
                read = function()
                    return Mocks.systemctl_show_output or ""
                end,
                close = function() return true end
            }
        end

        if cmd:match("systemctl %-%-root=/ is%-enabled ") then
            if Mocks.is_enabled_handle_missing then
                return nil
            end
            return {
                read = function()
                    return Mocks.systemctl_is_enabled_output or ""
                end,
                close = function() return true end
            }
        end

        return {
            read = function()
                return (Mocks.active_state or "active") .. "\n"
            end,
            close = function() return true end
        }
    end

    services_probe._test_set_dependencies({
        bus_default_system = fake_bus_default_system,
        io_popen = fake_io_popen,
        lfs_attributes = Mocks.lfs_attributes or function(path)
            if path == "/usr/bin/systemctl" then
                return { mode = "file" }
            end
            return nil
        end
    })
end

function test_get_unit_properties_success()
    setup({ unit_state = "enabled", active_state = "active" })
    local result = services_probe.get_unit_properties({ name = "sshd.service" })
    assert(result.UnitFileState == "enabled", "Expected enabled state")
    assert(result.ActiveState == "active", "Expected active state")
end

function test_get_unit_properties_bus_failure_falls_back_to_systemctl_show()
    setup({
        bus_error = true,
        systemctl_show_output = "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n"
    })
    local result = services_probe.get_unit_properties({ name = "sshd.service" })
    assert(result.UnitFileState == "disabled", "Expected UnitFileState fallback from systemctl show")
    assert(result.ActiveState == "inactive", "Expected ActiveState fallback from systemctl show")
end

function test_get_unit_properties_retries_dbus_after_failure()
    local bus_calls = 0

    services_probe._test_set_dependencies({
        bus_default_system = function()
            bus_calls = bus_calls + 1
            if bus_calls == 1 then
                return nil, "no bus"
            end
            return {
                unit_filestate = function()
                    return {
                        read = function()
                            return "enabled"
                        end
                    }
                end
            }
        end,
        io_popen = function(cmd)
            return {
                read = function()
                    if cmd:match("systemctl show ") then
                        return "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n"
                    end
                    return "active\n"
                end,
                close = function()
                    return true
                end
            }
        end,
        lfs_attributes = function(path)
            if path == "/usr/bin/systemctl" then
                return { mode = "file" }
            end
            return nil
        end
    })

    local first = services_probe.get_unit_properties({ name = "sshd.service" })
    local second = services_probe.get_unit_properties({ name = "sshd.service" })

    assert(first.UnitFileState == "disabled", "Expected first call to use systemctl show fallback")
    assert(second.UnitFileState == "enabled", "Expected second call to retry D-Bus")
    assert(bus_calls == 2, "Expected D-Bus connection to be retried")
end

function test_get_unit_properties_unit_not_found()
    setup({ unit_not_found = true })
    local result = services_probe.get_unit_properties({ name = "missing.service" })
    assert(result.UnitFileState == "not-found", "Expected not-found state")
end

function test_get_unit_properties_unit_filestate_not_found_falls_back_to_systemctl_show()
    setup({
        unit_not_found = true,
        systemctl_show_output = "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n"
    })
    local result = services_probe.get_unit_properties({ name = "crond" })
    assert(result.UnitFileState == "enabled", "Expected systemctl show fallback for bare unit names")
    assert(result.ActiveState == "active", "Expected ActiveState fallback for bare unit names")
end

function test_get_unit_properties_bus_failure_maps_systemctl_not_found()
    setup({
        bus_error = true,
        systemctl_show_output = "LoadState=not-found\nUnitFileState=\nActiveState=inactive\n"
    })
    local result = services_probe.get_unit_properties({ name = "missing.service" })
    assert(result.UnitFileState == "not-found", "Expected LoadState=not-found to map to not-found")
    assert(result.ActiveState == "inactive", "Expected fallback ActiveState from systemctl show")
end

function test_get_unit_properties_read_error_falls_back_to_systemctl_show()
    setup({
        read_error = true,
        systemctl_show_output = "LoadState=loaded\nUnitFileState=masked\nActiveState=inactive\n"
    })
    local result = services_probe.get_unit_properties({ name = "masked.service" })
    assert(result.UnitFileState == "masked", "Expected read errors to fall back to systemctl show")
    assert(result.ActiveState == "inactive", "Expected ActiveState fallback to remain available")
end

function test_get_unit_properties_bus_failure_returns_unknown_when_all_fallbacks_unavailable()
    setup({
        bus_error = true,
        systemctl_show_output = "Failed to connect to bus: Operation not permitted\n",
        active_state = "active"
    })
    local result = services_probe.get_unit_properties({ name = "sshd.service" })
    assert(result.UnitFileState == "unknown", "Expected unknown state when D-Bus and unit file state fallbacks fail")
    assert(result.ActiveState == "active", "Expected legacy systemctl is-active fallback to remain available")
end

function test_get_unit_properties_uses_offline_is_enabled_for_bare_service_name()
    setup({
        bus_error = true,
        systemctl_show_output = "Failed to connect to bus: Operation not permitted\n",
        systemctl_is_enabled_output = "enabled\n",
        active_state = "inactive"
    })

    local result = services_probe.get_unit_properties({ name = "crond" })

    assert(result.UnitFileState == "enabled", "Expected offline is-enabled fallback to recover UnitFileState")
    assert(result.ActiveState == "inactive", "Expected is-active fallback to remain available")
    assert(Mocks.popen_cmds[1]:match("^/usr/bin/systemctl show .* crond%.service 2>/dev/null$"),
        "Expected systemctl show to use the normalized unit name")
    assert(Mocks.popen_cmds[2]:match("^/usr/bin/systemctl %-%-root=/ is%-enabled crond%.service 2>/dev/null$"),
        "Expected offline is-enabled fallback to use the resolved absolute path")
    assert(Mocks.popen_cmds[3]:match("^/usr/bin/systemctl is%-active crond%.service 2>/dev/null$"),
        "Expected systemctl is-active to use the normalized unit name")
end

function test_get_unit_properties_invalid_unit_name()
    setup({})
    local result = services_probe.get_unit_properties({ name = "bad;name" })
    assert(result.ActiveState == "unknown", "Expected unknown active state for invalid unit name")
end

function test_get_unit_properties_missing_param()
    local result, err = services_probe.get_unit_properties({})
    assert(result == nil, "Expected nil result for missing param")
    assert(err:match("requires a 'name' parameter"), "Expected missing param error")
end
