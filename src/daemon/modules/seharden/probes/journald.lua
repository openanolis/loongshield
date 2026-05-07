local file_probe = require('seharden.probes.file')

local M = {}

function M._test_set_dependencies(deps)
    file_probe._test_set_dependencies(deps)
end

local BOOLEAN_VALUES = {
    yes = true,
    ["true"] = true,
    ["1"] = true,
    on = true,
    no = false,
    ["false"] = false,
    ["0"] = false,
    off = false,
}

local function parse_systemd_boolean(value)
    if value == nil then
        return nil
    end
    return BOOLEAN_VALUES[tostring(value):lower()]
end

function M.inspect_forward_to_syslog_disabled(params)
    params = params or {}
    local values, err = file_probe.parse_systemd_key_values({
        path = params.path or "/etc/systemd/journald.conf",
        config_dirs = params.config_dirs,
        section = "Journal",
        effective = true,
        allow_missing = true,
        normalize_values = "lower",
    })

    if not values then
        return {
            available = false,
            error = err,
            found = false,
            value = nil,
            configured = false,
        }
    end

    local value = values.ForwardToSyslog
    local parsed = parse_systemd_boolean(value)
    local configured = value == nil or parsed == false

    return {
        available = true,
        found = value ~= nil,
        value = value,
        parsed = parsed,
        configured = configured,
    }
end

return M
