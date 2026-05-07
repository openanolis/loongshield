local text = require('seharden.shared.text')

local M = {}

local _default_dependencies = {
    io_popen = io.popen,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function shell_escape(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function read_command(command)
    local handle = _dependencies.io_popen(command, "r")
    if not handle then
        return nil, "failed to execute command"
    end

    local lines = {}
    for line in handle:lines() do
        lines[#lines + 1] = line
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil, string.format("command failed with exit code: %s", tostring(code))
    end

    return lines
end

local function parse_active_zones(lines)
    local zones = {}
    for _, line in ipairs(lines or {}) do
        local zone = line:match("^(%S+)%s*$")
        if zone and zone ~= "interfaces:" and zone ~= "sources:" then
            zones[#zones + 1] = zone
        end
    end
    return zones
end

local function split_words(value)
    local words = {}
    for word in tostring(value or ""):gmatch("%S+") do
        words[#words + 1] = word
    end
    return words
end

local function is_loopback_or_virtual_interface(name)
    return name == "lo" or tostring(name):match("^virbr%S*$") ~= nil
end

local function should_check_interfaces(value)
    local interfaces = split_words(value)
    if #interfaces == 0 then
        return true
    end

    for _, iface in ipairs(interfaces) do
        if not is_loopback_or_virtual_interface(iface) then
            return true
        end
    end

    return false
end

local function parse_target_from_list_all(lines)
    for _, line in ipairs(lines or {}) do
        local target = line:match("^%s*target:%s*(%S+)%s*$")
        if target then
            return target
        end
    end
    return ""
end

local function lower(value)
    return tostring(value or ""):lower()
end

local function add_violation(violations, zone, reason, extra)
    local detail = {
        zone = zone,
        reason = reason,
    }
    for key, value in pairs(extra or {}) do
        detail[key] = value
    end
    violations[#violations + 1] = detail
end

function M.inspect_active_zone_targets()
    local active_lines, active_err = read_command("firewall-cmd --get-active-zones 2>/dev/null")
    if not active_lines then
        return {
            available = false,
            error = active_err,
            checked_count = 0,
            violation_count = 0,
            details = {},
        }
    end

    local zones = parse_active_zones(active_lines)
    local checked_count = 0
    local violations = {}

    for _, zone in ipairs(zones) do
        if not zone:match("^[%w_.:-]+$") then
            add_violation(violations, zone, "invalid_zone_name")
            goto continue
        end

        local escaped_zone = shell_escape(zone)
        local interfaces_lines, interfaces_err = read_command(
            "firewall-cmd --zone=" .. escaped_zone .. " --list-interfaces 2>/dev/null")
        if not interfaces_lines then
            return {
                available = false,
                error = interfaces_err,
                checked_count = checked_count,
                violation_count = #violations,
                details = violations,
            }
        end

        local interfaces = text.trim(table.concat(interfaces_lines, " "))
        if should_check_interfaces(interfaces) then
            checked_count = checked_count + 1

            local permanent_lines, permanent_err = read_command(
                "firewall-cmd --permanent --zone=" .. escaped_zone .. " --get-target 2>/dev/null")
            local list_all_lines, list_all_err = read_command(
                "firewall-cmd --list-all --zone=" .. escaped_zone .. " 2>/dev/null")
            if not permanent_lines or not list_all_lines then
                return {
                    available = false,
                    error = permanent_err or list_all_err,
                    checked_count = checked_count,
                    violation_count = #violations,
                    details = violations,
                }
            end

            local permanent_target = text.trim(table.concat(permanent_lines, " "))
            local active_target = parse_target_from_list_all(list_all_lines)

            if active_target == "" or lower(active_target) == "accept" then
                add_violation(violations, zone, "active_target_accept_or_empty", {
                    active_target = active_target,
                    interfaces = interfaces,
                })
            elseif lower(active_target) ~= lower(permanent_target) then
                add_violation(violations, zone, "target_not_permanent", {
                    active_target = active_target,
                    permanent_target = permanent_target,
                    interfaces = interfaces,
                })
            end
        end

        ::continue::
    end

    if checked_count == 0 then
        add_violation(violations, nil, "no_active_non_loopback_zone")
    end

    return {
        available = true,
        checked_count = checked_count,
        violation_count = #violations,
        details = violations,
    }
end

return M
