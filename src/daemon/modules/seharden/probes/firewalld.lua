local log = require('runtime.log')
local text = require('seharden.shared.text')
local lfs = require('lfs')

local M = {}

local _default_dependencies = {
    io_popen = io.popen,
    io_open = io.open,
    lfs_dir = lfs and lfs.dir or nil,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local shell_escape = text.shell_escape

--- Read a whole file, or nil when it cannot be opened.
local function read_file(path)
    local f = _dependencies.io_open(path, 'r')
    if not f then
        return nil
    end
    local content = f:read('*a')
    f:close()
    return content
end

--- Heuristic check for SSH allowance in a firewalld zone XML file.
-- Matches <service name="ssh"/> and <port port="22" protocol="tcp"/> with
-- attributes in either order; firewalld writes these files canonically.
-- Rich rules opening SSH are not covered by this heuristic.
local function zone_xml_allows_ssh(xml)
    return xml:match('service[^>]*name="ssh"')
        or xml:match('port[^>]*port="22"[^>]*protocol="tcp"')
        or xml:match('port[^>]*protocol="tcp"[^>]*port="22"')
end

local function zone_option(zone)
    return '--zone=' .. shell_escape(zone)
end

local function unavailable_result(err, checked_count, violations)
    violations = violations or {}
    return {
        available = false,
        error = err,
        checked_count = checked_count or 0,
        violation_count = #violations,
        details = violations,
    }
end

local function read_command(command)
    local handle = _dependencies.io_popen(command, 'r')
    if not handle then
        return nil, 'failed to execute command'
    end

    local lines = {}
    for line in handle:lines() do
        lines[#lines + 1] = line
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil, string.format('command failed with exit code: %s', tostring(code))
    end

    return lines
end

local function parse_active_zones(lines)
    local zones = {}
    for _, line in ipairs(lines or {}) do
        local zone = line:match('^(%S+)%s*$')
        if zone and zone ~= 'interfaces:' and zone ~= 'sources:' then
            zones[#zones + 1] = zone
        end
    end
    return zones
end

local function split_words(value)
    local words = {}
    for word in tostring(value or ''):gmatch('%S+') do
        words[#words + 1] = word
    end
    return words
end

local function is_loopback_or_virtual_interface(name)
    return name == 'lo' or tostring(name):match('^virbr%S*$') ~= nil
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
        local target = line:match('^%s*target:%s*(%S+)%s*$')
        if target then
            return target
        end
    end
    return ''
end

local function lower(value)
    return tostring(value or ''):lower()
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
    local active_lines, active_err = read_command('firewall-cmd --get-active-zones 2>/dev/null')
    if not active_lines then
        return unavailable_result(active_err)
    end

    local zones = parse_active_zones(active_lines)
    local checked_count = 0
    local violations = {}

    for _, zone in ipairs(zones) do
        if not zone:match('^[%w_.:-]+$') then
            add_violation(violations, zone, 'invalid_zone_name')
            goto continue
        end

        local zone_arg = zone_option(zone)
        local interfaces_lines, interfaces_err =
            read_command('firewall-cmd ' .. zone_arg .. ' --list-interfaces 2>/dev/null')
        if not interfaces_lines then
            return unavailable_result(interfaces_err, checked_count, violations)
        end

        local interfaces = text.trim(table.concat(interfaces_lines, ' '))
        if should_check_interfaces(interfaces) then
            checked_count = checked_count + 1

            local permanent_lines, permanent_err =
                read_command('firewall-cmd --permanent ' .. zone_arg .. ' --get-target 2>/dev/null')
            local list_all_lines, list_all_err = read_command('firewall-cmd --list-all ' .. zone_arg .. ' 2>/dev/null')
            if not permanent_lines or not list_all_lines then
                return unavailable_result(permanent_err or list_all_err, checked_count, violations)
            end

            local permanent_target = text.trim(table.concat(permanent_lines, ' '))
            local active_target = parse_target_from_list_all(list_all_lines)

            if active_target == '' or lower(active_target) == 'accept' then
                add_violation(violations, zone, 'active_target_accept_or_empty', {
                    active_target = active_target,
                    interfaces = interfaces,
                })
            elseif lower(active_target) ~= lower(permanent_target) then
                add_violation(violations, zone, 'target_not_permanent', {
                    active_target = active_target,
                    permanent_target = permanent_target,
                    interfaces = interfaces,
                })
            end
        end

        ::continue::
    end

    if checked_count == 0 then
        add_violation(violations, nil, 'no_active_non_loopback_zone')
    end

    return {
        available = true,
        checked_count = checked_count,
        violation_count = #violations,
        details = violations,
    }
end

--- Check whether firewalld allows SSH in its on-disk zone configuration.
-- Reads zone XML files from /etc/firewalld/zones and the packaged defaults in
-- /usr/lib/firewalld/zones, so the check works while firewalld is stopped
-- (the scenario in which rule 3.3.1 needs to reinforce). When the
-- configuration cannot be inspected (e.g. firewalld is not installed), returns
-- false so the `no_ssh_service` guard fails closed and skips reinforcement.
-- Returns: true, reason  when SSH is configured in firewalld
--          false          when SSH is not found or config is unavailable
function M.has_ssh_service(_params)
    local zone_dirs = _dependencies.firewalld_zone_dirs
        or { '/etc/firewalld/zones', '/usr/lib/firewalld/zones' }

    for _, dir in ipairs(zone_dirs) do
        local ok, iter, dir_obj = pcall(_dependencies.lfs_dir, dir)
        if ok and iter then
            for name in iter, dir_obj do
                if name:match('%.xml$') then
                    local content = read_file(dir .. '/' .. name)
                    if content and zone_xml_allows_ssh(content) then
                        return true, string.format('firewalld zone %s allows SSH in %s', name, dir)
                    end
                end
            end
        end
    end

    log.debug('firewalld.has_ssh_service: no SSH service/port in on-disk zone configuration')
    return false
end

--- Check whether firewalld has NO SSH service or port 22 allowed in any active zone.
-- Inverse of `has_ssh_service`, for use as a lockout-protection reinforce guard:
-- returns truthy when enabling firewalld would drop SSH access, so that
-- `evaluate_guard()` (truthy = skip) skips the enable/start reinforcement.
-- Returns: true, reason  when SSH is NOT found (reinforce should be skipped)
--          false          when SSH is configured in firewalld
function M.no_ssh_service(params)
    local found = M.has_ssh_service(params)
    if found then
        return false
    end
    return true, 'firewalld has no SSH service or port 22 in an active zone'
end

return M
