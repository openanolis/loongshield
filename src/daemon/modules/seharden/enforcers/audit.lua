local lfs = require('lfs')
local fsutil = require('seharden.enforcers.fsutil')
local user_defaults = require('seharden.shared.user_defaults')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    io_popen = io.popen,
    os_rename = os.rename,
    os_remove = os.remove,
    os_execute = os.execute,
    lfs_attributes = lfs.attributes,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    rules_dir = '/etc/audit/rules.d',
    fallback_rules_path = '/etc/audit/audit.rules',
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function is_non_empty_string(value)
    return type(value) == 'string' and value ~= ''
end

local function is_safe_path(path)
    return is_non_empty_string(path) and not path:find('[%c\n\r]')
end

local function is_safe_key(key)
    return type(key) == 'string' and key:match('^[%w_.:-]+$') ~= nil
end

local function canonicalize_permissions(permissions)
    if type(permissions) ~= 'string' or permissions == '' then
        return nil
    end

    local seen = {}
    for char in permissions:gmatch('.') do
        if not char:match('[rwax]') then
            return nil
        end
        seen[char] = true
    end

    local ordered = {}
    for _, char in ipairs({ 'r', 'w', 'a', 'x' }) do
        if seen[char] then
            ordered[#ordered + 1] = char
        end
    end

    return table.concat(ordered)
end

local function normalize_string_list(values, field_name, pattern)
    if type(values) ~= 'table' or #values == 0 then
        return nil, string.format("audit.%s requires a non-empty '%s' list", field_name, field_name)
    end

    local normalized = {}
    local seen = {}
    for index, value in ipairs(values) do
        if type(value) ~= 'string' or value == '' or (pattern and not value:match(pattern)) then
            return nil, string.format("audit.%s requires '%s[%d]' to be a valid string", field_name, field_name, index)
        end
        if not seen[value] then
            normalized[#normalized + 1] = value
            seen[value] = true
        end
    end

    table.sort(normalized)
    return normalized
end

local function resolve_rule_file(params)
    if params and params.rule_file ~= nil then
        if not is_safe_path(params.rule_file) then
            return nil, "audit enforcer requires a safe 'rule_file' path"
        end
        return params.rule_file
    end

    local rules_dir = params and params.rules_dir or _dependencies.rules_dir
    local dir_attr = rules_dir and _dependencies.lfs_attributes(rules_dir)
    if dir_attr and dir_attr.mode == 'directory' then
        return rules_dir .. '/99-loongshield-seharden.rules'
    end

    local fallback_path = params and params.fallback_rules_path or _dependencies.fallback_rules_path
    if not is_safe_path(fallback_path) then
        return nil, 'audit enforcer requires a safe fallback audit rules path'
    end

    return fallback_path
end

function M.ensure_watch_rule(params)
    if not params or not is_safe_path(params.path) then
        return nil, "audit.ensure_watch_rule: requires a safe 'path' parameter"
    end

    local permissions = canonicalize_permissions(params.permissions)
    if not permissions then
        return nil, "audit.ensure_watch_rule: requires 'permissions' to contain only r,w,a,x"
    end

    if params.key ~= nil and not is_safe_key(params.key) then
        return nil, string.format("audit.ensure_watch_rule: invalid key '%s'", tostring(params.key))
    end

    local rule_file, path_err = resolve_rule_file(params)
    if not rule_file then
        return nil, path_err
    end

    local line = string.format('-w %s -p %s', params.path, permissions)
    if params.key then
        line = line .. string.format(' -k %s', params.key)
    end

    return fsutil.append_unique_line(rule_file, line, 'audit.ensure_watch_rule', _dependencies)
end

function M.ensure_syscall_rule(params)
    if not params then
        return nil, 'audit.ensure_syscall_rule: requires parameters'
    end

    local syscalls, syscall_err = normalize_string_list(params.syscalls, 'syscalls', '^[%w_]+$')
    if not syscalls then
        return nil, syscall_err:gsub('audit%.syscalls', 'audit.ensure_syscall_rule')
    end

    local arches = params.arches or params.required_arches or (params.arch and { params.arch })
    local normalized_arches, arch_err = normalize_string_list(arches, 'arches', '^[%w_]+$')
    if not normalized_arches then
        return nil, arch_err:gsub('audit%.arches', 'audit.ensure_syscall_rule')
    end

    local auid_min
    if params.auid_min == false then
        auid_min = nil
    elseif params.auid_min ~= nil then
        auid_min = tonumber(params.auid_min)
        if not auid_min or auid_min < 0 or auid_min ~= math.floor(auid_min) then
            return nil, "audit.ensure_syscall_rule: requires a non-negative integer 'auid_min'"
        end
    else
        auid_min = user_defaults.read_uid_min(_dependencies.io_open, '/etc/login.defs')
    end

    local include_auid_unset = params.require_auid_unset_exclusion ~= false

    -- Build optional comparison fragment: -C field!=value
    local comparison_fragment = ''
    if type(params.comparisons_any) == 'table' and #params.comparisons_any > 0 then
        local parts = {}
        for _, cmp in ipairs(params.comparisons_any) do
            if type(cmp) == 'string' and cmp ~= '' then
                parts[#parts + 1] = '-C ' .. cmp
            end
        end
        if #parts > 0 then
            comparison_fragment = ' ' .. table.concat(parts, ' ')
        end
    end

    -- Build optional fields fragment: -F name=value
    local fields_fragment = ''
    if type(params.fields) == 'table' and #params.fields > 0 then
        local parts = {}
        for _, field in ipairs(params.fields) do
            if type(field) == 'table' and field.name and field.value then
                parts[#parts + 1] = string.format('-F %s=%s', tostring(field.name), tostring(field.value))
            end
        end
        if #parts > 0 then
            fields_fragment = ' ' .. table.concat(parts, ' ')
        end
    end

    -- Build exit list (nil = no exit filter; list = one rule per exit value)
    local exit_values
    if type(params.exits) == 'table' and #params.exits > 0 then
        exit_values = {}
        for _, exit_val in ipairs(params.exits) do
            local normalized = tostring(exit_val):gsub('^%-', '')
            exit_values[#exit_values + 1] = normalized
        end
    end

    if params.key ~= nil and not is_safe_key(params.key) then
        return nil, string.format("audit.ensure_syscall_rule: invalid key '%s'", tostring(params.key))
    end

    local rule_file, path_err = resolve_rule_file(params)
    if not rule_file then
        return nil, path_err
    end

    local syscall_fragment = {}
    for _, syscall in ipairs(syscalls) do
        syscall_fragment[#syscall_fragment + 1] = '-S ' .. syscall
    end

    -- Build auid fragment
    local auid_fragment
    if auid_min and include_auid_unset then
        auid_fragment = string.format(' -F auid>=%d -F auid!=unset', auid_min)
    elseif auid_min then
        auid_fragment = string.format(' -F auid>=%d', auid_min)
    elseif include_auid_unset then
        auid_fragment = ' -F auid!=unset'
    else
        auid_fragment = ''
    end

    -- Build key fragment
    local key_fragment = params.key and string.format(' -k %s', params.key) or ''

    local function write_rule(exit_filter)
        local exit_frag = exit_filter and string.format(' -F exit=-%s', exit_filter) or ''
        for _, arch in ipairs(normalized_arches) do
            local line = string.format(
                '-a always,exit -F arch=%s %s%s%s%s%s%s',
                arch,
                table.concat(syscall_fragment, ' '),
                comparison_fragment,
                fields_fragment,
                exit_frag,
                auid_fragment,
                key_fragment
            )
            local ok, err = fsutil.append_unique_line(rule_file, line, 'audit.ensure_syscall_rule', _dependencies)
            if not ok then
                return nil, err
            end
        end
        return true
    end

    if exit_values then
        for _, exit_val in ipairs(exit_values) do
            local ok, err = write_rule(exit_val)
            if not ok then
                return nil, err
            end
        end
    else
        local ok, err = write_rule(nil)
        if not ok then
            return nil, err
        end
    end

    return true
end

-- Ensure an audit path-exec rule exists in the rules file.
-- Monitors execution of a specific binary path.
-- params: { path: "/usr/bin/foo", key: "mykey", arches: {"b64"} (optional) }
function M.ensure_path_exec_rule(params)
    if not params or not is_safe_path(params.path) then
        return nil, "audit.ensure_path_exec_rule: requires a safe 'path' parameter"
    end

    if params.key ~= nil and not is_safe_key(params.key) then
        return nil, string.format("audit.ensure_path_exec_rule: invalid key '%s'", tostring(params.key))
    end

    local arches = params.arches or params.required_arches or { 'b64', 'b32' }
    local normalized_arches, arch_err = normalize_string_list(arches, 'arches', '^[%w_]+$')
    if not normalized_arches then
        return nil, arch_err:gsub('audit%.arches', 'audit.ensure_path_exec_rule')
    end

    local rule_file, path_err = resolve_rule_file(params)
    if not rule_file then
        return nil, path_err
    end

    local key_fragment = params.key and string.format(' -k %s', params.key) or ''

    for _, arch in ipairs(normalized_arches) do
        local line = string.format('-a always,exit -F arch=%s -F path=%s -F perm=x%s', arch, params.path, key_fragment)
        local ok, err = fsutil.append_unique_line(rule_file, line, 'audit.ensure_path_exec_rule', _dependencies)
        if not ok then
            return nil, err
        end
    end

    return true
end

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function normalize_popen_close(ok, _, code)
    if ok == true then
        return true
    end
    if type(code) == 'number' then
        return code == 0
    end
    if type(ok) == 'number' then
        return ok == 0
    end
    if ok == nil and code == nil then
        return true
    end
    return false
end

-- Run a shell command and collect its output lines.
local function run_command_lines(command)
    local handle = _dependencies.io_popen(command, 'r')
    if not handle then
        return nil, 'Could not execute command: ' .. command
    end

    local lines = {}
    for line in handle:lines() do
        local trimmed = line:match('^%s*(.-)%s*$')
        if trimmed ~= '' then
            lines[#lines + 1] = trimmed
        end
    end

    local ok, status_type, code = handle:close()
    if not normalize_popen_close(ok, status_type, code) then
        return nil, 'Command did not complete successfully: ' .. command
    end
    return lines
end

-- List eligible mount points (same logic as the audit probe).
-- Excludes filesystems with noexec or nosuid mount options.
local function list_eligible_mount_points()
    return run_command_lines(
        [[findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) ]]
            .. [[| grep -Pv 'noexec|nosuid' | awk '{print $1}' 2>/dev/null]]
    )
end

-- Collect setuid/setgid binaries across all eligible mount points,
-- matching the probe's inventory so that the enforcer can converge.
local function collect_privileged_paths()
    local mounts, mount_err = list_eligible_mount_points()
    if not mounts then
        return nil, mount_err
    end

    local paths = {}
    local seen = {}
    for _, mount in ipairs(mounts) do
        local found, find_err = run_command_lines(
            'find ' .. shell_escape(mount) .. ' -xdev -perm /6000 -type f 2>/dev/null'
        )
        if not found then
            return nil, find_err
        end
        for _, path in ipairs(found) do
            if not seen[path] then
                paths[#paths + 1] = path
                seen[path] = true
            end
        end
    end
    table.sort(paths)
    return paths
end

-- Ensure audit path-exec rules exist for all discovered setuid/setgid binaries.
-- Scans eligible mount points (matching the probe's inventory logic) and
-- writes one path_exec rule per binary so the rule can converge.
-- params: { key: "privileged" (optional) }
function M.ensure_privileged_command_rules(params)
    local key = (params and params.key) or 'privileged'

    if not is_safe_key(key) then
        return nil, string.format("audit.ensure_privileged_command_rules: invalid key '%s'", tostring(key))
    end

    local rule_file, path_err = resolve_rule_file(params)
    if not rule_file then
        return nil, path_err
    end

    -- Collect setuid/setgid binaries across eligible mount points
    -- (same logic as probe's collect_privileged_paths_from_system).
    local paths, collect_err = collect_privileged_paths()
    if not paths then
        return nil, string.format('audit.ensure_privileged_command_rules: %s', collect_err)
    end

    for _, path in ipairs(paths) do
        for _, arch in ipairs({ 'b64', 'b32' }) do
            local rule_line = string.format(
                '-a always,exit -F arch=%s -F path=%s -F perm=x -F auid>=1000 -F auid!=unset -k %s',
                arch,
                path,
                key
            )
            local ok, err =
                fsutil.append_unique_line(rule_file, rule_line, 'audit.ensure_privileged_command_rules', _dependencies)
            if not ok then
                return nil, err
            end
        end
    end

    return true
end

-- Reload audit rules from persistent configuration using augenrules.
-- This compiles /etc/audit/rules.d/*.rules into /etc/audit/audit.rules
-- and loads them into the running kernel.
-- params: {} (no parameters needed)
function M.reload_rules(params)
    local log = require('runtime.log')
    local cmd = 'augenrules --load 2>&1'
    log.debug('audit.reload_rules: %s', cmd)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil, string.format('audit.reload_rules: augenrules --load failed (exit %s)', tostring(code))
    end
    log.debug('audit.reload_rules: audit rules reloaded successfully')
    return true
end

-- Ensure an audit directive line exists in the rules file.
-- Appends the directive if not already present. Idempotent.
-- params: { directive: "-c" | "-e", value: "2" (optional) }
function M.ensure_directive(params)
    if not params or not params.directive then
        return nil, "audit.ensure_directive: requires 'directive' parameter"
    end

    local directive = params.directive
    if not directive:match('^%-') then
        return nil, string.format("audit.ensure_directive: directive '%s' must start with '-'", directive)
    end

    local rule_file, path_err = resolve_rule_file(params)
    if not rule_file then
        return nil, path_err
    end

    local line = directive
    if params.value then
        line = line .. ' ' .. tostring(params.value)
    end

    return fsutil.append_unique_line(rule_file, line, 'audit.ensure_directive', _dependencies)
end

return M
