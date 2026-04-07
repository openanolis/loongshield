local lfs = require('lfs')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    lfs_attributes = lfs.attributes,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    rules_dir = "/etc/audit/rules.d",
    fallback_rules_path = "/etc/audit/audit.rules",
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
    return type(value) == "string" and value ~= ""
end

local function is_safe_path(path)
    return is_non_empty_string(path) and not path:find("[%c\n\r]")
end

local function is_safe_key(key)
    return type(key) == "string" and key:match("^[%w_.:-]+$") ~= nil
end

local function canonicalize_permissions(permissions)
    if type(permissions) ~= "string" or permissions == "" then
        return nil
    end

    local seen = {}
    for char in permissions:gmatch(".") do
        if not char:match("[rwax]") then
            return nil
        end
        seen[char] = true
    end

    local ordered = {}
    for _, char in ipairs({ "r", "w", "a", "x" }) do
        if seen[char] then
            ordered[#ordered + 1] = char
        end
    end

    return table.concat(ordered)
end

local function normalize_string_list(values, field_name, pattern)
    if type(values) ~= "table" or #values == 0 then
        return nil, string.format("audit.%s requires a non-empty '%s' list", field_name, field_name)
    end

    local normalized = {}
    local seen = {}
    for index, value in ipairs(values) do
        if type(value) ~= "string" or value == "" or (pattern and not value:match(pattern)) then
            return nil, string.format(
                "audit.%s requires '%s[%d]' to be a valid string",
                field_name,
                field_name,
                index
            )
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
    if dir_attr and dir_attr.mode == "directory" then
        return rules_dir .. "/99-loongshield-seharden.rules"
    end

    local fallback_path = params and params.fallback_rules_path or _dependencies.fallback_rules_path
    if not is_safe_path(fallback_path) then
        return nil, "audit enforcer requires a safe fallback audit rules path"
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

    local line = string.format("-w %s -p %s", params.path, permissions)
    if params.key then
        line = line .. string.format(" -k %s", params.key)
    end

    return fsutil.append_unique_line(rule_file, line, "audit.ensure_watch_rule", _dependencies)
end

function M.ensure_syscall_rule(params)
    if not params then
        return nil, "audit.ensure_syscall_rule: requires parameters"
    end

    local syscalls, syscall_err = normalize_string_list(params.syscalls, "syscalls", "^[%w_]+$")
    if not syscalls then
        return nil, syscall_err:gsub("audit%.syscalls", "audit.ensure_syscall_rule")
    end

    local arches = params.arches or params.required_arches or (params.arch and { params.arch })
    local normalized_arches, arch_err = normalize_string_list(arches, "arches", "^[%w_]+$")
    if not normalized_arches then
        return nil, arch_err:gsub("audit%.arches", "audit.ensure_syscall_rule")
    end

    local auid_min = tonumber(params.auid_min)
    if not auid_min or auid_min < 0 or auid_min ~= math.floor(auid_min) then
        return nil, "audit.ensure_syscall_rule: requires a non-negative integer 'auid_min'"
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
        syscall_fragment[#syscall_fragment + 1] = "-S " .. syscall
    end

    for _, arch in ipairs(normalized_arches) do
        local line = string.format(
            "-a always,exit -F arch=%s %s -F auid>=%d -F auid!=unset",
            arch,
            table.concat(syscall_fragment, " "),
            auid_min
        )
        if params.key then
            line = line .. string.format(" -k %s", params.key)
        end

        local ok, err = fsutil.append_unique_line(rule_file, line,
            "audit.ensure_syscall_rule", _dependencies)
        if not ok then
            return nil, err
        end
    end

    return true
end

return M
