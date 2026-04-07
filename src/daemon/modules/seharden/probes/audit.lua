local lfs = require('lfs')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
    audit_rules_path = "/etc/audit/audit.rules",
    audit_rules_d_path = "/etc/audit/rules.d",
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function normalize_path(path)
    if path == "/" then
        return path
    end

    local normalized = tostring(path):gsub("/+$", "")
    if normalized == "" then
        return "/"
    end
    return normalized
end

local function list_rule_files()
    local files = {}
    local audit_rules_attr = _dependencies.lfs_attributes(_dependencies.audit_rules_path)
    if audit_rules_attr and audit_rules_attr.mode == "file" then
        files[#files + 1] = _dependencies.audit_rules_path
    end

    local rules_d_attr = _dependencies.lfs_attributes(_dependencies.audit_rules_d_path)
    if rules_d_attr and rules_d_attr.mode == "directory" then
        for name in _dependencies.lfs_dir(_dependencies.audit_rules_d_path) do
            if name ~= "." and name ~= ".." and name:match("%.rules$") then
                local path = _dependencies.audit_rules_d_path .. "/" .. name
                local attr = _dependencies.lfs_attributes(path)
                if attr and attr.mode == "file" then
                    files[#files + 1] = path
                end
            end
        end
    end

    table.sort(files)
    return files
end

local function load_rule_lines()
    local lines = {}

    for _, path in ipairs(list_rule_files()) do
        local file, err = _dependencies.io_open(path, "r")
        if not file then
            return nil, string.format("Could not open file '%s': %s", path, tostring(err))
        end

        for line in file:lines() do
            local trimmed = line:match("^%s*(.-)%s*$")
            if trimmed ~= "" and not trimmed:match("^#") then
                lines[#lines + 1] = trimmed
            end
        end

        file:close()
    end

    return lines
end

local function line_has_key(line)
    return line:match("%-k%s+%S+") ~= nil or line:match("%-F%s+key=%S+") ~= nil
end

local function has_required_permissions(actual, required)
    local present = {}

    for permission in tostring(actual):gmatch(".") do
        if permission:match("[rwax]") then
            present[permission] = true
        end
    end

    for permission in tostring(required):gmatch(".") do
        if permission:match("[rwax]") and not present[permission] then
            return false
        end
    end

    return true
end

local function extract_watch_target(line)
    local watched_path = line:match("^%-w%s+(%S+)")
    if watched_path then
        return watched_path, "watch"
    end

    watched_path = line:match("%-F%s+path=(%S+)")
    if watched_path then
        return watched_path, "path"
    end

    watched_path = line:match("%-F%s+dir=(%S+)")
    if watched_path then
        return watched_path, "dir"
    end
end

local function extract_watch_permissions(line)
    return (line:match("%-p%s+([rwax]+)") or line:match("%-F%s+perm=([rwax]+)") or "")
end

local function is_always_exit_rule(line)
    return line:match("^%-a%s+always,exit%f[%s]") ~= nil
        or line:match("^%-a%s+exit,always%f[%s]") ~= nil
end

local function line_matches_auid_min(line, threshold)
    for raw_value in line:gmatch("%-F%s+auid>=(%d+)") do
        local numeric_value = tonumber(raw_value)
        if numeric_value and numeric_value <= threshold then
            return true
        end
    end

    return false
end

local function line_excludes_unset_auid(line)
    return line:match("%-F%s+auid!=unset") ~= nil
        or line:match("%-F%s+auid!=%-1") ~= nil
        or line:match("%-F%s+auid!=4294967295") ~= nil
end

local function collect_syscalls(line)
    local syscalls = {}

    for token in line:gmatch("%-S%s+([^%s]+)") do
        for syscall in token:gmatch("([^,]+)") do
            if syscall ~= "" then
                syscalls[syscall] = true
            end
        end
    end

    return syscalls
end

local function extract_syscall_arch(line)
    return line:match("%-F%s+arch=(%S+)")
end

local function normalize_required_arches(required_arches)
    if required_arches == nil then
        return nil
    end

    if type(required_arches) ~= "table" or #required_arches == 0 then
        return nil, "Probe 'audit.find_syscall_rule' requires 'required_arches' to be a non-empty list when provided."
    end

    local normalized = {}
    local seen = {}

    for index, arch in ipairs(required_arches) do
        if type(arch) ~= "string" or arch == "" then
            return nil, string.format(
                "Probe 'audit.find_syscall_rule' requires non-empty strings in required_arches[%d].",
                index
            )
        end

        if not seen[arch] then
            normalized[#normalized + 1] = arch
            seen[arch] = true
        end
    end

    return normalized
end

local function is_same_or_descendant_path(path, parent_path)
    if path == parent_path then
        return true
    end

    if parent_path == "/" then
        return true
    end

    return path:sub(1, #parent_path) == parent_path
        and path:sub(#parent_path + 1, #parent_path + 1) == "/"
end

local function watch_target_is_directory(watch_kind, watched_path)
    if watch_kind == "dir" then
        return true
    end

    if watch_kind ~= "watch" then
        return false
    end

    local attr = _dependencies.lfs_attributes(watched_path)
    return attr and attr.mode == "directory"
end

function M.find_watch_rule(params)
    if not params or type(params.path) ~= "string" or params.path == "" then
        return nil, "Probe 'audit.find_watch_rule' requires a non-empty 'path' parameter."
    end
    if type(params.permissions) ~= "string" or params.permissions == "" then
        return nil, "Probe 'audit.find_watch_rule' requires a non-empty 'permissions' parameter."
    end

    local lines, err = load_rule_lines()
    if not lines then
        return nil, err
    end

    local target_path = normalize_path(params.path)
    local require_key = params.require_key ~= false

    for _, line in ipairs(lines) do
        local watched_path, watch_kind = extract_watch_target(line)
        local is_watch_rule = line:match("^%-w%s+") ~= nil
            or (is_always_exit_rule(line) and watched_path ~= nil)

        if is_watch_rule and watched_path then
            local normalized_watched_path = normalize_path(watched_path)
            local path_matches = normalized_watched_path == target_path

            if not path_matches and watch_target_is_directory(watch_kind, watched_path) then
                path_matches = is_same_or_descendant_path(target_path, normalized_watched_path)
            end

            if not path_matches then
                goto continue
            end

            local permissions = extract_watch_permissions(line)
            if has_required_permissions(permissions, params.permissions)
                and (not require_key or line_has_key(line)) then
                return {
                    found = true,
                    details = {
                        path = watched_path,
                        permissions = permissions,
                        line = line
                    }
                }
            end
        end

        ::continue::
    end

    return { found = false }
end

function M.find_syscall_rule(params)
    if not params or type(params.syscalls) ~= "table" or #params.syscalls == 0 then
        return nil, "Probe 'audit.find_syscall_rule' requires a non-empty 'syscalls' list."
    end

    local auid_min = tonumber(params.auid_min) or 1000
    if auid_min < 0 then
        return nil, "Probe 'audit.find_syscall_rule' requires a non-negative 'auid_min' parameter."
    end

    local lines, err = load_rule_lines()
    if not lines then
        return nil, err
    end

    local required_syscalls = {}
    local global_syscalls = {}
    local syscalls_by_arch = {}
    local require_auid_unset_exclusion = params.require_auid_unset_exclusion ~= false
    local required_arches, arch_err = normalize_required_arches(params.required_arches)

    if arch_err then
        return nil, arch_err
    end

    for _, syscall in ipairs(params.syscalls) do
        required_syscalls[syscall] = true
    end

    for _, line in ipairs(lines) do
        if is_always_exit_rule(line)
            and line_matches_auid_min(line, auid_min)
            and (not require_auid_unset_exclusion or line_excludes_unset_auid(line)) then
            local line_syscalls = collect_syscalls(line)
            local arch = extract_syscall_arch(line)
            local seen_syscalls = global_syscalls

            if arch then
                seen_syscalls = syscalls_by_arch[arch]
                if seen_syscalls == nil then
                    seen_syscalls = {}
                    syscalls_by_arch[arch] = seen_syscalls
                end
            end

            for syscall in pairs(required_syscalls) do
                if line_syscalls[syscall] then
                    seen_syscalls[syscall] = true
                end
            end
        end
    end

    local active_arches = {}
    for arch in pairs(syscalls_by_arch) do
        active_arches[#active_arches + 1] = arch
    end
    table.sort(active_arches)

    local missing = {}
    local missing_set = {}

    if required_arches then
        local allow_global_fallback = #required_arches == 1 and #active_arches == 0

        for _, arch in ipairs(required_arches) do
            local arch_syscalls = syscalls_by_arch[arch]
            if arch_syscalls == nil and allow_global_fallback then
                arch_syscalls = global_syscalls
            end

            for _, syscall in ipairs(params.syscalls) do
                if not arch_syscalls or not arch_syscalls[syscall] then
                    missing_set[syscall] = true
                end
            end
        end
    elseif #active_arches == 0 then
        for _, syscall in ipairs(params.syscalls) do
            if not global_syscalls[syscall] then
                missing_set[syscall] = true
            end
        end
    else
        for _, arch in ipairs(active_arches) do
            local arch_syscalls = syscalls_by_arch[arch]
            for _, syscall in ipairs(params.syscalls) do
                if not global_syscalls[syscall] and not arch_syscalls[syscall] then
                    missing_set[syscall] = true
                end
            end
        end
    end

    for _, syscall in ipairs(params.syscalls) do
        if missing_set[syscall] then
            missing[#missing + 1] = syscall
        end
    end

    table.sort(missing)

    return {
        count = #missing,
        details = missing
    }
end

return M
