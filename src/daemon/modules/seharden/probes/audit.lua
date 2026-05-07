local lfs = require('lfs')
local text = require('seharden.shared.text')
local user_defaults = require('seharden.shared.user_defaults')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    io_popen = io.popen,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
    audit_rules_path = "/etc/audit/audit.rules",
    audit_rules_d_path = "/etc/audit/rules.d",
    login_defs_path = "/etc/login.defs",
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

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

local function list_rules_d_files()
    local files = {}
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

local function add_active_line(lines, line)
    local trimmed = text.trim(line)
    if trimmed ~= "" and not trimmed:match("^#") then
        lines[#lines + 1] = trimmed
    end
end

local function load_lines_from_files(files)
    local lines = {}

    for _, path in ipairs(files) do
        local file, err = _dependencies.io_open(path, "r")
        if not file then
            return nil, string.format("Could not open file '%s': %s", path, tostring(err))
        end

        for line in file:lines() do
            add_active_line(lines, line)
        end

        file:close()
    end

    return lines
end

local function load_rule_lines()
    return load_lines_from_files(list_rule_files())
end

local function load_persistent_rule_lines()
    local files = list_rules_d_files()
    if #files == 0 then
        return {}, false, nil
    end

    local lines, err = load_lines_from_files(files)
    if not lines then
        return nil, false, err
    end
    return lines, true, nil
end

local function normalize_popen_close(ok, _, code)
    if ok == true then
        return true
    end
    if type(code) == "number" then
        return code == 0
    end
    if type(ok) == "number" then
        return ok == 0
    end
    if ok == nil and code == nil then
        return true
    end
    return false
end

local function load_loaded_rule_lines()
    local handle = _dependencies.io_popen("auditctl -l 2>/dev/null", "r")
    if not handle then
        return {}, false, "Could not execute auditctl -l."
    end

    local lines = {}
    for line in handle:lines() do
        add_active_line(lines, line)
    end

    local ok, status_type, code = handle:close()
    if not normalize_popen_close(ok, status_type, code) then
        return {}, false, "auditctl -l did not complete successfully."
    end

    return lines, true, nil
end

local function load_source_lines(source)
    if source == "persistent" then
        return load_persistent_rule_lines()
    end
    if source == "loaded" then
        return load_loaded_rule_lines()
    end
    if source == "all" then
        local lines, err = load_rule_lines()
        return lines, lines ~= nil, err
    end
    return nil, false, "Unknown audit rule source: " .. tostring(source)
end

local function normalize_sources(params)
    local sources = params and params.sources or nil
    if sources == nil then
        return { "persistent", "loaded" }
    end
    if type(sources) ~= "table" or #sources == 0 then
        return nil, "Audit rule sources must be a non-empty list."
    end
    return sources
end

local function read_uid_min(params)
    if params and params.auid_min == false then
        return nil
    end
    if params and params.auid_min ~= nil then
        return tonumber(params.auid_min)
    end
    return user_defaults.read_uid_min(_dependencies.io_open, _dependencies.login_defs_path)
end

local function line_has_key(line)
    return line:match("%-k%s+%S+") ~= nil or line:match("%-F%s+key=%S+") ~= nil
end

local function extract_key(line)
    return line:match("%-k%s+(%S+)") or line:match("%-F%s+key=(%S+)")
end

local function line_key_matches(line, key, require_key)
    if require_key == false then
        return true
    end
    if key == nil then
        return line_has_key(line)
    end
    return extract_key(line) == key
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

local function line_has_exit(line, expected_exit)
    if expected_exit == nil then
        return true
    end

    local normalized_expected = tostring(expected_exit):gsub("^%-", "")
    for value in line:gmatch("%-F%s+exit=([^%s]+)") do
        if value:gsub("^%-", "") == normalized_expected then
            return true
        end
    end
    return false
end

local function line_has_field(line, field)
    if type(field) ~= "table" or not field.name then
        return true
    end

    for value in line:gmatch("%-F%s+" .. tostring(field.name) .. "=([^%s]+)") do
        if field.value == nil or tostring(value) == tostring(field.value) then
            return true
        end
    end
    return false
end

local function line_has_fields(line, fields)
    for _, field in ipairs(fields or {}) do
        if not line_has_field(line, field) then
            return false
        end
    end
    return true
end

local function normalize_comparison(value)
    value = tostring(value or "")
    if value == "uid!=euid" or value == "euid!=uid" then
        return "uid!=euid"
    end
    return value
end

local function line_has_comparison(line, expected)
    if expected == nil then
        return true
    end

    local normalized_expected = normalize_comparison(expected)
    for value in line:gmatch("%-C%s+([^%s]+)") do
        if normalize_comparison(value) == normalized_expected then
            return true
        end
    end
    return false
end

local function line_has_any_comparison(line, comparisons)
    if comparisons == nil or #comparisons == 0 then
        return true
    end
    for _, comparison in ipairs(comparisons) do
        if line_has_comparison(line, comparison) then
            return true
        end
    end
    return false
end

local function line_matches_auid_filters(line, auid_min, require_unset_exclusion)
    if auid_min ~= nil and not line_matches_auid_min(line, auid_min) then
        return false
    end
    if require_unset_exclusion ~= false and not line_excludes_unset_auid(line) then
        return false
    end
    return true
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

local function find_watch_rule_in_lines(lines, params)
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

            if path_matches then
                local permissions = extract_watch_permissions(line)
                if has_required_permissions(permissions, params.permissions)
                    and line_key_matches(line, params.key, require_key) then
                    return {
                        found = true,
                        details = {
                            path = watched_path,
                            permissions = permissions,
                            key = extract_key(line),
                            line = line
                        }
                    }
                end
            end
        end
    end

    return { found = false }
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

    return find_watch_rule_in_lines(lines, params)
end

local function normalize_exit_requirements(exits)
    if exits == nil then
        return {
            { key = "*", value = nil },
        }
    end
    if type(exits) ~= "table" or #exits == 0 then
        return nil, "Probe 'audit.find_syscall_rule' requires 'exits' to be a non-empty list when provided."
    end

    local normalized = {}
    local seen = {}
    for _, value in ipairs(exits) do
        local key = tostring(value)
        if not seen[key] then
            normalized[#normalized + 1] = {
                key = key,
                value = value,
            }
            seen[key] = true
        end
    end
    return normalized
end

local function get_syscall_bucket(buckets, arch, exit_key)
    local arch_key = arch or "*"
    if buckets[arch_key] == nil then
        buckets[arch_key] = {}
    end
    if buckets[arch_key][exit_key] == nil then
        buckets[arch_key][exit_key] = {}
    end
    return buckets[arch_key][exit_key]
end

local function line_matches_syscall_filters(line, params, auid_min, exit_value)
    local require_auid_unset_exclusion = params.require_auid_unset_exclusion ~= false

    return is_always_exit_rule(line)
        and line_matches_auid_filters(line, auid_min, require_auid_unset_exclusion)
        and line_has_exit(line, exit_value)
        and line_has_fields(line, params.fields)
        and line_has_any_comparison(line, params.comparisons_any)
        and line_key_matches(line, params.key, params.require_key ~= false)
end

local function find_syscall_rule_in_lines(lines, params, auid_min)
    local required_syscalls = {}
    local buckets = {}
    local required_arches, arch_err = normalize_required_arches(params.required_arches)
    local required_exits, exit_err = normalize_exit_requirements(params.exits)

    if arch_err then
        return nil, arch_err
    end
    if exit_err then
        return nil, exit_err
    end

    for _, syscall in ipairs(params.syscalls) do
        required_syscalls[syscall] = true
    end

    for _, line in ipairs(lines) do
        for _, exit_requirement in ipairs(required_exits) do
            if line_matches_syscall_filters(line, params, auid_min, exit_requirement.value) then
                local line_syscalls = collect_syscalls(line)
                local bucket = get_syscall_bucket(buckets, extract_syscall_arch(line), exit_requirement.key)
                for syscall in pairs(required_syscalls) do
                    if line_syscalls[syscall] then
                        bucket[syscall] = true
                    end
                end
            end
        end
    end

    local active_arches = {}
    for arch in pairs(buckets) do
        if arch ~= "*" then
            active_arches[#active_arches + 1] = arch
        end
    end
    table.sort(active_arches)

    local missing_set = {}

    local function require_syscalls_for_bucket(bucket)
        for _, syscall in ipairs(params.syscalls) do
            if not bucket or not bucket[syscall] then
                missing_set[syscall] = true
            end
        end
    end

    if required_arches then
        local allow_global_fallback = #required_arches == 1 and #active_arches == 0

        for _, arch in ipairs(required_arches) do
            for _, exit_requirement in ipairs(required_exits) do
                local bucket = buckets[arch] and buckets[arch][exit_requirement.key]
                if bucket == nil and allow_global_fallback then
                    bucket = buckets["*"] and buckets["*"][exit_requirement.key]
                end
                require_syscalls_for_bucket(bucket)
            end
        end
    elseif #active_arches == 0 then
        for _, exit_requirement in ipairs(required_exits) do
            require_syscalls_for_bucket(buckets["*"] and buckets["*"][exit_requirement.key])
        end
    else
        for _, arch in ipairs(active_arches) do
            for _, exit_requirement in ipairs(required_exits) do
                local bucket = buckets[arch] and buckets[arch][exit_requirement.key]
                local global_bucket = buckets["*"] and buckets["*"][exit_requirement.key]
                for _, syscall in ipairs(params.syscalls) do
                    if not (global_bucket and global_bucket[syscall])
                        and not (bucket and bucket[syscall]) then
                        missing_set[syscall] = true
                    end
                end
            end
        end
    end

    local missing = {}
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

local function find_path_exec_rule_in_lines(lines, params, auid_min)
    local target_path = normalize_path(params.path)
    local require_key = params.require_key ~= false
    local require_auid_unset_exclusion = params.require_auid_unset_exclusion ~= false

    for _, line in ipairs(lines) do
        local watched_path = extract_watch_target(line)
        if is_always_exit_rule(line)
            and watched_path
            and normalize_path(watched_path) == target_path
            and has_required_permissions(extract_watch_permissions(line), params.permissions or "x")
            and line_matches_auid_filters(line, auid_min, require_auid_unset_exclusion)
            and line_key_matches(line, params.key, require_key) then
            return {
                found = true,
                details = {
                    path = watched_path,
                    permissions = extract_watch_permissions(line),
                    key = extract_key(line),
                    line = line,
                },
            }
        end
    end

    return { found = false }
end

local function directive_name_matches(line, name)
    if name == "-c" then
        return line:match("^%-c%f[%s]") ~= nil
    end
    if name == "-e" then
        return line:match("^%-e%s+") ~= nil
    end
    return false
end

local function directive_value(line, name)
    if name == "-c" then
        return nil
    end
    if name == "-e" then
        return line:match("^%-e%s+(%S+)")
    end
    return nil
end

local function find_directive_in_lines(lines, params)
    local directive = params.directive or params.name
    local last
    for _, line in ipairs(lines) do
        if directive_name_matches(line, directive) then
            last = {
                line = line,
                value = directive_value(line, directive),
            }
        end
    end

    if not last then
        return { found = false }
    end

    local value_matches = params.value == nil or tostring(last.value) == tostring(params.value)
    return {
        found = value_matches,
        details = last,
    }
end

local function merge_requirement_params(defaults, requirement)
    local merged = {}
    for key, value in pairs(defaults or {}) do
        merged[key] = value
    end
    for key, value in pairs(requirement or {}) do
        merged[key] = value
    end
    return merged
end

local function auid_min_for_requirement(requirement, default_auid_min)
    if requirement.auid_min == false then
        return nil
    end
    if requirement.auid_min ~= nil then
        return tonumber(requirement.auid_min)
    end
    return default_auid_min
end

local function evaluate_requirement(lines, requirement, defaults, default_auid_min)
    local params = merge_requirement_params(defaults, requirement)
    local kind = requirement.type

    if kind == "watch" then
        if type(params.path) ~= "string" or type(params.permissions) ~= "string" then
            return nil, "Audit watch requirements need path and permissions."
        end
        return find_watch_rule_in_lines(lines, params)
    end

    if kind == "syscall" then
        if type(params.syscalls) ~= "table" or #params.syscalls == 0 then
            return nil, "Audit syscall requirements need a non-empty syscalls list."
        end
        return find_syscall_rule_in_lines(lines, params, auid_min_for_requirement(requirement, default_auid_min))
    end

    if kind == "path_exec" then
        if type(params.path) ~= "string" then
            return nil, "Audit path_exec requirements need path."
        end
        return find_path_exec_rule_in_lines(lines, params, auid_min_for_requirement(requirement, default_auid_min))
    end

    if kind == "directive" then
        if type(params.directive or params.name) ~= "string" then
            return nil, "Audit directive requirements need directive."
        end
        return find_directive_in_lines(lines, params)
    end

    return nil, "Unknown audit rule requirement type: " .. tostring(kind)
end

function M.inspect_rule_coverage(params)
    params = params or {}
    if type(params.requirements) ~= "table" or #params.requirements == 0 then
        return nil, "Probe 'audit.inspect_rule_coverage' requires a non-empty 'requirements' list."
    end

    local sources, source_err = normalize_sources(params)
    if not sources then
        return nil, source_err
    end

    local default_auid_min = read_uid_min(params)
    if default_auid_min ~= nil and default_auid_min < 0 then
        return nil, "Probe 'audit.inspect_rule_coverage' requires a non-negative 'auid_min' parameter."
    end

    local defaults = {
        required_arches = params.required_arches,
        require_key = params.require_key,
        require_auid_unset_exclusion = params.require_auid_unset_exclusion,
    }
    local source_lines = {}
    local source_available = {}
    local source_errors = {}
    local available = true

    for _, source in ipairs(sources) do
        local lines, source_ok, err = load_source_lines(source)
        source_lines[source] = lines or {}
        source_available[source] = source_ok == true
        source_errors[source] = err
        if source_ok ~= true then
            available = false
        end
    end

    local details = {}
    local violation_count = 0

    for index, requirement in ipairs(params.requirements) do
        local requirement_ok = true
        local source_details = {}

        for _, source in ipairs(sources) do
            if not source_available[source] then
                requirement_ok = false
                source_details[source] = {
                    available = false,
                    found = false,
                    error = source_errors[source],
                }
            else
                local result, err = evaluate_requirement(source_lines[source], requirement, defaults, default_auid_min)
                if not result then
                    return nil, err
                end
                local found = result.found == true or result.count == 0
                source_details[source] = result
                source_details[source].available = true
                source_details[source].found = found
                if not found then
                    requirement_ok = false
                end
            end
        end

        details[#details + 1] = {
            name = requirement.name or ("requirement_" .. tostring(index)),
            type = requirement.type,
            configured = requirement_ok,
            sources = source_details,
        }

        if not requirement_ok then
            violation_count = violation_count + 1
        end
    end

    return {
        available = available,
        checked_source_count = #sources,
        checked_requirement_count = #params.requirements,
        violation_count = violation_count,
        all_configured = available and violation_count == 0,
        details = details,
    }
end

local function run_lines(command)
    local handle = _dependencies.io_popen(command, "r")
    if not handle then
        return nil, "Could not execute command: " .. command
    end

    local lines = {}
    for line in handle:lines() do
        local trimmed = text.trim(line)
        if trimmed ~= "" then
            lines[#lines + 1] = trimmed
        end
    end

    local ok, status_type, code = handle:close()
    if not normalize_popen_close(ok, status_type, code) then
        return nil, "Command did not complete successfully: " .. command
    end
    return lines
end

local function collect_privileged_paths_from_system()
    local mounts, mount_err = run_lines(
        "findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) " ..
        "| grep -Pv 'noexec|nosuid' | awk '{print $1}' 2>/dev/null")
    if not mounts then
        return nil, mount_err
    end

    local paths = {}
    local seen = {}
    for _, mount in ipairs(mounts) do
        local found, find_err = run_lines("find " .. shell_escape(mount) .. " -xdev -perm /6000 -type f 2>/dev/null")
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

function M.inspect_privileged_command_coverage(params)
    params = params or {}
    local paths = params.paths

    if paths == nil then
        local collected, collect_err = collect_privileged_paths_from_system()
        if not collected then
            return {
                available = false,
                error = collect_err,
                checked_source_count = 0,
                checked_requirement_count = 0,
                violation_count = 0,
                all_configured = false,
                details = {},
            }
        end
        paths = collected
    end

    if type(paths) ~= "table" then
        return nil, "Probe 'audit.inspect_privileged_command_coverage' requires 'paths' to be a list when provided."
    end

    if #paths == 0 then
        return {
            available = true,
            checked_source_count = 0,
            checked_requirement_count = 0,
            violation_count = 0,
            all_configured = true,
            details = {},
        }
    end

    local requirements = {}
    for _, path in ipairs(paths) do
        requirements[#requirements + 1] = {
            name = path,
            type = "path_exec",
            path = path,
            key = params.key or "privileged",
        }
    end

    return M.inspect_rule_coverage({
        sources = params.sources,
        auid_min = params.auid_min,
        requirements = requirements,
    })
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

    return find_syscall_rule_in_lines(lines, params, auid_min)
end

return M
