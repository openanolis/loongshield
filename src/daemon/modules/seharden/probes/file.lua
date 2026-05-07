local log = require('runtime.log')
local config_paths = require('seharden.shared.config_paths')
local comparators = require('seharden.comparators')
local fs = require('fs')
local key_value_file = require('seharden.shared.key_value_file')
local lfs = require('lfs')
local path_list = require('seharden.shared.path_list')
local text = require('seharden.shared.text')
local M = {}

local _default_dependencies = {
    fs_stat = fs.stat,
    io_open = io.open,
    os_execute = os.execute,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
    path_list._test_set_dependencies({
        lfs_attributes = _dependencies.lfs_attributes,
        lfs_dir = _dependencies.lfs_dir,
    })
    config_paths._test_set_dependencies({
        lfs_attributes = _dependencies.lfs_attributes,
        lfs_dir = _dependencies.lfs_dir,
    })
end

M._test_set_dependencies()

local function expand_paths(paths_table)
    return path_list.expand_files(paths_table)
end

local function normalize_execute_exit_code(ok, _, code)
    if ok == true then
        return 0
    end
    if type(code) == "number" then
        return code
    end
    if type(ok) == "number" then
        if ok > 0 and ok % 256 == 0 then
            return ok / 256
        end
        return ok
    end
    return nil
end

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function lua_pattern_to_ere(pattern)
    local map = {
        s = "[[:space:]]",
        S = "[^[:space:]]",
        d = "[0-9]",
        D = "[^0-9]",
        w = "[[:alnum:]_]",
        W = "[^[:alnum:]_]",
        a = "[[:alpha:]]",
        A = "[^[:alpha:]]",
        l = "[[:lower:]]",
        u = "[[:upper:]]",
        p = "[[:punct:]]"
    }

    local out = {}
    local i = 1
    while i <= #pattern do
        local c = pattern:sub(i, i)
        if c == "%" then
            local n = pattern:sub(i + 1, i + 1)
            if n == "" then
                out[#out + 1] = "%"
            elseif n == "%" then
                out[#out + 1] = "%"
                i = i + 1
            else
                out[#out + 1] = map[n] or ("\\" .. n)
                i = i + 1
            end
        else
            out[#out + 1] = c
        end
        i = i + 1
    end
    return table.concat(out)
end

local function parse_pattern_options(pattern)
    if pattern:sub(1, 4) == "(?i)" then
        return pattern:sub(5), true
    end
    return pattern, false
end

local function grep_match(path, pattern, is_case_insensitive)
    local flags = is_case_insensitive and "-i" or ""
    local cmd = string.format("grep -E -q %s -- %s %s 2>/dev/null",
        flags,
        shell_escape(lua_pattern_to_ere(pattern)),
        shell_escape(path))
    local ok, status_type, code = _dependencies.os_execute(cmd)
    local exit_code = normalize_execute_exit_code(ok, status_type, code)
    if exit_code == 0 then
        return true
    end
    if exit_code == 1 then
        return false
    end
    if exit_code == 2 then
        local err = string.format("grep -E failed for file '%s' with pattern '%s'",
            path, pattern)
        log.warn("%s", err)
        return nil, err
    end

    local err = string.format("grep -E exited unexpectedly for file '%s' with code: %s",
        path, tostring(exit_code))
    log.warn("%s", err)
    return nil, err
end

local function lua_pattern_match(path, pattern, is_case_insensitive)
    local pattern_to_match = is_case_insensitive and pattern:lower() or pattern
    local file, err = _dependencies.io_open(path, "r")
    if not file then
        log.warn("Could not open file '%s' while matching pattern: %s",
            path, tostring(err))
        return nil, string.format("Could not open file '%s': %s",
            path, tostring(err))
    end

    for line in file:lines() do
        local line_to_check = is_case_insensitive and line:lower() or line
        if line_to_check:match(pattern_to_match) then
            file:close()
            return true
        end
    end
    file:close()
    return false
end

local function parse_key_value_file(path, opts, allow_missing)
    local file, err = _dependencies.io_open(path, "r")

    if not file then
        if allow_missing and _dependencies.lfs_attributes(path) == nil then
            return {}
        end
        log.warn("Could not open file for parsing '%s': %s", path, tostring(err))
        return nil, string.format("Could not open file '%s': %s", path, tostring(err))
    end

    local config_values = key_value_file.parse_handle(file, opts)
    file:close()
    return config_values
end

local function normalize_value(value, mode)
    if value == nil then
        return nil
    end
    value = tostring(value)
    if mode == "lower" then
        value = value:lower()
    end
    return value
end

local function build_allowed_set(values, normalize_mode)
    local allowed = {}
    for _, value in ipairs(values or {}) do
        allowed[normalize_value(value, normalize_mode)] = true
    end
    return allowed
end

local function unquote_value(value)
    value = tostring(value or "")
    local first = value:sub(1, 1)
    local last = value:sub(-1)
    if #value >= 2 and ((first == '"' and last == '"') or (first == "'" and last == "'")) then
        return value:sub(2, -2)
    end
    return value
end

local function key_value_matches(value, params)
    local normalized = normalize_value(value, params.normalize_values)

    if params.expected_value ~= nil and
        normalized ~= normalize_value(params.expected_value, params.normalize_values) then
        return false
    end

    if params.require_non_empty_value and text.trim(unquote_value(normalized)) == "" then
        return false
    end

    if params.value_pattern and not normalized:match(params.value_pattern) then
        return false
    end

    if params.numeric_min ~= nil or params.numeric_max ~= nil then
        local numeric_value = tonumber(tostring(normalized):match("(-?%d+)%s*$"))
        if numeric_value == nil then
            return false
        end
        if params.numeric_min ~= nil and numeric_value < tonumber(params.numeric_min) then
            return false
        end
        if params.numeric_max ~= nil and numeric_value > tonumber(params.numeric_max) then
            return false
        end
    end

    return true
end

local function basename(path)
    return tostring(path):match("([^/]+)$") or tostring(path)
end

local function sorted_dir_entries(path)
    local ok, iter, dir_obj = pcall(_dependencies.lfs_dir, path)
    if not ok then
        return nil, tostring(iter)
    end
    if not iter then
        return nil, tostring(dir_obj or "directory unavailable")
    end

    local entries = {}
    for name in iter, dir_obj do
        if name ~= "." and name ~= ".." then
            entries[#entries + 1] = name
        end
    end
    table.sort(entries)
    return entries
end

local function collect_bootloader_config_paths(base_path, out)
    local attr = _dependencies.lfs_attributes(base_path)
    if not attr then
        return true
    end
    if attr.mode == "file" then
        local name = basename(base_path)
        if name == "user.cfg" or name:match("^grub") then
            out[#out + 1] = base_path
        end
        return true
    end
    if attr.mode ~= "directory" then
        return true
    end

    local entries, err = sorted_dir_entries(base_path)
    if not entries then
        return nil, err
    end

    for _, entry in ipairs(entries) do
        local ok, child_err = collect_bootloader_config_paths(base_path .. "/" .. entry, out)
        if not ok then
            return nil, child_err
        end
    end
    return true
end

local function bootloader_expected_mode(path)
    if tostring(path):match("^/boot/efi/EFI/") then
        return tonumber("700", 8)
    end
    return tonumber("600", 8)
end

local function bootloader_access_ok(access)
    return access.exists == true
        and access.uid == 0
        and access.gid == 0
        and comparators.mode_is_no_more_permissive(access.mode, access.expected_mode)
end

local function parse_file_into(values, path, params)
    local parsed, parse_err = parse_key_value_file(path, {
        normalize_values = params.normalize_values,
        section = params.section,
    }, false)
    if not parsed then
        return nil, parse_err
    end
    for key, value in pairs(parsed) do
        values[key] = value
    end
    return true
end

local function make_key_value_detail(path, entry)
    return {
        path = path,
        section = entry.section,
        key = entry.key,
        value = entry.value,
    }
end

function M.find_pattern(params)
    if not params or not params.paths or not params.pattern then
        return nil, "Probe 'find_pattern' requires 'paths' and 'pattern' parameters."
    end

    local pattern_to_match, is_case_insensitive = parse_pattern_options(params.pattern)

    local files_to_check = expand_paths(params.paths)
    if #files_to_check == 0 then
        return {
            found = false,
            checked_count = 0,
        }
    end

    local use_grep = pattern_to_match:find("|", 1, true) ~= nil

    for _, file_path in ipairs(files_to_check) do
        local matched, err
        if use_grep then
            matched, err = grep_match(file_path, pattern_to_match, is_case_insensitive)
        else
            matched, err = lua_pattern_match(file_path, pattern_to_match, is_case_insensitive)
        end
        if err then
            return nil, err
        end
        if matched then
            return {
                found = true,
                checked_count = #files_to_check,
            }
        end
    end
    return {
        found = false,
        checked_count = #files_to_check,
    }
end

function M.parse_key_values(params)
    if not params or not params.path then
        return nil, "Probe 'file.parse_key_values' requires a 'path' parameter."
    end

    return parse_key_value_file(params.path, {
        normalize_values = params.normalize_values,
        section = params.section,
    }, params.allow_missing)
end

function M.find_key_value_outside_allowed(params)
    if not params or not params.paths or not params.key or not params.allowed_values then
        return nil, "Probe 'file.find_key_value_outside_allowed' requires 'paths', 'key', and 'allowed_values' parameters."
    end

    local files_to_check = expand_paths(params.paths)
    local allowed = build_allowed_set(params.allowed_values, params.normalize_values)
    local details = {}

    for _, file_path in ipairs(files_to_check) do
        local file, err = _dependencies.io_open(file_path, "r")
        if not file then
            log.warn("Could not open file '%s' while checking key values: %s",
                file_path, tostring(err))
            return nil, string.format("Could not open file '%s': %s", file_path, tostring(err))
        end

        for _, entry in ipairs(key_value_file.parse_entries(file)) do
            if entry.key == params.key then
                if not allowed[normalize_value(entry.value, params.normalize_values)] then
                    details[#details + 1] = {
                        path = file_path,
                        key = entry.key,
                        value = entry.value,
                    }
                end
            end
        end
        file:close()
    end

    return {
        found = #details > 0,
        count = #details,
        details = details,
    }
end

function M.find_key_value(params)
    if not params or not params.paths or not params.key then
        return nil, "Probe 'file.find_key_value' requires 'paths' and 'key' parameters."
    end

    local files_to_check = expand_paths(params.paths)
    local details = {}

    for _, file_path in ipairs(files_to_check) do
        local file, err = _dependencies.io_open(file_path, "r")
        if not file then
            log.warn("Could not open file '%s' while checking key values: %s",
                file_path, tostring(err))
            return nil, string.format("Could not open file '%s': %s", file_path, tostring(err))
        end

        for _, entry in ipairs(key_value_file.parse_entries(file, {
            normalize_values = params.normalize_values,
            section = params.section,
        })) do
            if entry.key == params.key and key_value_matches(entry.value, params) then
                details[#details + 1] = make_key_value_detail(file_path, entry)
            end
        end
        file:close()
    end

    return {
        found = #details > 0,
        count = #details,
        details = details,
    }
end

function M.get_effective_key_value(params)
    if not params or not params.paths or not params.key then
        return nil, "Probe 'file.get_effective_key_value' requires 'paths' and 'key' parameters."
    end

    local files_to_check = expand_paths(params.paths)
    table.sort(files_to_check)

    local effective
    for _, file_path in ipairs(files_to_check) do
        local file, err = _dependencies.io_open(file_path, "r")
        if not file then
            log.warn("Could not open file '%s' while checking effective key values: %s",
                file_path, tostring(err))
            return nil, string.format("Could not open file '%s': %s", file_path, tostring(err))
        end

        for _, entry in ipairs(key_value_file.parse_entries(file, {
            normalize_values = params.normalize_values,
            section = params.section,
        })) do
            if entry.key == params.key then
                effective = make_key_value_detail(file_path, entry)
            end
        end
        file:close()
    end

    local matched = effective ~= nil and key_value_matches(effective.value, params) or false
    return {
        found = effective ~= nil,
        matched = matched,
        path = effective and effective.path or nil,
        section = effective and effective.section or nil,
        key = effective and effective.key or params.key,
        value = effective and effective.value or nil,
        details = effective and { effective } or {},
    }
end

function M.parse_systemd_key_values(params)
    if not params or not params.path then
        return nil, "Probe 'file.parse_systemd_key_values' requires a 'path' parameter."
    end

    if params.effective then
        local config_name = basename(params.path)
        local config_dirs = params.config_dirs or {
            "/etc/systemd",
            "/run/systemd",
            "/usr/local/lib/systemd",
            "/usr/lib/systemd",
            "/lib/systemd",
        }
        local values = {}
        local main_loaded = false

        local main_path = config_paths.first_existing_file(config_dirs, config_name)
        if main_path then
            local ok, parse_err = parse_file_into(values, main_path, params)
            if not ok then
                return nil, parse_err
            end
            main_loaded = true
        end

        if not main_loaded and not params.allow_missing then
            return nil, string.format("Could not open effective systemd configuration '%s'", params.path)
        end

        for _, path in ipairs(config_paths.sorted_unique_files(config_dirs, config_name .. ".d", "%.conf$")) do
            local ok, parse_err = parse_file_into(values, path, params)
            if not ok then
                return nil, parse_err
            end
        end

        return values
    end

    local values, err = parse_key_value_file(params.path, {
        normalize_values = params.normalize_values,
        section = params.section,
    }, params.allow_missing)
    if not values then
        return nil, err
    end

    local dropin_dirs = params.dropin_dirs
    if dropin_dirs == nil then
        dropin_dirs = { params.path .. ".d" }
    end

    for _, path in ipairs(config_paths.sorted_unique_files(dropin_dirs, nil, "%.conf$")) do
        local ok, parse_err = parse_file_into(values, path, params)
        if not ok then
            return nil, parse_err
        end
    end

    return values
end

function M.find_duplicate_values_in_field(params)
    if not params or not (params.path and params.field_index and params.key_name and params.value_index) then
        return nil, "Probe 'file.find_duplicate_values_in_field' requires 'path', 'field_index', 'key_name', and 'value_index'."
    end

    local delimiter = params.delimiter or ":"
    local match_key = params.match_key
    if match_key ~= nil then
        match_key = tostring(match_key)
    end
    local file, err = _dependencies.io_open(params.path, "r")
    if not file then
        log.warn("Could not open file '%s': %s", params.path, tostring(err))
        return nil, string.format("Could not open file '%s': %s", params.path, tostring(err))
    end

    local key_to_values = {}
    local safe_delimiter = delimiter:gsub("([%^$()%%.[]*+?-])", "%%%1")

    for line in file:lines() do
        if not line:match("^#") and line:match(".") then
            local parts = {}
            for part in (line .. delimiter):gmatch("(.-)" .. safe_delimiter) do
                table.insert(parts, part)
            end
            table.remove(parts)

            if #parts >= params.field_index and #parts >= params.value_index then
                local key = parts[params.field_index]
                local value = parts[params.value_index]

                if match_key == nil or key == match_key then
                    if not key_to_values[key] then key_to_values[key] = {} end
                    table.insert(key_to_values[key], value)
                end
            end
        end
    end
    file:close()

    local duplicates = {}
    for key, values in pairs(key_to_values) do
        if #values > 1 then
            local entry = { values = values }
            entry[params.key_name] = tonumber(key) or key
            table.insert(duplicates, entry)
        end
    end
    return { count = #duplicates, details = duplicates }
end

function M.list_paths(params)
    if not params or not params.paths then
        return nil, "Probe 'file.list_paths' requires a 'paths' parameter."
    end

    local expanded = expand_paths(params.paths)
    local details = {}

    for _, path in ipairs(expanded) do
        details[#details + 1] = { path = path }
    end

    return {
        count = #details,
        details = details
    }
end

function M.inspect_bootloader_config_access(params)
    params = params or {}
    local base_path = params.base_path or "/boot"
    local paths = {}
    local ok, err = collect_bootloader_config_paths(base_path, paths)
    if not ok then
        return {
            available = false,
            error = err,
            checked_count = 0,
            invalid_count = 0,
            all_configured = false,
            details = {},
        }
    end

    table.sort(paths)
    local details = {}
    local invalid_count = 0
    for _, path in ipairs(paths) do
        local attr = _dependencies.fs_stat(path)
        local expected_mode = bootloader_expected_mode(path)
        local access = {
            path = path,
            expected_mode = expected_mode,
            exists = attr ~= nil,
        }
        if attr then
            access.uid = attr:uid()
            access.gid = attr:gid()
            access.mode = attr:mode()
        end
        access.configured = bootloader_access_ok(access)
        details[#details + 1] = access
        if not access.configured then
            invalid_count = invalid_count + 1
        end
    end

    return {
        available = true,
        checked_count = #details,
        invalid_count = invalid_count,
        all_configured = #details > 0 and invalid_count == 0,
        details = details,
    }
end

return M
