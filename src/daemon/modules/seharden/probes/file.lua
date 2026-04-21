local log = require('runtime.log')
local key_value_file = require('seharden.key_value_file')
local lfs = require('lfs')
local path_list = require('seharden.path_list')
local M = {}

local _default_dependencies = {
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
end

M._test_set_dependencies()

local function expand_paths(paths_table)
    return path_list.expand_files(paths_table)
end

function M.find_pattern(params)
    if not params or not params.paths or not params.pattern then
        return nil, "Probe 'find_pattern' requires 'paths' and 'pattern' parameters."
    end

    local pattern_to_match = params.pattern
    local is_case_insensitive = false

    if pattern_to_match:sub(1, 4) == "(?i)" then
        is_case_insensitive = true
        pattern_to_match = pattern_to_match:sub(5)
    end

    local files_to_check = expand_paths(params.paths)
    if #files_to_check == 0 then
        return { found = false }
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

    local function grep_match(path)
        local flags = is_case_insensitive and "-i" or ""
        local cmd = string.format("grep -E -q %s -- %s %s 2>/dev/null",
            flags,
            shell_escape(lua_pattern_to_ere(pattern_to_match)),
            shell_escape(path))
        local ok, _, code = _dependencies.os_execute(cmd)
        if ok == true or code == 0 then
            return true
        end

        local exit_code = type(ok) == "number" and ok or code
        if exit_code == 1 then
            return false
        end
        if exit_code == 2 then
            local err = string.format("grep -E failed for file '%s' with pattern '%s'",
                path, pattern_to_match)
            log.warn("%s", err)
            return nil, err
        end
        local err = string.format("grep -E exited unexpectedly for file '%s' with code: %s",
            path, tostring(exit_code))
        log.warn("%s", err)
        return nil, err
    end

    local use_grep = pattern_to_match:find("|", 1, true) ~= nil

    for _, file_path in ipairs(files_to_check) do
        if use_grep then
            local matched, err = grep_match(file_path)
            if not matched and err then
                return nil, err
            end
            if matched then
                return { found = true }
            end
        else
            if is_case_insensitive then
                pattern_to_match = pattern_to_match:lower()
            end
            local file, err = _dependencies.io_open(file_path, "r")
            if not file then
                log.warn("Could not open file '%s' while matching pattern: %s",
                    file_path, tostring(err))
                return nil, string.format("Could not open file '%s': %s",
                    file_path, tostring(err))
            end
            for line in file:lines() do
                local line_to_check = line
                if is_case_insensitive then
                    line_to_check = line_to_check:lower()
                end
                if line_to_check:match(pattern_to_match) then
                    file:close()
                    return { found = true }
                end
            end
            file:close()
        end
    end
    return { found = false }
end

function M.parse_key_values(params)
    if not params or not params.path then
        return nil, "Probe 'file.parse_key_values' requires a 'path' parameter."
    end

    local normalize_values = params.normalize_values
    local file, err = _dependencies.io_open(params.path, "r")

    if not file then
        log.warn("Could not open file for parsing '%s': %s", params.path, tostring(err))
        return nil, string.format("Could not open file '%s': %s", params.path, tostring(err))
    end

    local config_values = key_value_file.parse_handle(file, {
        normalize_values = normalize_values,
    })
    file:close()
    return config_values
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

return M
