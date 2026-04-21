local lfs = require('lfs')
local log = require('runtime.log')
local key_value_file = require('seharden.key_value_file')
local text = require('seharden.text')
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
end

M._test_set_dependencies()

local function join_path(base, part)
    if base == "." then
        return part
    elseif base == "/" then
        return "/" .. part
    end
    return base .. "/" .. part
end

local function has_wildcard(s)
    return s:find("[%*%?%[]") ~= nil
end

local function path_mode(path)
    local attr = _dependencies.lfs_attributes(path)
    return attr and attr.mode or nil
end

local function expand_glob_path(path_glob)
    local is_abs = path_glob:sub(1, 1) == "/"
    local parts = {}
    for part in path_glob:gmatch("[^/]+") do
        table.insert(parts, part)
    end

    local bases = { is_abs and "/" or "." }
    for _, part in ipairs(parts) do
        if part == "." then
            goto continue
        end
        if part == ".." then
            local new_bases = {}
            local seen = {}
            for _, base in ipairs(bases) do
                local parent
                if base == "/" then
                    parent = "/"
                else
                    parent = base:match("^(.*)/[^/]+$") or "."
                end
                if not seen[parent] then
                    table.insert(new_bases, parent)
                    seen[parent] = true
                end
            end
            bases = new_bases
            goto continue
        end

        if has_wildcard(part) then
            local pat = text.glob_to_pattern(part)
            local new_bases = {}
            local seen = {}
            for _, base in ipairs(bases) do
                if path_mode(base) == "directory" then
                    for name in _dependencies.lfs_dir(base) do
                        if name ~= "." and name ~= ".." and name:match(pat) then
                            local full = join_path(base, name)
                            if not seen[full] then
                                table.insert(new_bases, full)
                                seen[full] = true
                            end
                        end
                    end
                end
            end
            bases = new_bases
        else
            local new_bases = {}
            local seen = {}
            for _, base in ipairs(bases) do
                local full = join_path(base, part)
                if not seen[full] then
                    table.insert(new_bases, full)
                    seen[full] = true
                end
            end
            bases = new_bases
        end

        ::continue::
    end

    return bases
end

local function expand_paths(paths_table)
    local expanded = {}
    local unique_paths = {}
    for _, path_glob in ipairs(paths_table) do
        if type(path_glob) == "string" and path_glob ~= "" then
            if not has_wildcard(path_glob) then
                if path_mode(path_glob) == "file" and not unique_paths[path_glob] then
                    table.insert(expanded, path_glob)
                    unique_paths[path_glob] = true
                end
            else
                for _, full in ipairs(expand_glob_path(path_glob)) do
                    if path_mode(full) == "file" and not unique_paths[full] then
                        table.insert(expanded, full)
                        unique_paths[full] = true
                    end
                end
            end
        end
    end
    return expanded
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
