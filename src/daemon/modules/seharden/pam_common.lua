local key_value_file = require('seharden.key_value_file')
local pam_parser = require('seharden.parsers.pam')
local path_list = require('seharden.path_list')

local M = {}

local default_dependencies = {
    io_open = io.open,
    expand_paths = function(paths)
        return path_list.expand_files(paths)
    end,
}

local dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(default_dependencies) do
        dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

function M.resolve_pam_paths(params, probe_name)
    local pam_paths = params and params.pam_paths
    if type(pam_paths) ~= "table" or #pam_paths == 0 then
        return nil, string.format("Probe '%s' requires a non-empty 'pam_paths' list.", probe_name)
    end
    return pam_paths
end

function M.add_detail(details, path, reason, extra)
    local detail = {
        path = path,
        reason = reason,
    }

    for key, value in pairs(extra or {}) do
        detail[key] = value
    end

    details[#details + 1] = detail
end

function M.load_optional_key_value_file(path)
    local file = dependencies.io_open(path, "r")
    if not file then
        return nil, false
    end

    local values = key_value_file.parse_handle(file)
    file:close()
    return values, true
end

local function expand_ordered_paths(path_specs)
    local expanded = {}
    local seen = {}

    for _, path_spec in ipairs(path_specs or {}) do
        local matches, err = dependencies.expand_paths({ path_spec })
        if not matches then
            return nil, err
        end

        table.sort(matches)
        for _, path in ipairs(matches) do
            if not seen[path] then
                expanded[#expanded + 1] = path
                seen[path] = true
            end
        end
    end

    return expanded
end

function M.load_optional_key_value_files(path_specs)
    local paths, err = expand_ordered_paths(path_specs)
    if not paths then
        return nil, false, err
    end

    local values = {}
    local found = false

    for _, path in ipairs(paths) do
        local parsed, file_found = M.load_optional_key_value_file(path)
        if not file_found then
            return nil, false, string.format("Could not open config file '%s' for reading.", path)
        end
        found = true

        for key, value in pairs(parsed) do
            values[key] = value
        end
    end

    return values, found
end

function M.parse_option(args, option_name)
    for _, arg in ipairs(args) do
        local value = arg:match("^" .. option_name .. "=(.+)$")
        if value then
            return value
        end
    end
    return nil
end

function M.has_arg(args, option_name)
    for _, arg in ipairs(args) do
        if arg == option_name then
            return true
        end
    end
    return false
end

function M.parse_non_negative_integer(value)
    local number = tonumber(value)
    if not number or number < 0 then
        return nil
    end
    return number
end

function M.parse_positive_integer(value)
    local number = tonumber(value)
    if not number or number < 1 then
        return nil
    end
    return number
end

function M.parse_integer(value)
    local number = tonumber(value)
    if number == nil then
        return nil
    end
    return number
end

function M.load_pam_entries(path)
    local file = dependencies.io_open(path, "r")
    if not file then
        return nil
    end

    local entries = {}
    for line in file:lines() do
        local entry = pam_parser.parse_line(line)
        if entry then
            entries[#entries + 1] = entry
        end
    end
    file:close()
    return entries
end

return M
