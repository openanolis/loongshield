local lfs = require('lfs')
local path_list = require('seharden.shared.path_list')
local text = require('seharden.shared.text')

local M = {}

local DEFAULT_CONFIG_PATHS = { "/etc/chrony.conf" }
local DEFAULT_SYSCONFIG_PATH = "/etc/sysconfig/chronyd"

local _default_dependencies = {
    io_open = io.open,
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

local function strip_comment(line)
    local index = tostring(line or ""):find("#", 1, true)
    if index then
        return line:sub(1, index - 1)
    end
    return line
end

local function parse_directive(line)
    local active = text.trim(strip_comment(line))
    if active == "" then
        return nil, nil
    end

    local directive, value = active:match("^([%w_]+)%s*:%s*(.-)%s*$")
    if not directive then
        directive, value = active:match("^([%w_]+)%s+(.-)%s*$")
    end
    if not directive or value == "" then
        return nil, nil
    end

    return directive:lower(), value
end

local function first_word(value)
    return tostring(value or ""):match("^(%S+)")
end

local function sorted_directory_files(path)
    local files = {}
    local dir = _dependencies.lfs_dir(path)
    if not dir then
        return files
    end

    for name in dir do
        if name ~= "." and name ~= ".." then
            local full_path = path .. "/" .. name
            local attr = _dependencies.lfs_attributes(full_path)
            if attr and attr.mode == "file" then
                files[#files + 1] = full_path
            end
        end
    end

    table.sort(files)
    return files
end

local function expand_include_path(path)
    path = first_word(path)
    if not path then
        return {}
    end

    local attr = _dependencies.lfs_attributes(path)
    if attr and attr.mode == "directory" then
        return sorted_directory_files(path)
    end
    if attr and attr.mode == "file" then
        return { path }
    end
    if path:find("[%*%?%[]") then
        return path_list.expand_files({ path })
    end

    return {}
end

local function append_unique(out, seen, path)
    if path and not seen[path] then
        out[#out + 1] = path
        seen[path] = true
    end
end

local function discover_config_files(initial_paths)
    local files = {}
    local seen = {}
    local queue = {}

    for _, path in ipairs(initial_paths or DEFAULT_CONFIG_PATHS) do
        append_unique(queue, seen, path)
    end

    local index = 1
    while index <= #queue do
        local path = queue[index]
        index = index + 1

        local attr = _dependencies.lfs_attributes(path)
        if attr and attr.mode == "file" then
            files[#files + 1] = path
            local handle = _dependencies.io_open(path, "r")
            if handle then
                for line in handle:lines() do
                    local directive, value = parse_directive(line)
                    if directive == "confdir" or directive == "sourcedir" then
                        for _, include_path in ipairs(expand_include_path(value)) do
                            append_unique(queue, seen, include_path)
                        end
                    end
                end
                handle:close()
            end
        elseif attr and attr.mode == "directory" then
            for _, include_path in ipairs(sorted_directory_files(path)) do
                append_unique(queue, seen, include_path)
            end
        elseif tostring(path):find("[%*%?%[]") then
            for _, include_path in ipairs(path_list.expand_files({ path })) do
                append_unique(queue, seen, include_path)
            end
        end
    end

    table.sort(files)
    return files
end

local function inspect_sources(config_files)
    local details = {}
    local unreadable = 0

    for _, path in ipairs(config_files) do
        local handle = _dependencies.io_open(path, "r")
        if not handle then
            unreadable = unreadable + 1
        else
            for line in handle:lines() do
                local directive, value = parse_directive(line)
                if (directive == "server" or directive == "pool") and first_word(value) then
                    details[#details + 1] = {
                        path = path,
                        directive = directive,
                        value = value,
                    }
                end
            end
            handle:close()
        end
    end

    return details, unreadable
end

local function strip_quotes(value)
    value = text.trim(tostring(value or ""))
    local first = value:sub(1, 1)
    local last = value:sub(-1)
    if #value >= 2 and ((first == '"' and last == '"') or (first == "'" and last == "'")) then
        return value:sub(2, -2)
    end
    return value
end

local function options_runs_as_root(value)
    return strip_quotes(value):lower():find("%-u%s+root%f[%A]") ~= nil
end

local function inspect_sysconfig(path)
    local handle = _dependencies.io_open(path, "r")
    if not handle then
        return false, false
    end

    local runs_as_root = false
    for line in handle:lines() do
        local active = text.trim(strip_comment(line))
        local key, value = active:match("^([^=%s]+)%s*=%s*(.-)%s*$")
        if key and key:lower() == "options" and options_runs_as_root(value) then
            runs_as_root = true
            break
        end
    end
    handle:close()

    return true, runs_as_root
end

function M.inspect_configuration(params)
    params = params or {}
    local config_paths = params.config_paths or DEFAULT_CONFIG_PATHS
    local sysconfig_path = params.sysconfig_path or DEFAULT_SYSCONFIG_PATH

    local config_files = discover_config_files(config_paths)
    local source_details, unreadable_count = inspect_sources(config_files)
    local sysconfig_available, runs_as_root = inspect_sysconfig(sysconfig_path)

    return {
        config_available = #config_files > 0 and unreadable_count == 0,
        config_files = config_files,
        unreadable_count = unreadable_count,
        source_count = #source_details,
        source_details = source_details,
        has_time_source = #source_details > 0,
        sysconfig_available = sysconfig_available,
        runs_as_root = runs_as_root,
        non_root_configured = sysconfig_available and not runs_as_root,
    }
end

return M
