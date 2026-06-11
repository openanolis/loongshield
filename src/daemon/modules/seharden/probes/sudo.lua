local lfs = require('lfs')
local sudoers = require('seharden.parsers.sudoers')
local text = require('seharden.shared.text')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
    get_short_hostname = function()
        local file = io.open('/proc/sys/kernel/hostname', 'r')
        if not file then
            return nil
        end

        local hostname = file:read('*l')
        file:close()
        if not hostname or hostname == '' then
            return nil
        end

        hostname = hostname:match('^[^.]+') or hostname
        return hostname:gsub('/', '_')
    end,
}

local _dependencies = {}
local DEFAULT_SUDOERS_PATHS = { '/etc/sudoers' }

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local trim = text.trim

local function copy_entry(entry)
    local detail = {}
    for key, value in pairs(entry) do
        detail[key] = value
    end
    return detail
end

local function split_defaults_options(raw_options)
    local options = {}
    local buffer = {}
    local quote = nil
    local escaped = false

    local function push()
        local option = trim(table.concat(buffer))
        if option ~= '' then
            options[#options + 1] = option
        end
        buffer = {}
    end

    for index = 1, #raw_options do
        local char = raw_options:sub(index, index)

        if escaped then
            buffer[#buffer + 1] = char
            escaped = false
        elseif char == '\\' then
            buffer[#buffer + 1] = char
            escaped = true
        elseif quote then
            buffer[#buffer + 1] = char
            if char == quote then
                quote = nil
            end
        elseif char == '"' or char == "'" then
            buffer[#buffer + 1] = char
            quote = char
        elseif char == ',' then
            push()
        else
            buffer[#buffer + 1] = char
        end
    end

    push()
    return options
end

local function unquote_defaults_value(value)
    value = trim(value or '')
    if #value >= 2 then
        local first = value:sub(1, 1)
        local last = value:sub(-1)
        if (first == '"' and last == '"') or (first == "'" and last == "'") then
            value = value:sub(2, -2)
        end
    end

    return value:gsub('\\(.)', '%1')
end

local function append_defaults_option(options, option_text)
    local name, operator, value = option_text:match('^(!?[%w_]+)%s*([+%-]?=)%s*(.-)%s*$')
    if name then
        options[#options + 1] = {
            name = name:gsub('^!', ''):lower(),
            negated = name:sub(1, 1) == '!',
            operator = operator,
            value = unquote_defaults_value(value),
            text = option_text,
        }
        return
    end

    for token in option_text:gmatch('%S+') do
        local negation, flag_name = token:match('^(!?)([%w_]+)$')
        if flag_name then
            options[#options + 1] = {
                name = flag_name:lower(),
                negated = negation == '!',
                text = token,
            }
        end
    end
end

local function parse_defaults_entry(text)
    local active = trim(tostring(text or ''))
    local prefix, raw_options = active:match('^(%S+)%s+(.+)$')
    if not prefix then
        return nil
    end

    local lowered_prefix = prefix:lower()
    local scope = nil
    if lowered_prefix == 'defaults' then
        scope = 'global'
    elseif lowered_prefix:match('^defaults[@:!>]') then
        scope = 'scoped'
    else
        return nil
    end

    local options = {}
    for _, option_text in ipairs(split_defaults_options(raw_options)) do
        append_defaults_option(options, option_text)
    end

    return {
        scope = scope,
        options = options,
    }
end

local function get_defaults_flag_state(text, flag_name)
    local state = nil
    local defaults = parse_defaults_entry(text)
    if not defaults then
        return state
    end

    flag_name = flag_name:lower()
    for _, option in ipairs(defaults.options) do
        if option.operator == nil and option.name == flag_name then
            state = not option.negated
        end
    end

    return state
end

local function load_sudoers_state(paths)
    return sudoers.load(paths, {
        dependencies = {
            io_open = _dependencies.io_open,
            lfs_attributes = _dependencies.lfs_attributes,
            lfs_dir = _dependencies.lfs_dir,
            get_short_hostname = _dependencies.get_short_hostname,
        },
    })
end

local function load_sudoers_lines(paths)
    local state, err = load_sudoers_state(paths)
    if not state then
        return nil, err
    end

    return state.lines
end

local function resolve_probe_paths(params, probe_name)
    local paths = params and params.paths or DEFAULT_SUDOERS_PATHS
    if type(paths) ~= 'table' or #paths == 0 then
        return nil, string.format("Probe '%s' requires a non-empty 'paths' list.", probe_name)
    end
    return paths
end

function M.find_use_pty(params)
    local paths, path_err = resolve_probe_paths(params, 'sudo.find_use_pty')
    if not paths then
        return nil, path_err
    end

    local lines, err = load_sudoers_lines(paths)
    if not lines then
        return nil, err
    end

    local details = {}
    local conflicts = {}

    for _, entry in ipairs(lines) do
        local defaults = parse_defaults_entry(entry.text)
        local defaults_scope = defaults and defaults.scope or nil
        local use_pty_enabled = get_defaults_flag_state(entry.text, 'use_pty')

        if use_pty_enabled == false and defaults_scope ~= nil then
            conflicts[#conflicts + 1] = entry
        elseif use_pty_enabled == true and defaults_scope == 'global' then
            details[#details + 1] = entry
        end
    end

    return {
        found = #details > 0,
        count = #details,
        conflicting_count = #conflicts,
        details = details,
        conflicts = conflicts,
    }
end

function M.find_nopasswd_entries(params)
    local paths, path_err = resolve_probe_paths(params, 'sudo.find_nopasswd_entries')
    if not paths then
        return nil, path_err
    end

    local lines, err = load_sudoers_lines(paths)
    if not lines then
        return nil, err
    end

    local details = {}
    for _, entry in ipairs(lines) do
        local lowered_text = entry.text:lower()
        local defaults = parse_defaults_entry(entry.text)
        local defaults_scope = defaults and defaults.scope or nil

        if defaults_scope == nil and lowered_text:find('nopasswd:', 1, true) then
            local detail = copy_entry(entry)
            detail.reason = 'nopasswd_tag'
            details[#details + 1] = detail
        elseif defaults_scope ~= nil then
            local authenticate_enabled = get_defaults_flag_state(entry.text, 'authenticate')
            if authenticate_enabled == false then
                local detail = copy_entry(entry)
                detail.reason = 'authenticate_disabled'
                details[#details + 1] = detail
            end
        end
    end

    return {
        found = #details > 0,
        count = #details,
        value = details[#details] and details[#details].value or nil,
        details = details,
    }
end

function M.find_logfile_entries(params)
    local paths, path_err = resolve_probe_paths(params, 'sudo.find_logfile_entries')
    if not paths then
        return nil, path_err
    end

    local lines, err = load_sudoers_lines(paths)
    if not lines then
        return nil, err
    end

    local details = {}
    for _, entry in ipairs(lines) do
        local defaults = parse_defaults_entry(entry.text)
        if defaults and defaults.scope == 'global' then
            for _, option in ipairs(defaults.options) do
                if option.name == 'logfile' and option.operator == '=' and option.value ~= '' then
                    local detail = copy_entry(entry)
                    detail.value = option.value
                    details[#details + 1] = detail
                end
            end
        end
    end

    return {
        found = #details > 0,
        count = #details,
        value = details[1] and details[1].value or nil,
        details = details,
    }
end

function M.find_global_reauth_disabled(params)
    local paths, path_err = resolve_probe_paths(params, 'sudo.find_global_reauth_disabled')
    if not paths then
        return nil, path_err
    end

    local lines, err = load_sudoers_lines(paths)
    if not lines then
        return nil, err
    end

    local details = {}
    for _, entry in ipairs(lines) do
        local defaults = parse_defaults_entry(entry.text)
        local authenticate_enabled = get_defaults_flag_state(entry.text, 'authenticate')
        if defaults and defaults.scope == 'global' and authenticate_enabled == false then
            details[#details + 1] = copy_entry(entry)
        end
    end

    return {
        found = #details > 0,
        count = #details,
        details = details,
    }
end

function M.find_invalid_timestamp_timeout(params)
    local paths, path_err = resolve_probe_paths(params, 'sudo.find_invalid_timestamp_timeout')
    if not paths then
        return nil, path_err
    end

    local lines, err = load_sudoers_lines(paths)
    if not lines then
        return nil, err
    end

    local max_minutes = tonumber(params and params.max_minutes) or 15
    local details = {}

    for _, entry in ipairs(lines) do
        local defaults = parse_defaults_entry(entry.text)
        if defaults then
            for _, option in ipairs(defaults.options) do
                if option.name == 'timestamp_timeout' and option.operator == '=' then
                    local numeric_value = tonumber(option.value)
                    if not numeric_value or numeric_value < 0 or numeric_value > max_minutes then
                        local detail = copy_entry(entry)
                        detail.value = option.value
                        if numeric_value == nil then
                            detail.reason = 'non_numeric'
                        elseif numeric_value < 0 then
                            detail.reason = 'disabled'
                        else
                            detail.reason = 'exceeds_max'
                        end
                        details[#details + 1] = detail
                    end
                end
            end
        end
    end

    return {
        found = #details > 0,
        count = #details,
        details = details,
    }
end

function M.collect_audit_paths(params)
    local paths, path_err = resolve_probe_paths(params, 'sudo.collect_audit_paths')
    if not paths then
        return nil, path_err
    end

    local state, err = load_sudoers_state(paths)
    if not state then
        return nil, err
    end

    return {
        count = #state.audit_paths,
        details = state.audit_paths,
    }
end

function M.collect_permission_paths(params)
    local paths, path_err = resolve_probe_paths(params, 'sudo.collect_permission_paths')
    if not paths then
        return nil, path_err
    end

    local state, err = load_sudoers_state(paths)
    if not state then
        return nil, err
    end

    return {
        count = #state.permission_paths,
        details = state.permission_paths,
    }
end

return M
