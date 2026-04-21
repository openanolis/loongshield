local lfs = require('lfs')
local sudoers = require('seharden.parsers.sudoers')
local text = require('seharden.shared.text')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
    get_short_hostname = function()
        local file = io.open("/proc/sys/kernel/hostname", "r")
        if not file then
            return nil
        end

        local hostname = file:read("*l")
        file:close()
        if not hostname or hostname == "" then
            return nil
        end

        hostname = hostname:match("^[^.]+") or hostname
        return hostname:gsub("/", "_")
    end,
}

local _dependencies = {}
local DEFAULT_SUDOERS_PATHS = { "/etc/sudoers" }

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local trim = text.trim

local function get_defaults_scope(text)
    local lowered_text = trim(text):lower()

    if lowered_text:match("^defaults%s") then
        return "global"
    end
    if lowered_text:match("^defaults[@:!>]") then
        return "scoped"
    end

    return nil
end

local function get_defaults_flag_state(text, flag_name)
    local state = nil

    for token in tostring(text or ""):lower():gmatch("[^,%s]+") do
        if token == flag_name then
            state = true
        elseif token == "!" .. flag_name then
            state = false
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
    if type(paths) ~= "table" or #paths == 0 then
        return nil, string.format("Probe '%s' requires a non-empty 'paths' list.", probe_name)
    end
    return paths
end

function M.find_use_pty(params)
    local paths, path_err = resolve_probe_paths(params, "sudo.find_use_pty")
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
        local defaults_scope = get_defaults_scope(entry.text)
        local use_pty_enabled = get_defaults_flag_state(entry.text, "use_pty")

        if use_pty_enabled == false and defaults_scope ~= nil then
            conflicts[#conflicts + 1] = entry
        elseif use_pty_enabled == true and defaults_scope == "global" then
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
    local paths, path_err = resolve_probe_paths(params, "sudo.find_nopasswd_entries")
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
        local defaults_scope = get_defaults_scope(entry.text)

        if defaults_scope == nil and lowered_text:find("nopasswd:", 1, true) then
            local detail = {}
            for key, value in pairs(entry) do
                detail[key] = value
            end
            detail.reason = "nopasswd_tag"
            details[#details + 1] = detail
        elseif defaults_scope ~= nil then
            local authenticate_enabled = get_defaults_flag_state(entry.text, "authenticate")
            if authenticate_enabled == false then
                local detail = {}
                for key, value in pairs(entry) do
                    detail[key] = value
                end
                detail.reason = "authenticate_disabled"
                details[#details + 1] = detail
            end
        end
    end

    return {
        count = #details,
        details = details,
    }
end

function M.collect_audit_paths(params)
    local paths, path_err = resolve_probe_paths(params, "sudo.collect_audit_paths")
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
    local paths, path_err = resolve_probe_paths(params, "sudo.collect_permission_paths")
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
