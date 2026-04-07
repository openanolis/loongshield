local lfs = require('lfs')
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

local function trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

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

local function get_dirname(path)
    return path:match("^(.*)/[^/]+$") or "."
end

local function resolve_include_path(raw_path, current_path)
    local path = trim(raw_path)
    if path:sub(1, 1) == '"' and path:sub(-1) == '"' and #path >= 2 then
        path = path:sub(2, -2)
    end

    path = path:gsub("%%h", _dependencies.get_short_hostname() or "")
    path = path:gsub("\\ ", " ")
    path = path:gsub("\\\\", "\\")

    if path:sub(1, 1) ~= "/" then
        path = get_dirname(current_path) .. "/" .. path
    end

    return path
end

local function parse_include_directive(line)
    local path = line:match("^[@#]includedir%s+(.+)$")
    if path then
        return "includedir", path
    end

    path = line:match("^[@#]include%s+(.+)$")
    if path then
        return "include", path
    end

    return nil, nil
end

local function list_directory_files(path)
    local attr = _dependencies.lfs_attributes(path)
    if not attr or attr.mode ~= "directory" then
        return nil, string.format("Could not open sudoers include directory '%s'.", path)
    end

    local entries = {}
    for name in _dependencies.lfs_dir(path) do
        local is_includedir_member = name ~= "."
            and name ~= ".."
            and not name:find("%.", 1, true)
            and not name:match("~$")

        if is_includedir_member then
            local full_path = path .. "/" .. name
            local full_attr = _dependencies.lfs_attributes(full_path)
            if full_attr and full_attr.mode == "file" then
                entries[#entries + 1] = full_path
            end
        end
    end

    table.sort(entries)
    return entries
end

local visit_path

local function record_unique_path(paths, seen, path, path_type)
    local key = tostring(path_type) .. ":" .. tostring(path)
    if not seen[key] then
        seen[key] = true
        paths[#paths + 1] = {
            path = path,
            path_type = path_type,
        }
    end
end

local function visit_directory(path, state, depth)
    record_unique_path(state.audit_paths, state.audit_path_set, path, "directory")
    record_unique_path(state.permission_paths, state.permission_path_set, path, "directory")

    local entries, err = list_directory_files(path)
    if not entries then
        return nil, err
    end

    for _, entry in ipairs(entries) do
        record_unique_path(state.permission_paths, state.permission_path_set, entry, "file")
        local ok, visit_err = visit_path(entry, state, depth + 1, false)
        if not ok then
            return nil, visit_err
        end
    end

    return true
end

visit_path = function(path, state, depth, record_path_for_audit)
    if depth > 128 then
        return nil, "Sudoers include depth exceeded the supported limit."
    end
    if state.stack[path] then
        return nil, string.format("Detected a sudoers include loop at '%s'.", path)
    end

    if record_path_for_audit ~= false then
        record_unique_path(state.audit_paths, state.audit_path_set, path, "file")
    end
    record_unique_path(state.permission_paths, state.permission_path_set, path, "file")

    local attr = _dependencies.lfs_attributes(path)
    if not attr or attr.mode ~= "file" then
        return nil, string.format("Could not open sudoers file '%s'.", path)
    end

    local file = _dependencies.io_open(path, "r")
    if not file then
        return nil, string.format("Could not open sudoers file '%s'.", path)
    end

    state.stack[path] = true

    for line in file:lines() do
        local trimmed = trim(line)
        if trimmed ~= "" then
            local include_kind, include_arg = parse_include_directive(trimmed)
            if include_kind == "include" then
                local include_path = resolve_include_path(include_arg, path)
                local ok, err = visit_path(include_path, state, depth + 1)
                if not ok then
                    file:close()
                    state.stack[path] = nil
                    return nil, err
                end
            elseif include_kind == "includedir" then
                local include_path = resolve_include_path(include_arg, path)
                local ok, err = visit_directory(include_path, state, depth + 1)
                if not ok then
                    file:close()
                    state.stack[path] = nil
                    return nil, err
                end
            elseif not trimmed:match("^#") then
                local active = trim((trimmed:gsub("%s+#.*$", "")))
                if active ~= "" then
                    state.lines[#state.lines + 1] = {
                        path = path,
                        text = active,
                    }
                end
            end
        end
    end

    file:close()
    state.stack[path] = nil
    return true
end

local function load_sudoers_state(paths)
    local state = {
        lines = {},
        stack = {},
        audit_paths = {},
        audit_path_set = {},
        permission_paths = {},
        permission_path_set = {},
    }

    for _, path in ipairs(paths) do
        local ok, err = visit_path(path, state, 1)
        if not ok then
            return nil, err
        end
    end

    return state
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
