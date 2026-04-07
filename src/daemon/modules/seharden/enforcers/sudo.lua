local lfs = require('lfs')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    fs_stat = function(path) return require('fs').stat(path) end,
    fs_chmod = function(path, mode) return require('fs').chmod(path, mode) end,
    fs_chown = function(path, uid, gid) return require('fs').chown(path, uid, gid) end,
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
    root_path = "/etc/sudoers",
    ensure_watch_rule = function(params)
        return require('seharden.enforcers.audit').ensure_watch_rule(params)
    end,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function trim(value)
    return tostring(value or ""):match("^%s*(.-)%s*$")
end

local function get_dirname(path)
    return path:match("^(.*)/[^/]+$") or "."
end

local function is_safe_path(path)
    return type(path) == "string" and path ~= "" and not path:find("[%c\n\r]")
end

local function record_unique_path(paths, seen, path)
    if not seen[path] then
        seen[path] = true
        paths[#paths + 1] = path
    end
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

local function list_directory_files(path, context)
    local attr = _dependencies.lfs_attributes(path)
    if not attr or attr.mode ~= "directory" then
        return nil, string.format("%s: could not open sudoers include directory '%s'", context, path)
    end

    local entries = {}
    for name in _dependencies.lfs_dir(path) do
        local is_member = name ~= "."
            and name ~= ".."
            and not name:find(".", 1, true)
            and not name:match("~$")

        if is_member then
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

visit_path = function(path, state, depth, context, record_path_for_audit)
    if depth > 128 then
        return nil, string.format("%s: sudoers include depth exceeded the supported limit", context)
    end
    if state.stack[path] then
        return nil, string.format("%s: detected a sudoers include loop at '%s'", context, path)
    end

    if record_path_for_audit ~= false then
        record_unique_path(state.audit_paths, state.audit_path_set, path)
    end
    if state.seen[path] then
        return true
    end

    local attr = _dependencies.lfs_attributes(path)
    if not attr or attr.mode ~= "file" then
        return nil, string.format("%s: could not open sudoers file '%s'", context, path)
    end

    local file = _dependencies.io_open(path, "r")
    if not file then
        return nil, string.format("%s: could not open sudoers file '%s'", context, path)
    end

    state.stack[path] = true
    state.seen[path] = true
    record_unique_path(state.paths, state.path_set, path)

    for line in file:lines() do
        local trimmed = trim(line)
        if trimmed ~= "" then
            local include_kind, include_arg = parse_include_directive(trimmed)
            if include_kind == "include" then
                local include_path = resolve_include_path(include_arg, path)
                local ok, err = visit_path(include_path, state, depth + 1, context)
                if not ok then
                    file:close()
                    state.stack[path] = nil
                    return nil, err
                end
            elseif include_kind == "includedir" then
                local include_path = resolve_include_path(include_arg, path)
                record_unique_path(state.audit_paths, state.audit_path_set, include_path)
                local entries, err = list_directory_files(include_path, context)
                if not entries then
                    file:close()
                    state.stack[path] = nil
                    return nil, err
                end
                for _, entry in ipairs(entries) do
                    local ok, visit_err = visit_path(entry, state, depth + 1, context, false)
                    if not ok then
                        file:close()
                        state.stack[path] = nil
                        return nil, visit_err
                    end
                end
            end
        end
    end

    file:close()
    state.stack[path] = nil
    return true
end

local function collect_state(root_path, context)
    local state = {
        paths = {},
        path_set = {},
        audit_paths = {},
        audit_path_set = {},
        seen = {},
        stack = {},
    }

    local ok, err = visit_path(root_path, state, 1, context)
    if not ok then
        return nil, err
    end

    return state
end

local function collect_paths(root_path, context)
    local state, err = collect_state(root_path, context)
    if not state then
        return nil, err
    end

    return state.paths
end

local function collect_audit_paths(root_path, context)
    local state, err = collect_state(root_path, context)
    if not state then
        return nil, err
    end

    return state.audit_paths
end

local function read_lines(path)
    local file, err = _dependencies.io_open(path, "r")
    if not file then
        return nil, string.format("sudo.set_use_pty: could not open sudoers file '%s': %s", path, tostring(err))
    end

    local lines = {}
    for line in file:lines() do
        lines[#lines + 1] = line
    end
    file:close()
    return lines
end

local function lines_equal(left, right)
    if #left ~= #right then
        return false
    end

    for index = 1, #left do
        if left[index] ~= right[index] then
            return false
        end
    end

    return true
end

local function strip_negated_use_pty(line)
    local active = trim((line:gsub("%s+#.*$", "")))
    if active == "" or active:match("^#") then
        return line
    end

    local prefix, remainder = active:match("^(Defaults[^%s]*)%s+(.+)$")
    if not prefix then
        return line
    end

    local tokens = {}
    local removed = false
    for token in remainder:gmatch("[^,%s]+") do
        if token == "!use_pty" then
            removed = true
        else
            tokens[#tokens + 1] = token
        end
    end

    if not removed then
        return line
    end

    if #tokens == 0 then
        return nil
    end

    return prefix .. " " .. table.concat(tokens, ",")
end

function M.set_use_pty(params)
    params = params or {}
    local root_path = params.root_path or _dependencies.root_path
    if not is_safe_path(root_path) then
        return nil, "sudo.set_use_pty: requires a safe root_path"
    end
    if fsutil.is_symlink(root_path, _dependencies) then
        return nil, string.format("sudo.set_use_pty: refusing to overwrite symlink '%s'", root_path)
    end

    local paths, err = collect_paths(root_path, "sudo.set_use_pty")
    if not paths then
        return nil, err
    end

    local desired_line = "Defaults use_pty"

    for _, path in ipairs(paths) do
        if fsutil.is_symlink(path, _dependencies) then
            return nil, string.format("sudo.set_use_pty: refusing to overwrite symlink '%s'", path)
        end

        local original_lines, read_err = read_lines(path)
        if not original_lines then
            return nil, read_err
        end

        local new_lines = {}
        local has_desired_line = false

        for _, line in ipairs(original_lines) do
            local rewritten = strip_negated_use_pty(line)
            if rewritten then
                if rewritten == desired_line then
                    has_desired_line = true
                end
                new_lines[#new_lines + 1] = rewritten
            end
        end

        if path == root_path and not has_desired_line then
            new_lines[#new_lines + 1] = desired_line
        end

        if not lines_equal(original_lines, new_lines) then
            local ok, write_err = fsutil.write_lines_atomically_preserving_attrs(
                path,
                new_lines,
                "sudo.set_use_pty",
                _dependencies
            )
            if not ok then
                return nil, write_err
            end
        end
    end

    return true
end

function M.ensure_audit_watches(params)
    params = params or {}
    local root_path = params.root_path or _dependencies.root_path
    if not is_safe_path(root_path) then
        return nil, "sudo.ensure_audit_watches: requires a safe root_path"
    end

    local permissions = params.permissions or "wa"
    if type(permissions) ~= "string" or permissions == "" or permissions:find("[^rwax]") then
        return nil, "sudo.ensure_audit_watches: requires 'permissions' to contain only r,w,a,x"
    end

    local paths, err = collect_audit_paths(root_path, "sudo.ensure_audit_watches")
    if not paths then
        return nil, err
    end

    for _, path in ipairs(paths) do
        local ok, watch_err = _dependencies.ensure_watch_rule({
            path = path,
            permissions = permissions,
            key = params.key,
            rule_file = params.rule_file,
            rules_dir = params.rules_dir,
            fallback_rules_path = params.fallback_rules_path,
        })
        if not ok then
            return nil, watch_err
        end
    end

    return true
end

return M
