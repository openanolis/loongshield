local lfs = require('lfs')
local fsutil = require('seharden.enforcers.fsutil')
local sudoers = require('seharden.parsers.sudoers')
local text = require('seharden.shared.text')
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

local trim = text.trim

local function is_safe_path(path)
    return type(path) == "string" and path ~= "" and not path:find("[%c\n\r]")
end

local function collect_state(root_path, context)
    return sudoers.load({ root_path }, {
        dependencies = {
            io_open = _dependencies.io_open,
            lfs_attributes = _dependencies.lfs_attributes,
            lfs_dir = _dependencies.lfs_dir,
            get_short_hostname = _dependencies.get_short_hostname,
        },
        error_context = context,
    })
end

local function collect_paths(root_path, context)
    local state, err = collect_state(root_path, context)
    if not state then
        return nil, err
    end

    return state.files
end

local function collect_audit_paths(root_path, context)
    local state, err = collect_state(root_path, context)
    if not state then
        return nil, err
    end

    local paths = {}
    for _, entry in ipairs(state.audit_paths) do
        paths[#paths + 1] = entry.path
    end

    return paths
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
