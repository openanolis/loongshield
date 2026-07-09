local log = require('runtime.log')
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
    fs_stat = function(path)
        return require('fs').stat(path)
    end,
    fs_chmod = function(path, mode)
        return require('fs').chmod(path, mode)
    end,
    fs_chown = function(path, uid, gid)
        return require('fs').chown(path, uid, gid)
    end,
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
    root_path = '/etc/sudoers',
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
    return type(path) == 'string' and path ~= '' and not path:find('[%c\n\r]')
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

local function rewrite_sudo_auth_line(line)
    local active = trim((line:gsub('%s+#.*$', '')))
    if active == '' or active:match('^#') then
        return line, false
    end

    if active:lower():find('nopasswd:', 1, true) then
        local new_line = line:gsub('([Nn][Oo][Pp][Aa][Ss][Ss][Ww][Dd]:)', '')
        new_line = new_line:gsub('%s+', ' '):gsub('%s+$', '')

        local leading_ws = line:match('^(%s*)')
        return leading_ws .. trim(new_line), true, 'nopasswd'
    end

    local rewritten, changed = sudoers.rewrite_defaults_without_flag(line, 'authenticate', true)
    if not changed then
        return line, false
    end

    if not rewritten then
        return nil, true, 'empty_defaults'
    end

    return rewritten, true, 'authenticate'
end

function M.set_use_pty(params)
    params = params or {}
    local root_path = params.root_path or _dependencies.root_path
    if not is_safe_path(root_path) then
        return nil, 'sudo.set_use_pty: requires a safe root_path'
    end
    if fsutil.is_symlink(root_path, _dependencies) then
        return nil, string.format("sudo.set_use_pty: refusing to overwrite symlink '%s'", root_path)
    end

    local paths, err = collect_paths(root_path, 'sudo.set_use_pty')
    if not paths then
        return nil, err
    end

    local desired_line = 'Defaults use_pty'

    for _, path in ipairs(paths) do
        if fsutil.is_symlink(path, _dependencies) then
            return nil, string.format("sudo.set_use_pty: refusing to overwrite symlink '%s'", path)
        end

        local original_lines, read_err = fsutil.read_lines(path, 'sudo.set_use_pty', _dependencies)
        if not original_lines then
            return nil, read_err
        end

        local new_lines = {}
        local has_desired_line = false

        for _, line in ipairs(original_lines) do
            local rewritten = sudoers.rewrite_defaults_without_flag(line, 'use_pty', true)
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

        if not fsutil.lines_equal(original_lines, new_lines) then
            local ok, write_err =
                fsutil.write_lines_atomically_preserving_attrs(path, new_lines, 'sudo.set_use_pty', _dependencies)
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
        return nil, 'sudo.ensure_audit_watches: requires a safe root_path'
    end

    local permissions = params.permissions or 'wa'
    if type(permissions) ~= 'string' or permissions == '' or permissions:find('[^rwax]') then
        return nil, "sudo.ensure_audit_watches: requires 'permissions' to contain only r,w,a,x"
    end

    local paths, err = collect_audit_paths(root_path, 'sudo.ensure_audit_watches')
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

-- Fix permissions and ownership on sudoers configuration paths.
-- Applies different modes based on path type (file vs directory).
-- params: { list = probe_data_table }
-- list.details is expected to contain entries with .path and .path_type fields.
function M.fix_permission_paths(params)
    if not params or not params.list then
        return nil, "sudo.fix_permission_paths: requires 'list' parameter"
    end

    local list = params.list
    local entries = list.details
    if not entries or type(entries) ~= 'table' then
        return nil, "sudo.fix_permission_paths: 'list' must contain a 'details' table"
    end

    local changed = 0
    local skipped_symlink = 0
    local skipped_missing = 0
    local already_compliant = 0
    local errors = {}

    for _, entry in ipairs(entries) do
        local path = entry.path
        local path_type = entry.path_type
        if not path or not path_type then
            goto continue
        end

        -- Skip symlinks for safety
        if fsutil.is_symlink(path, _dependencies) then
            log.debug("sudo.fix_permission_paths: skipping symlink '%s'", path)
            skipped_symlink = skipped_symlink + 1
            goto continue
        end

        -- Check if path exists
        local attr = _dependencies.fs_stat(path)
        if not attr then
            log.warn('sudo.fix_permission_paths: path not found: %s', path)
            skipped_missing = skipped_missing + 1
            goto continue
        end

        -- Determine target mode based on path type
        local want_mode
        if path_type == 'file' then
            want_mode = tonumber('0440', 8) -- octal 0440 = decimal 288
        elseif path_type == 'directory' then
            want_mode = tonumber('0750', 8) -- octal 0750 = decimal 488
        else
            log.warn("sudo.fix_permission_paths: unknown path_type '%s' for '%s'", path_type, path)
            goto continue
        end

        local needs_chown = (attr:uid() ~= 0 or attr:gid() ~= 0)
        local needs_chmod = (want_mode ~= attr:mode())

        if not needs_chown and not needs_chmod then
            already_compliant = already_compliant + 1
            goto continue
        end

        -- Fix ownership (chown to root:root)
        if needs_chown then
            log.debug('sudo.fix_permission_paths: chown 0:0 %s', path)
            local ok, err = _dependencies.fs_chown(path, 0, 0)
            if not ok then
                errors[#errors + 1] = string.format("chown failed on '%s': %s", path, tostring(err))
                goto continue
            end
        end

        -- Fix permissions (chmod)
        if needs_chmod then
            log.debug('sudo.fix_permission_paths: chmod %o %s (was %o)', want_mode, path, attr:mode())
            local ok, err = _dependencies.fs_chmod(path, want_mode)
            if not ok then
                errors[#errors + 1] = string.format("chmod failed on '%s': %s", path, tostring(err))
                goto continue
            end
        end

        changed = changed + 1

        ::continue::
    end

    if #errors > 0 then
        return nil, string.format('sudo.fix_permission_paths: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.info(
        'sudo.fix_permission_paths: changed %d, already compliant %d, skipped symlink %d, missing %d',
        changed,
        already_compliant,
        skipped_symlink,
        skipped_missing
    )
    return true
end

-- Remove NOPASSWD tags and neutralize !authenticate Defaults entries
-- from sudoers configuration.
-- Replaces 'NOPASSWD:' with empty string to require password authentication.
-- Removes '!authenticate' tokens from Defaults lines; drops the line if empty.
-- params: { root_path = path_to_sudoers_file }
function M.remove_nopasswd(params)
    params = params or {}
    local root_path = params.root_path or _dependencies.root_path
    if not is_safe_path(root_path) then
        return nil, 'sudo.remove_nopasswd: requires a safe root_path'
    end
    if fsutil.is_symlink(root_path, _dependencies) then
        return nil, string.format("sudo.remove_nopasswd: refusing to overwrite symlink '%s'", root_path)
    end

    local paths, err = collect_paths(root_path, 'sudo.remove_nopasswd')
    if not paths then
        return nil, err
    end

    local changed_files = 0
    local changed_lines = 0

    for _, path in ipairs(paths) do
        if fsutil.is_symlink(path, _dependencies) then
            log.warn("sudo.remove_nopasswd: skipping symlink '%s'", path)
            goto continue
        end

        local original_lines, read_err = fsutil.read_lines(path, 'sudo.remove_nopasswd', _dependencies)
        if not original_lines then
            return nil, read_err
        end

        local new_lines = {}
        local file_changed = false
        local file_changed_lines = 0

        for _, line in ipairs(original_lines) do
            local rewritten, changed, action = rewrite_sudo_auth_line(line)
            if rewritten then
                new_lines[#new_lines + 1] = rewritten
            end

            if changed then
                file_changed = true
                changed_lines = changed_lines + 1
                file_changed_lines = file_changed_lines + 1
                if action == 'nopasswd' then
                    log.debug('sudo.remove_nopasswd: removed NOPASSWD from line: %s -> %s', trim(line), trim(rewritten))
                elseif action == 'empty_defaults' then
                    log.debug('sudo.remove_nopasswd: dropped empty Defaults line: %s', trim(line))
                elseif action == 'authenticate' then
                    log.debug('sudo.remove_nopasswd: removed !authenticate from line: %s -> %s', trim(line), rewritten)
                end
            end
        end

        if file_changed then
            local ok, write_err =
                fsutil.write_lines_atomically_preserving_attrs(path, new_lines, 'sudo.remove_nopasswd', _dependencies)
            if not ok then
                return nil, write_err
            end
            changed_files = changed_files + 1
            log.info('sudo.remove_nopasswd: modified %s (%d lines changed)', path, file_changed_lines)
        end

        ::continue::
    end

    if changed_files == 0 then
        log.debug('sudo.remove_nopasswd: no NOPASSWD tags found, skipping')
        return true
    end

    log.info('sudo.remove_nopasswd: modified %d file(s), %d line(s) total', changed_files, changed_lines)
    return true
end

return M
