local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    fs_stat = function(path)
        return require('fs').stat(path)
    end,
    fs_chmod = function(path, mode)
        return require('fs').chmod(path, mode)
    end,
    fs_chown = function(path, uid, gid)
        return require('fs').chown(path, uid, gid)
    end,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    lfs_attributes = function(path)
        return require('lfs').attributes(path)
    end,
    lfs_dir = function(path)
        return require('lfs').dir(path)
    end,
    io_open = io.open,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.fs_stat = deps.fs_stat or _default_dependencies.fs_stat
    _dependencies.fs_chmod = deps.fs_chmod or _default_dependencies.fs_chmod
    _dependencies.fs_chown = deps.fs_chown or _default_dependencies.fs_chown
    _dependencies.lfs_symlinkattributes = deps.lfs_symlinkattributes or _default_dependencies.lfs_symlinkattributes
    _dependencies.lfs_attributes = deps.lfs_attributes or _default_dependencies.lfs_attributes
    _dependencies.lfs_dir = deps.lfs_dir or _default_dependencies.lfs_dir
    _dependencies.io_open = deps.io_open or _default_dependencies.io_open
end

M._test_set_dependencies()

local function parse_numeric_id(value, field_name)
    if value == nil then
        return nil
    end

    local parsed = tonumber(value)
    if not parsed or parsed < 0 or parsed ~= math.floor(parsed) then
        return nil, string.format("permissions.set_attributes: invalid %s '%s'", field_name, tostring(value))
    end

    return parsed
end

-- Set file ownership and/or permissions. Idempotent (checks before writing).
-- params: { path, uid (number, optional), gid (number, optional), mode (octal number, optional) }
function M.set_attributes(params)
    if not params or not params.path then
        return nil, "permissions.set_attributes: requires 'path' parameter"
    end

    local path = params.path
    if fsutil.is_symlink(path, _dependencies) then
        return nil, string.format("permissions.set_attributes: refusing to operate on symlink '%s'", path)
    end

    local attr = _dependencies.fs_stat(path)
    if not attr then
        return nil, string.format('permissions.set_attributes: path not found: %s', path)
    end

    local want_uid, uid_err = parse_numeric_id(params.uid, 'uid')
    if uid_err then
        return nil, uid_err
    end

    local want_gid, gid_err = parse_numeric_id(params.gid, 'gid')
    if gid_err then
        return nil, gid_err
    end

    -- chown if uid or gid specified
    want_uid = want_uid ~= nil and want_uid or attr:uid()
    want_gid = want_gid ~= nil and want_gid or attr:gid()

    if want_uid ~= attr:uid() or want_gid ~= attr:gid() then
        if fsutil.is_symlink(path, _dependencies) then
            return nil, string.format("permissions.set_attributes: refusing to operate on symlink '%s'", path)
        end
        log.debug('Enforcer permissions.set_attributes: chown %s:%s %s', want_uid, want_gid, path)
        local ok, err = _dependencies.fs_chown(path, want_uid, want_gid)
        if not ok then
            return nil, string.format("permissions.set_attributes: chown failed on '%s': %s", path, tostring(err))
        end
    end

    -- chmod if mode specified
    if params.mode ~= nil then
        local want_mode = tonumber(params.mode)
        if not want_mode then
            return nil, string.format("permissions.set_attributes: invalid mode '%s'", tostring(params.mode))
        end
        if want_mode ~= attr:mode() then
            if fsutil.is_symlink(path, _dependencies) then
                return nil, string.format("permissions.set_attributes: refusing to operate on symlink '%s'", path)
            end
            log.debug('Enforcer permissions.set_attributes: chmod %o %s', want_mode, path)
            local ok, err = _dependencies.fs_chmod(path, want_mode)
            if not ok then
                return nil, string.format("permissions.set_attributes: chmod failed on '%s': %s", path, tostring(err))
            end
        end
    end

    return true
end

-- Set permissions (and optionally ownership) on multiple paths from a probe result list.
-- Designed for rules that use meta.map/for_all pattern (e.g., home directory permissions, SSH keys).
-- params: { list = probe_data_table, mode = decimal_number, uid = optional_decimal, gid = optional_decimal }
-- list.details is expected to contain entries with a .path field.
function M.set_attributes_for_all(params)
    if not params or not params.list then
        return nil, "permissions.set_attributes_for_all: requires 'list' parameter"
    end

    local list = params.list
    local entries = list.details
    if not entries or type(entries) ~= 'table' then
        return nil, "permissions.set_attributes_for_all: 'list' must contain a 'details' table"
    end

    local want_mode
    if params.mode ~= nil then
        want_mode = tonumber(params.mode)
        if not want_mode then
            return nil, string.format("permissions.set_attributes_for_all: invalid mode '%s'", tostring(params.mode))
        end
    end

    if not want_mode then
        return nil, "permissions.set_attributes_for_all: requires 'mode' parameter"
    end

    -- Optional uid and gid parameters
    local want_uid = params.uid ~= nil and tonumber(params.uid) or nil
    local want_gid = params.gid ~= nil and tonumber(params.gid) or nil

    local changed = 0
    local skipped_symlink = 0
    local skipped_missing = 0
    local already_compliant = 0
    local errors = {}

    for _, entry in ipairs(entries) do
        local path = entry.path
        if not path then
            goto continue
        end

        if fsutil.is_symlink(path, _dependencies) then
            log.debug("permissions.set_attributes_for_all: skipping symlink '%s'", path)
            skipped_symlink = skipped_symlink + 1
            goto continue
        end

        local attr = _dependencies.fs_stat(path)
        if not attr then
            log.warn('permissions.set_attributes_for_all: path not found: %s', path)
            skipped_missing = skipped_missing + 1
            goto continue
        end

        local needs_chown = false
        local needs_chmod = false

        -- Check if mode needs to be changed
        if want_mode ~= attr:mode() then
            needs_chmod = true
        end

        -- Check if ownership needs to be changed (only if uid/gid provided)
        if want_uid ~= nil or want_gid ~= nil then
            local target_uid = want_uid or attr:uid()
            local target_gid = want_gid or attr:gid()
            if target_uid ~= attr:uid() or target_gid ~= attr:gid() then
                needs_chown = true
            end
        end

        -- Skip if already compliant
        if not needs_chmod and not needs_chown then
            already_compliant = already_compliant + 1
            goto continue
        end

        -- Fix ownership first (if needed)
        if needs_chown then
            local target_uid = want_uid or attr:uid()
            local target_gid = want_gid or attr:gid()
            log.info(
                'permissions.set_attributes_for_all: chown %d:%d %s (was %d:%d)',
                target_uid,
                target_gid,
                path,
                attr:uid(),
                attr:gid()
            )
            local ok, err = _dependencies.fs_chown(path, target_uid, target_gid)
            if not ok then
                errors[#errors + 1] = string.format("chown failed on '%s': %s", path, tostring(err))
                goto continue
            end
        end

        -- Fix permissions (if needed)
        if needs_chmod then
            log.info('permissions.set_attributes_for_all: chmod %o %s (was %o)', want_mode, path, attr:mode())
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
        return nil,
            string.format('permissions.set_attributes_for_all: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.info(
        'permissions.set_attributes_for_all: changed %d, already compliant %d, skipped symlink %d, missing %d',
        changed,
        already_compliant,
        skipped_symlink,
        skipped_missing
    )
    return true
end

--------------------------------------------------------------------------------
-- Bootloader config fix helpers
--------------------------------------------------------------------------------

local function sorted_dir_entries(base_path)
    local entries = {}
    local iter, dir_obj = _dependencies.lfs_dir(base_path)
    if not iter then
        return nil, string.format("cannot list directory '%s'", tostring(base_path))
    end
    for name in iter, dir_obj do
        if name ~= '.' and name ~= '..' then
            entries[#entries + 1] = name
        end
    end
    table.sort(entries)
    return entries
end

local function collect_bootloader_config_paths(base_path, out)
    local attr = _dependencies.lfs_attributes(base_path)
    if not attr then
        return true
    end
    if attr.mode == 'file' then
        local name = base_path:match('([^/]+)$')
        if name == 'user.cfg' or name:match('^grub') then
            out[#out + 1] = base_path
        end
        return true
    end
    if attr.mode ~= 'directory' then
        return true
    end

    local entries, err = sorted_dir_entries(base_path)
    if not entries then
        return nil, err
    end

    for _, entry in ipairs(entries) do
        local ok, child_err = collect_bootloader_config_paths(base_path .. '/' .. entry, out)
        if not ok then
            return nil, child_err
        end
    end
    return true
end

local function bootloader_expected_mode(path)
    if tostring(path):match('^/boot/efi/EFI/') then
        return tonumber('700', 8)
    end
    return tonumber('600', 8)
end

-- Fix ownership and permissions of bootloader configuration files.
-- Dynamically discovers files under base_path (default "/boot") matching
-- "grub*" or "user.cfg". Applies uid=0, gid=0 and the expected mode (0600
-- for grub2 paths, 0700 for /boot/efi/EFI/ paths). Idempotent.
-- params: { base_path (optional, default "/boot") }
function M.fix_bootloader_config(params)
    params = params or {}
    local base_path = params.base_path or '/boot'

    local paths = {}
    local ok, err = collect_bootloader_config_paths(base_path, paths)
    if not ok then
        return nil, string.format('permissions.fix_bootloader_config: %s', err)
    end

    if #paths == 0 then
        log.warn('permissions.fix_bootloader_config: no bootloader config files found under %s', base_path)
        return true
    end

    local fixed_count = 0
    local total = #paths
    for _, path in ipairs(paths) do
        if fsutil.is_symlink(path, _dependencies) then
            log.warn("permissions.fix_bootloader_config: refusing to operate on symlink '%s'", path)
            goto continue
        end

        local attr = _dependencies.fs_stat(path)
        if not attr then
            log.warn('permissions.fix_bootloader_config: path not found: %s', path)
            goto continue
        end

        local expected_mode = bootloader_expected_mode(path)
        local needs_fix = false

        if attr:uid() ~= 0 then
            log.debug('permissions.fix_bootloader_config: chown 0:0 %s', path)
            local chown_ok, chown_err = _dependencies.fs_chown(path, 0, 0)
            if not chown_ok then
                log.warn("permissions.fix_bootloader_config: chown failed on '%s': %s", path, tostring(chown_err))
                goto continue
            end
            needs_fix = true
        elseif attr:gid() ~= 0 then
            log.debug('permissions.fix_bootloader_config: chgrp 0 %s', path)
            local chown_ok, chown_err = _dependencies.fs_chown(path, 0, 0)
            if not chown_ok then
                log.warn("permissions.fix_bootloader_config: chgrp failed on '%s': %s", path, tostring(chown_err))
                goto continue
            end
            needs_fix = true
        end

        if attr:mode() ~= expected_mode then
            log.debug('permissions.fix_bootloader_config: chmod %o %s', expected_mode, path)
            local chmod_ok, chmod_err = _dependencies.fs_chmod(path, expected_mode)
            if not chmod_ok then
                log.warn("permissions.fix_bootloader_config: chmod failed on '%s': %s", path, tostring(chmod_err))
                goto continue
            end
            needs_fix = true
        end

        if needs_fix then
            fixed_count = fixed_count + 1
        end

        ::continue::
    end

    if fixed_count == 0 then
        log.debug('permissions.fix_bootloader_config: all %d file(s) already configured correctly.', total)
    else
        log.info('permissions.fix_bootloader_config: fixed %d of %d file(s).', fixed_count, total)
    end

    return true
end

--------------------------------------------------------------------------------
-- sshd config fix helpers
--------------------------------------------------------------------------------

local function trim(s)
    return s:match('^%s*(.-)%s*$')
end

local function strip_comment(line)
    local pos = line:find('#')
    if pos then
        return line:sub(1, pos - 1)
    end
    return line
end

local function path_exists_as_file(path)
    local attr = _dependencies.lfs_attributes(path)
    return attr and attr.mode == 'file'
end

local function expand_include_spec(spec, base_dir)
    local paths = {}
    if spec:sub(1, 1) ~= '/' then
        spec = base_dir .. '/' .. spec
    end
    local dir = spec:match('^(.*)/[^/]+$') or '.'
    local pattern = spec:match('([^/]+)$')
    if dir and pattern then
        local entries = sorted_dir_entries(dir)
        if entries then
            local lua_pattern = '^' .. pattern:gsub('%*', '.*') .. '$'
            for _, entry in ipairs(entries) do
                if entry:match(lua_pattern) then
                    local full_path = dir .. '/' .. entry
                    if path_exists_as_file(full_path) then
                        paths[#paths + 1] = full_path
                    end
                end
            end
        end
    elseif path_exists_as_file(spec) then
        paths[#paths + 1] = spec
    end
    return paths
end

local function discover_include_files(path, base_dir, io_open)
    local file = io_open(path, 'r')
    if not file then
        return {}
    end
    local includes = {}
    for line in file:lines() do
        local active = trim(strip_comment(line))
        local directive, value = active:match('^(%S+)%s+(.+)$')
        if directive and directive:lower() == 'include' then
            for spec in tostring(value or ''):gmatch('%S+') do
                for _, include_path in ipairs(expand_include_spec(spec, base_dir)) do
                    includes[#includes + 1] = include_path
                end
            end
        end
    end
    file:close()
    return includes
end

local function append_unique(list, seen, item)
    if not seen[item] then
        list[#list + 1] = item
        seen[item] = true
    end
end

-- Fix ownership and permissions of sshd configuration files.
-- Discovers all config files by following Include directives.
-- Applies uid=0, gid=0 and mode 0600. Idempotent.
-- params: { path (optional, default "/etc/ssh/sshd_config"),
--           include_dir (optional, default "/etc/ssh/sshd_config.d") }
function M.fix_sshd_config_access(params)
    params = params or {}
    local main_path = params.path or '/etc/ssh/sshd_config'
    local include_dir = params.include_dir or '/etc/ssh/sshd_config.d'
    local base_dir = params.base_dir or '/etc/ssh'
    local expected_mode = tonumber('600', 8)

    -- Discover all config files (matching probe logic)
    local queue = {}
    local queued = {}
    local files = {}
    local seen_files = {}
    local io_open = _dependencies.io_open or io.open

    append_unique(queue, queued, main_path)
    local dropin_entries = sorted_dir_entries(include_dir)
    if dropin_entries then
        for _, entry in ipairs(dropin_entries) do
            if entry:match('%.conf$') then
                local full_path = include_dir .. '/' .. entry
                append_unique(queue, queued, full_path)
            end
        end
    end

    local index = 1
    while index <= #queue do
        local path = queue[index]
        index = index + 1
        if path_exists_as_file(path) then
            append_unique(files, seen_files, path)
            for _, include_path in ipairs(discover_include_files(path, base_dir, io_open)) do
                append_unique(queue, queued, include_path)
            end
        end
    end

    if #files == 0 then
        log.warn('permissions.fix_sshd_config_access: no sshd config files found')
        return true
    end

    local fixed_count = 0
    local total = #files
    for _, path in ipairs(files) do
        -- Resolve symlinks: operate on the target file
        local real_path = path
        local sym_attr = _dependencies.lfs_symlinkattributes(path)
        if sym_attr and sym_attr.mode == 'link' then
            -- Use fs_stat which follows symlinks to get the real path attributes
            local target_stat = _dependencies.fs_stat(path)
            if not target_stat then
                log.warn('permissions.fix_sshd_config_access: symlink target not found: %s', path)
                goto continue
            end
            -- fs_chmod and fs_chown follow symlinks, so operating on path modifies the target
            log.debug('permissions.fix_sshd_config_access: following symlink %s', path)
        end

        local attr = _dependencies.fs_stat(real_path)
        if not attr then
            log.warn('permissions.fix_sshd_config_access: path not found: %s', real_path)
            goto continue
        end

        local needs_fix = false

        if attr:uid() ~= 0 or attr:gid() ~= 0 then
            log.debug('permissions.fix_sshd_config_access: chown 0:0 %s', real_path)
            local chown_ok, chown_err = _dependencies.fs_chown(real_path, 0, 0)
            if not chown_ok then
                log.warn("permissions.fix_sshd_config_access: chown failed on '%s': %s", real_path, tostring(chown_err))
                goto continue
            end
            needs_fix = true
        end

        if attr:mode() ~= expected_mode then
            log.debug('permissions.fix_sshd_config_access: chmod %o %s', expected_mode, real_path)
            local chmod_ok, chmod_err = _dependencies.fs_chmod(real_path, expected_mode)
            if not chmod_ok then
                log.warn("permissions.fix_sshd_config_access: chmod failed on '%s': %s", real_path, tostring(chmod_err))
                goto continue
            end
            needs_fix = true
        end

        if needs_fix then
            fixed_count = fixed_count + 1
        end

        ::continue::
    end

    if fixed_count == 0 then
        log.debug('permissions.fix_sshd_config_access: all %d file(s) already configured correctly.', total)
    else
        log.info('permissions.fix_sshd_config_access: fixed %d of %d file(s).', fixed_count, total)
    end

    return true
end

return M
