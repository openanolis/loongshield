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

local function parse_numeric_id(value, field_name, context)
    if value == nil then
        return nil
    end

    local parsed = tonumber(value)
    if not parsed or parsed < 0 or parsed ~= math.floor(parsed) then
        return nil,
            string.format("%s: invalid %s '%s'", context or 'permissions.set_attributes', field_name, tostring(value))
    end

    return parsed
end

--- Parse a mode parameter as octal when given as a string.
-- Profiles pass modes as quoted strings ("0600") because unquoted leading-0
-- integers are read by lyaml as decimal (600); numeric values (tests, legacy
-- callers) are used as-is. Returns nil for invalid values.
local function parse_mode_param(value)
    if value == nil then
        return nil
    end
    if type(value) == 'number' then
        return value
    end
    return tonumber(value, 8)
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
        local want_mode = parse_mode_param(params.mode)
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
        want_mode = parse_mode_param(params.mode)
        if not want_mode then
            return nil, string.format("permissions.set_attributes_for_all: invalid mode '%s'", tostring(params.mode))
        end
    end

    if not want_mode then
        return nil, "permissions.set_attributes_for_all: requires 'mode' parameter"
    end

    local want_uid, uid_err = parse_numeric_id(params.uid, 'uid', 'permissions.set_attributes_for_all')
    if uid_err then
        return nil, uid_err
    end

    local want_gid, gid_err = parse_numeric_id(params.gid, 'gid', 'permissions.set_attributes_for_all')
    if gid_err then
        return nil, gid_err
    end

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
-- World-writable and unowned file fix helpers
--------------------------------------------------------------------------------

local WORLD_WRITABLE_BIT = tonumber('0002', 8)
local STICKY_BIT = tonumber('1000', 8)
local SUID_BIT = tonumber('4000', 8)
local SGID_BIT = tonumber('2000', 8)

--- Special filesystem entries that must never be chmod'd/chown'd blindly.
local SPECIAL_MODES = {
    ['socket'] = true,
    ['fifo'] = true,
    ['device'] = true,
    ['block device'] = true,
}

local function is_special_entry(lfs_attr)
    return lfs_attr ~= nil and SPECIAL_MODES[lfs_attr.mode] == true
end

local function has_setid_bit(mode)
    return mode % (SUID_BIT * 2) >= SUID_BIT or mode % (SGID_BIT * 2) >= SGID_BIT
end

--- Remove world-writable permission from a list of paths (conservative).
-- Directories only gain the sticky bit (their world-writable permission is
-- kept, since services may depend on it); regular files lose the
-- world-writable bit. Setuid/setgid files and special entries (sockets,
-- fifos, devices) are skipped rather than modified.
-- Idempotent: skips entries that are already compliant.
-- params: { list = { details = { { path = "..." }, ... } } }
function M.remove_world_writable(params)
    if not params or not params.list then
        return nil, 'permissions.remove_world_writable: requires list parameter'
    end
    local entries = params.list.details
    if not entries or type(entries) ~= 'table' then
        return nil, 'permissions.remove_world_writable: list.details must be a table'
    end

    local changed = 0
    local skipped_symlink = 0
    local skipped_missing = 0
    local skipped_special = 0
    local skipped_setid = 0
    local errors = {}

    for _, entry in ipairs(entries) do
        local path = entry.path
        if not path then
            goto continue
        end

        if fsutil.is_symlink(path, _dependencies) then
            skipped_symlink = skipped_symlink + 1
            goto continue
        end

        local attr = _dependencies.fs_stat(path)
        if not attr then
            skipped_missing = skipped_missing + 1
            goto continue
        end

        local file_attr = _dependencies.lfs_attributes(path)
        if is_special_entry(file_attr) then
            skipped_special = skipped_special + 1
            goto continue
        end

        local current_mode = attr:mode()

        if file_attr and file_attr.mode == 'directory' then
            -- Directories: only ensure the sticky bit; keep permissions.
            if current_mode % (STICKY_BIT * 2) >= STICKY_BIT then
                goto continue
            end
            local new_mode = current_mode + STICKY_BIT
            log.info('permissions.remove_world_writable: chmod %o %s (was %o)', new_mode, path, current_mode)
            local ok, err = _dependencies.fs_chmod(path, new_mode)
            if not ok then
                errors[#errors + 1] = string.format("chmod failed on '%s': %s", path, tostring(err))
                goto continue
            end
            changed = changed + 1
            goto continue
        end

        -- Regular files: drop world-writable bit, skip setuid/setgid.
        if current_mode % (WORLD_WRITABLE_BIT * 2) < WORLD_WRITABLE_BIT then
            -- Not world-writable, already compliant
            goto continue
        end
        if has_setid_bit(current_mode) then
            skipped_setid = skipped_setid + 1
            goto continue
        end

        local new_mode = current_mode - WORLD_WRITABLE_BIT
        log.info('permissions.remove_world_writable: chmod %o %s (was %o)', new_mode, path, current_mode)
        local ok, err = _dependencies.fs_chmod(path, new_mode)
        if not ok then
            errors[#errors + 1] = string.format("chmod failed on '%s': %s", path, tostring(err))
            goto continue
        end
        changed = changed + 1

        ::continue::
    end

    if #errors > 0 then
        return nil,
            string.format('permissions.remove_world_writable: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.info(
        'permissions.remove_world_writable: changed %d, skipped symlink %d, missing %d, special %d, setid %d',
        changed,
        skipped_symlink,
        skipped_missing,
        skipped_special,
        skipped_setid
    )
    return true
end

--- Load /etc/passwd uid -> primary gid map (numeric ids only).
local function load_user_primary_gids()
    local gids = {}
    local f = _dependencies.io_open('/etc/passwd', 'r')
    if not f then
        return gids
    end
    for line in f:lines() do
        local uid, gid = line:match('^[^:]+:[^:]*:(%d+):(%d+)')
        if uid then
            gids[tonumber(uid)] = tonumber(gid)
        end
    end
    f:close()
    return gids
end

--- Load the set of group ids that exist in /etc/group.
local function load_group_ids()
    local ids = {}
    local f = _dependencies.io_open('/etc/group', 'r')
    if not f then
        return ids
    end
    for line in f:lines() do
        local gid = line:match('^[^:]+:[^:]*:(%d+)')
        if gid then
            ids[tonumber(gid)] = true
        end
    end
    f:close()
    return ids
end

--- Assign ownership to a list of unowned paths (conservative).
-- Only the missing half of the ownership is repaired: an unowned uid is set
-- to root (gid kept), an ungrouped gid is set to the owner's primary group
-- from /etc/passwd (falling back to the `users` gid 100). Setuid/setgid
-- files and special entries are skipped rather than modified.
-- Idempotent: skips entries that are already fully owned.
-- params: { list = { details = { { path = "..." }, ... } } }
function M.fix_unowned(params)
    if not params or not params.list then
        return nil, 'permissions.fix_unowned: requires list parameter'
    end
    local entries = params.list.details
    if not entries or type(entries) ~= 'table' then
        return nil, 'permissions.fix_unowned: list.details must be a table'
    end

    local user_primary_gids = load_user_primary_gids()
    local known_group_ids = load_group_ids()

    local changed = 0
    local skipped_symlink = 0
    local skipped_missing = 0
    local skipped_special = 0
    local skipped_setid = 0
    local errors = {}

    for _, entry in ipairs(entries) do
        local path = entry.path
        if not path then
            goto continue
        end

        if fsutil.is_symlink(path, _dependencies) then
            skipped_symlink = skipped_symlink + 1
            goto continue
        end

        local attr = _dependencies.fs_stat(path)
        if not attr then
            skipped_missing = skipped_missing + 1
            goto continue
        end

        local file_attr = _dependencies.lfs_attributes(path)
        if is_special_entry(file_attr) then
            skipped_special = skipped_special + 1
            goto continue
        end
        if has_setid_bit(attr:mode()) then
            skipped_setid = skipped_setid + 1
            goto continue
        end

        local uid = attr:uid()
        local gid = attr:gid()
        local uid_known = uid == 0 or user_primary_gids[uid] ~= nil
        local gid_known = gid == 0 or known_group_ids[gid] == true
        if uid_known and gid_known then
            -- Fully owned already (or the probe listed it conservatively).
            goto continue
        end

        local want_uid = uid_known and uid or 0
        local want_gid = gid_known and gid or (user_primary_gids[uid] or 100)

        log.info('permissions.fix_unowned: chown %d:%d %s (was %d:%d)', want_uid, want_gid, path, uid, gid)
        local ok, err = _dependencies.fs_chown(path, want_uid, want_gid)
        if not ok then
            errors[#errors + 1] = string.format("chown failed on '%s': %s", path, tostring(err))
            goto continue
        end
        changed = changed + 1

        ::continue::
    end

    if #errors > 0 then
        return nil, string.format('permissions.fix_unowned: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.info(
        'permissions.fix_unowned: changed %d, skipped symlink %d, missing %d, special %d, setid %d',
        changed,
        skipped_symlink,
        skipped_missing,
        skipped_special,
        skipped_setid
    )
    return true
end

--------------------------------------------------------------------------------
-- Ownership fix helper (uid/gid only, no mode change)
--------------------------------------------------------------------------------

--- Assign ownership (uid/gid) to a list of paths without changing mode.
-- Idempotent: skips files already owned by the target uid:gid.
-- params: { list = { details = { { path = "..." }, ... } }, uid (default 0), gid (default 0) }
function M.fix_ownership(params)
    if not params or not params.list then
        return nil, 'permissions.fix_ownership: requires list parameter'
    end
    local entries = params.list.details
    if not entries or type(entries) ~= 'table' then
        return nil, 'permissions.fix_ownership: list.details must be a table'
    end

    local want_uid, uid_err = parse_numeric_id(params.uid or 0, 'uid', 'permissions.fix_ownership')
    if uid_err then
        return nil, uid_err
    end
    local want_gid, gid_err = parse_numeric_id(params.gid or 0, 'gid', 'permissions.fix_ownership')
    if gid_err then
        return nil, gid_err
    end

    local changed = 0
    local skipped_symlink = 0
    local skipped_missing = 0
    local errors = {}

    for _, entry in ipairs(entries) do
        local path = entry.path
        if not path then
            goto continue
        end

        if fsutil.is_symlink(path, _dependencies) then
            skipped_symlink = skipped_symlink + 1
            goto continue
        end

        local attr = _dependencies.fs_stat(path)
        if not attr then
            skipped_missing = skipped_missing + 1
            goto continue
        end

        if attr:uid() == want_uid and attr:gid() == want_gid then
            goto continue
        end

        log.info('permissions.fix_ownership: chown %d:%d %s (was %d:%d)', want_uid, want_gid, path, attr:uid(), attr:gid())
        local ok, err = _dependencies.fs_chown(path, want_uid, want_gid)
        if not ok then
            errors[#errors + 1] = string.format("chown failed on '%s': %s", path, tostring(err))
            goto continue
        end
        changed = changed + 1

        ::continue::
    end

    if #errors > 0 then
        return nil, string.format('permissions.fix_ownership: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.info(
        'permissions.fix_ownership: changed %d, skipped symlink %d, missing %d',
        changed,
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
-- sshd config fix (delegated to sshd_config module)
--------------------------------------------------------------------------------

-- Fix ownership and permissions of sshd configuration files.
-- Discovers all config files by following Include directives.
-- Applies uid=0, gid=0 and mode 0600. Idempotent.
-- params: { path (optional, default "/etc/ssh/sshd_config"),
--           include_dir (optional, default "/etc/ssh/sshd_config.d"),
--           base_dir (optional, default "/etc/ssh") }
function M.fix_sshd_config_access(params)
    local sshd_config = require('seharden.enforcers.sshd_config')
    -- Pass through dependencies for testing
    sshd_config._test_set_dependencies(_dependencies)
    return sshd_config.fix_sshd_config_access(params)
end

return M
