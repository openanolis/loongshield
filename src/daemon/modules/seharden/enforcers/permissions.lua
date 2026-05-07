local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    fs_stat  = function(path) return require('fs').stat(path) end,
    fs_chmod = function(path, mode) return require('fs').chmod(path, mode) end,
    fs_chown = function(path, uid, gid) return require('fs').chown(path, uid, gid) end,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.fs_stat  = deps.fs_stat  or _default_dependencies.fs_stat
    _dependencies.fs_chmod = deps.fs_chmod or _default_dependencies.fs_chmod
    _dependencies.fs_chown = deps.fs_chown or _default_dependencies.fs_chown
    _dependencies.lfs_symlinkattributes = deps.lfs_symlinkattributes or _default_dependencies.lfs_symlinkattributes
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
        return nil, string.format("permissions.set_attributes: path not found: %s", path)
    end

    local want_uid, uid_err = parse_numeric_id(params.uid, "uid")
    if uid_err then
        return nil, uid_err
    end

    local want_gid, gid_err = parse_numeric_id(params.gid, "gid")
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
        log.debug("Enforcer permissions.set_attributes: chown %s:%s %s", want_uid, want_gid, path)
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
            log.debug("Enforcer permissions.set_attributes: chmod %o %s", want_mode, path)
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
    if not entries or type(entries) ~= "table" then
        return nil, "permissions.set_attributes_for_all: 'list' must contain a 'details' table"
    end

    local want_mode
    if params.mode ~= nil then
        want_mode = tonumber(params.mode)
        if not want_mode then
            return nil, string.format("permissions.set_attributes_for_all: invalid mode '%s'",
                tostring(params.mode))
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
            log.warn("permissions.set_attributes_for_all: path not found: %s", path)
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
            log.info("permissions.set_attributes_for_all: chown %d:%d %s (was %d:%d)",
                target_uid, target_gid, path, attr:uid(), attr:gid())
            local ok, err = _dependencies.fs_chown(path, target_uid, target_gid)
            if not ok then
                errors[#errors + 1] = string.format("chown failed on '%s': %s",
                    path, tostring(err))
                goto continue
            end
        end

        -- Fix permissions (if needed)
        if needs_chmod then
            log.info("permissions.set_attributes_for_all: chmod %o %s (was %o)",
                want_mode, path, attr:mode())
            local ok, err = _dependencies.fs_chmod(path, want_mode)
            if not ok then
                errors[#errors + 1] = string.format("chmod failed on '%s': %s",
                    path, tostring(err))
                goto continue
            end
        end

        changed = changed + 1

        ::continue::
    end

    if #errors > 0 then
        return nil, string.format(
            "permissions.set_attributes_for_all: %d error(s): %s",
            #errors, table.concat(errors, "; "))
    end

    log.info("permissions.set_attributes_for_all: changed %d, already compliant %d, skipped symlink %d, missing %d",
        changed, already_compliant, skipped_symlink, skipped_missing)
    return true
end

return M
