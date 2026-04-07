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

return M
