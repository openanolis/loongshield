local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local sshd_config_files = require('seharden.shared.sshd_config_files')
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

-- Discover all sshd configuration files by following Include directives.
-- Returns a list of file paths.
function M.discover_sshd_config_files(main_path, include_dir, base_dir)
    return sshd_config_files.discover({
        path = main_path,
        include_dir = include_dir,
        base_dir = base_dir,
        io_open = _dependencies.io_open,
        lfs_attributes = _dependencies.lfs_attributes,
        lfs_dir = _dependencies.lfs_dir,
    })
end

-- Fix ownership and permissions of sshd configuration files.
-- Discovers all config files by following Include directives.
-- Applies uid=0, gid=0 and mode 0600. Idempotent.
-- params: { path (optional, default "/etc/ssh/sshd_config"),
--           include_dir (optional, default "/etc/ssh/sshd_config.d"),
--           base_dir (optional, default "/etc/ssh") }
function M.fix_sshd_config_access(params)
    params = params or {}
    local main_path = params.path or '/etc/ssh/sshd_config'
    local include_dir = params.include_dir or '/etc/ssh/sshd_config.d'
    local base_dir = params.base_dir or '/etc/ssh'
    local expected_mode = tonumber('600', 8)

    local files = M.discover_sshd_config_files(main_path, include_dir, base_dir)

    if #files == 0 then
        log.warn('sshd_config.fix_sshd_config_access: no sshd config files found')
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
                log.warn('sshd_config.fix_sshd_config_access: symlink target not found: %s', path)
                goto continue
            end
            -- fs_chmod and fs_chown follow symlinks, so operating on path modifies the target
            log.debug('sshd_config.fix_sshd_config_access: following symlink %s', path)
        end

        local attr = _dependencies.fs_stat(real_path)
        if not attr then
            log.warn('sshd_config.fix_sshd_config_access: path not found: %s', real_path)
            goto continue
        end

        local needs_fix = false

        if attr:uid() ~= 0 or attr:gid() ~= 0 then
            log.debug('sshd_config.fix_sshd_config_access: chown 0:0 %s', real_path)
            local chown_ok, chown_err = _dependencies.fs_chown(real_path, 0, 0)
            if not chown_ok then
                log.warn("sshd_config.fix_sshd_config_access: chown failed on '%s': %s", real_path, tostring(chown_err))
                goto continue
            end
            needs_fix = true
        end

        if attr:mode() ~= expected_mode then
            log.debug('sshd_config.fix_sshd_config_access: chmod %o %s', expected_mode, real_path)
            local chmod_ok, chmod_err = _dependencies.fs_chmod(real_path, expected_mode)
            if not chmod_ok then
                log.warn("sshd_config.fix_sshd_config_access: chmod failed on '%s': %s", real_path, tostring(chmod_err))
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
        log.debug('sshd_config.fix_sshd_config_access: all %d file(s) already configured correctly.', total)
    else
        log.info('sshd_config.fix_sshd_config_access: fixed %d of %d file(s).', fixed_count, total)
    end

    return true
end

return M
