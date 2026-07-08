local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local text = require('seharden.shared.text')
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
        local active = text.trim(strip_comment(line))
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

-- Discover all sshd configuration files by following Include directives.
-- Returns a list of file paths.
function M.discover_sshd_config_files(main_path, include_dir, base_dir)
    main_path = main_path or '/etc/ssh/sshd_config'
    include_dir = include_dir or '/etc/ssh/sshd_config.d'
    base_dir = base_dir or '/etc/ssh'

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

    return files
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
