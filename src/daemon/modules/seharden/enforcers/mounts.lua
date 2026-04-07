local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    os_execute = os.execute,
    io_open    = io.open,
    os_rename  = os.rename,
    os_remove  = os.remove,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local FSTAB = "/etc/fstab"

local function run(cmd)
    local ok, _, code = _dependencies.os_execute(cmd)
    if ok == true or code == 0 then return true end
    return nil, string.format("command failed (exit %s): %s", tostring(code), cmd)
end

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function is_valid_mount_option(option)
    return type(option) == "string"
        and option ~= ""
        and not option:match("[%c%s,#]")
end

-- Add mount options to an existing fstab entry. Does not duplicate existing options.
local function add_fstab_options(mount_path, add_options)
    local lines = {}
    local entry_found = false
    local modified    = false

    if fsutil.is_symlink(FSTAB, _dependencies) then
        return nil, string.format("mounts.remount: refusing to overwrite symlink '%s'", FSTAB)
    end

    local f_in = _dependencies.io_open(FSTAB, "r")
    if not f_in then
        return nil, string.format("mounts.remount: cannot read %s", FSTAB)
    end

    for line in f_in:lines() do
        -- Match non-comment fstab lines: device mountpoint fstype options dump pass
        if not line:match("^%s*#") and line:match("%S") then
            local device, mp, fstype, opts, rest =
                line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s*(.*)")
            if mp == mount_path and device and opts then
                entry_found = true
                local opts_table = {}
                local opt_set = {}
                for opt in opts:gmatch("[^,]+") do
                    table.insert(opts_table, opt)
                    opt_set[opt] = true
                end
                local any_new = false
                for _, new_opt in ipairs(add_options) do
                    if not opt_set[new_opt] then
                        table.insert(opts_table, new_opt)
                        any_new = true
                    end
                end
                if any_new then
                    local new_opts = table.concat(opts_table, ",")
                    local new_line = string.format("%s\t%s\t%s\t%s\t%s",
                        device, mp, fstype, new_opts, rest)
                    table.insert(lines, new_line:match("^(.-)%s*$"))
                    modified = true
                else
                    table.insert(lines, line)
                end
                goto continue
            end
        end
        table.insert(lines, line)
        ::continue::
    end
    f_in:close()

    if not entry_found then
        log.warn("mounts.remount: no fstab entry for '%s' — live remount only, not persistent", mount_path)
        return true
    end
    if not modified then
        log.debug("mounts.remount: all options already present for '%s', skipping fstab write", mount_path)
        return true
    end

    return fsutil.write_lines_atomically(FSTAB, lines, "mounts.remount", _dependencies)
end

-- Remount a filesystem with additional options (live) and update fstab. Idempotent.
-- params: { path, add_options (list of strings, e.g. {"nodev","nosuid"}) }
function M.remount(params)
    if not params or not params.path or not params.add_options then
        return nil, "mounts.remount: requires 'path' and 'add_options' parameters"
    end

    local mount_path  = params.path
    local add_options = params.add_options
    if type(mount_path) ~= "string" or mount_path == "" or mount_path:match("[%c]") then
        return nil, "mounts.remount: 'path' must be a non-empty string without control characters"
    end
    if type(add_options) ~= "table" then
        return nil, "mounts.remount: 'add_options' must be a list"
    end
    for i, option in ipairs(add_options) do
        if not is_valid_mount_option(option) then
            return nil, string.format(
                "mounts.remount: add_options[%d] must be a mount option token without whitespace, commas, or control characters",
                i)
        end
    end

    local opts_str = "remount," .. table.concat(add_options, ",")
    log.debug("Enforcer mounts.remount: mount -o %s %s", opts_str, mount_path)
    local live_ok, live_err = run(string.format("mount -o %s %s 2>&1",
        shell_escape(opts_str), shell_escape(mount_path)))
    if not live_ok then
        log.warn("mounts.remount: live remount failed: %s", tostring(live_err))
    end

    -- Persist to fstab even if the live remount fails so the setting survives reboot.
    local fstab_ok, fstab_err = add_fstab_options(mount_path, add_options)
    if not fstab_ok then
        if not live_ok then
            return nil, string.format("mounts.remount: live remount failed: %s; %s",
                tostring(live_err), tostring(fstab_err))
        end
        return nil, fstab_err
    end

    if not live_ok then
        return nil, string.format("mounts.remount: live remount failed after persisting options: %s",
            tostring(live_err))
    end

    return true
end

return M
