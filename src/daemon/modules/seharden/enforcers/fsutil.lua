local _lfs = (function() local ok, lib = pcall(require, 'lfs'); return ok and lib or nil end)()

local M = {}

function M.default_lfs_symlinkattributes(path)
    return _lfs and _lfs.symlinkattributes(path) or nil
end

function M.symlink_mode(path, deps)
    local attr = deps.lfs_symlinkattributes(path)
    if type(attr) == "table" then
        return attr.mode
    end
    return attr
end

function M.is_symlink(path, deps)
    return M.symlink_mode(path, deps) == "link"
end

local function split_path(path)
    local dir = path:match("^(.*)/[^/]+$") or "."
    local base = path:match("([^/]+)$") or path
    return dir, base
end

function M.write_lines_atomically(path, lines, context, deps)
    local dir, base = split_path(path)
    local nonce = tostring({}):match("0x%x+") or tostring(os.time())
    local tmp_path = string.format("%s/.%s.loongshield.tmp.%s", dir, base, nonce)

    if M.is_symlink(path, deps) then
        return nil, string.format("%s: refusing to overwrite symlink '%s'", context, path)
    end

    local f_out, err = deps.io_open(tmp_path, "w")
    if not f_out then
        return nil, string.format("%s: cannot open temp file '%s': %s", context, tmp_path, tostring(err))
    end

    for _, line in ipairs(lines) do
        f_out:write(line .. "\n")
    end

    local closed, close_err = f_out:close()
    if not closed then
        deps.os_remove(tmp_path)
        return nil, string.format("%s: cannot close temp file '%s': %s", context, tmp_path, tostring(close_err))
    end

    if M.is_symlink(path, deps) then
        deps.os_remove(tmp_path)
        return nil, string.format("%s: refusing to replace symlink '%s'", context, path)
    end

    local ok, rename_err = deps.os_rename(tmp_path, path)
    if not ok then
        deps.os_remove(tmp_path)
        return nil, string.format("%s: cannot replace '%s': %s", context, path, tostring(rename_err))
    end

    return true
end

function M.write_lines_atomically_preserving_attrs(path, lines, context, deps)
    local stat = deps.fs_stat and deps.fs_stat(path) or nil
    local ok, err = M.write_lines_atomically(path, lines, context, deps)
    if not ok then
        return nil, err
    end

    if stat then
        if deps.fs_chown then
            local owner_ok, owner_err = deps.fs_chown(path, stat:uid(), stat:gid())
            if not owner_ok then
                return nil, string.format("%s: cannot restore owner on '%s': %s",
                    context, path, tostring(owner_err))
            end
        end

        if deps.fs_chmod then
            local mode_ok, mode_err = deps.fs_chmod(path, stat:mode())
            if not mode_ok then
                return nil, string.format("%s: cannot restore mode on '%s': %s",
                    context, path, tostring(mode_err))
            end
        end
    end

    return true
end

function M.append_unique_line(path, target_line, context, deps)
    local lines = {}

    if M.is_symlink(path, deps) then
        return nil, string.format("%s: refusing to overwrite symlink '%s'", context, path)
    end

    local f_in = deps.io_open(path, "r")
    if f_in then
        for line in f_in:lines() do
            lines[#lines + 1] = line
            if line == target_line then
                f_in:close()
                return true
            end
        end
        f_in:close()
    end

    lines[#lines + 1] = target_line
    return M.write_lines_atomically_preserving_attrs(path, lines, context, deps)
end

return M
