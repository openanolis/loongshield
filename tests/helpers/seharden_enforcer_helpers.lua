local M = {}

function M.make_fs_attr(uid, gid, mode)
    return {
        uid = function()
            return uid
        end,
        gid = function()
            return gid
        end,
        mode = function()
            return mode
        end,
    }
end

function M.merge_tables(...)
    local result = {}
    for index = 1, select('#', ...) do
        local tbl = select(index, ...)
        for key, value in pairs(tbl or {}) do
            result[key] = value
        end
    end
    return result
end

function M.split_content_lines(content)
    local lines = {}
    content = tostring(content or '')
    if content == '' then
        return lines
    end

    if content:sub(-1) ~= '\n' then
        content = content .. '\n'
    end

    for line in content:gmatch('(.-)\n') do
        lines[#lines + 1] = line
    end

    return lines
end

function M.make_fake_text_fs(initial_files, initial_attrs, directory_entries)
    local files = {}
    for path, content in pairs(initial_files or {}) do
        files[path] = content
    end

    local attrs = {}
    for path, attr in pairs(initial_attrs or {}) do
        attrs[path] = {
            type = attr.type,
            uid = attr.uid,
            gid = attr.gid,
            mode = attr.mode,
        }
    end

    local pending = {}
    local writes = {}

    local function ensure_attr(path)
        if not attrs[path] then
            attrs[path] = {}
        end
        return attrs[path]
    end

    local deps = {}

    deps.io_open = function(path, mode)
        if mode == 'r' then
            local content = files[path]
            if content == nil then
                return nil, 'not found'
            end

            local lines = M.split_content_lines(content)
            local index = 0
            return {
                lines = function()
                    return function()
                        index = index + 1
                        return lines[index]
                    end
                end,
                read = function(_, fmt)
                    if fmt == '*a' then
                        return content
                    end
                    return nil
                end,
                close = function()
                    return true
                end,
            }
        end

        if mode == 'w' then
            local buffer = {}
            return {
                write = function(_, chunk)
                    buffer[#buffer + 1] = chunk
                end,
                close = function()
                    pending[path] = table.concat(buffer)
                    return true
                end,
            }
        end

        return nil, 'unsupported mode'
    end

    deps.os_rename = function(src, dst)
        if pending[src] == nil then
            return nil, 'missing temp file'
        end

        files[dst] = pending[src]
        pending[src] = nil
        writes[#writes + 1] = {
            src = src,
            dst = dst,
            content = files[dst],
        }

        local attr = ensure_attr(dst)
        attr.type = attr.type or 'file'
        return true
    end

    deps.os_remove = function(path)
        pending[path] = nil
        return true
    end

    deps.lfs_attributes = function(path)
        local attr = attrs[path]
        if attr then
            return { mode = attr.type or 'file' }
        end
        if files[path] ~= nil then
            return { mode = 'file' }
        end
        return nil
    end

    deps.lfs_symlinkattributes = function(path)
        local attr = attrs[path]
        if attr and attr.type == 'link' then
            return { mode = 'link' }
        end
        return deps.lfs_attributes(path)
    end

    deps.lfs_dir = function(path)
        local entries = directory_entries and directory_entries[path] or {}
        local index = 0
        return function()
            index = index + 1
            return entries[index]
        end
    end

    deps.fs_stat = function(path)
        if files[path] == nil and attrs[path] == nil then
            return nil
        end
        local attr = attrs[path] or {}
        return M.make_fs_attr(attr.uid or 0, attr.gid or 0, attr.mode or 420)
    end

    deps.fs_chown = function(path, uid, gid)
        local attr = ensure_attr(path)
        attr.uid = uid
        attr.gid = gid
        attr.type = attr.type or 'file'
        return true
    end

    deps.fs_chmod = function(path, mode)
        local attr = ensure_attr(path)
        attr.mode = mode
        attr.type = attr.type or 'file'
        return true
    end

    return deps, files, attrs, writes
end

return M
