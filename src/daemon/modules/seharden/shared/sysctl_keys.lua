local M = {}

local function is_valid_key(key)
    return type(key) == 'string' and key:match('^[a-zA-Z0-9_.]+$') ~= nil and key:match('%.%.') == nil
end

function M.normalize(key)
    if key == nil then
        return nil
    end
    key = tostring(key):gsub('^%-', '')
    return key:gsub('/', '.')
end

function M.is_valid(key)
    return is_valid_key(key)
end

function M.validate(key)
    key = M.normalize(key)
    if not is_valid_key(key) then
        return nil
    end
    return key
end

function M.procfs_path(key, procfs_root)
    key = M.validate(key)
    if not key then
        return nil
    end
    return tostring(procfs_root or '/proc/sys') .. '/' .. key:gsub('%.', '/')
end

return M
