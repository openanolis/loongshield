local M = {}

M.FORBIDDEN = {
    ['.forward'] = true,
    ['.rhosts'] = true,
}

M.DEFAULT_MAX_MODE = tonumber('644', 8)

M.STRICT_MAX_MODES = {
    ['.bash_history'] = tonumber('600', 8),
    ['.netrc'] = tonumber('600', 8),
}

function M.basename(path)
    return tostring(path):match('([^/]+)$') or tostring(path)
end

function M.is_forbidden(filename)
    return M.FORBIDDEN[filename] == true
end

function M.max_mode_for(filename)
    return M.STRICT_MAX_MODES[filename] or M.DEFAULT_MAX_MODE
end

function M.is_dot_entry(name)
    return type(name) == 'string' and name:match('^%.') ~= nil
end

function M.same_device_or_unknown(attr, root_dev)
    return attr ~= nil and (root_dev == nil or attr.dev == nil or attr.dev == root_dev)
end

return M
