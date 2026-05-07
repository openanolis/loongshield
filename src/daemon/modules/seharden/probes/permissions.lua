local fs = require('fs')
local log = require('runtime.log')

local M = {}

local _default_dependencies = {
    fs_stat = fs.stat,
    fs_get_gid = fs.get_gid,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

function M.get_attributes(params)
    if not params or not params.path then
        return nil, "Probe 'permissions.get_attributes' requires a 'path' parameter."
    end

    local attr = _dependencies.fs_stat(params.path)
    if not attr then
        return { exists = false }
    end
    log.debug("uid: %s, gid: %s, mode: %s", attr:uid(), attr:gid(), attr:mode())
    return {
        exists = true,
        uid = attr:uid(),
        gid = attr:gid(),
        mode = attr:mode()
    }
end

function M.get_group_id(params)
    if not params or not params.name then
        return nil, "Probe 'permissions.get_group_id' requires a 'name' parameter."
    end

    local gid = _dependencies.fs_get_gid(params.name)
    return {
        exists = gid ~= nil,
        gid = gid,
    }
end

return M
