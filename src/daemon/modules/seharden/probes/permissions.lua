local fs = require('fs')
local log = require('runtime.log')

local M = {}

local _default_dependencies = {
    fs_stat = fs.stat,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.fs_stat = deps.fs_stat or _default_dependencies.fs_stat
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

return M
