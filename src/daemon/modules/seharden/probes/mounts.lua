local mount = require('mount')
local log = require('runtime.log')
local M = {}

local _default_dependencies = {
    mount_new_context = function()
        return mount.new_context()
    end
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.mount_new_context = deps.mount_new_context or _default_dependencies.mount_new_context
end

M._test_set_dependencies()

local function get_all_mounts()
    log.debug("Loading current mount table...")
    local mounts = {}
    local ctx = _dependencies.mount_new_context()
    if not ctx then
        log.error("Unable to create mount context.")
        return {}
    end

    local mtab = ctx:get_mtab()
    if not mtab then
        log.error("Unable to get current mount table.")
        return {}
    end

    for fs in mtab:fs() do
        local options_table = {}
        for opt in fs:options():gmatch("[^,]+") do
            options_table[opt] = true
        end
        mounts[fs:target()] = {
            exists = true, -- Explicitly state that it exists
            source = fs:source(),
            fstype = fs:fstype(),
            options = options_table
        }
    end
    return mounts
end

function M.get_mount_info(params)
    if not params or not params.path then
        return nil, "Probe 'mounts.get_mount_info' requires a 'path' parameter."
    end

    local mount_point = params.path
    local all_mounts = get_all_mounts()

    -- If the mount is not found in the cache, return a table indicating it doesn't exist.
    return all_mounts[mount_point] or { exists = false }
end

return M
