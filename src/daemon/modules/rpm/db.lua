local log = require('runtime.log')
local lfs = require('lfs')

local M = {}

local _default_dependencies = {
    lfs_attributes = lfs.attributes,
}

local _dependencies = {}
local cached_dbpath = nil
local cached_dbpath_checked = false
local applied_dbpath = nil

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.lfs_attributes = deps.lfs_attributes or _default_dependencies.lfs_attributes
    cached_dbpath = nil
    cached_dbpath_checked = false
    applied_dbpath = nil
end

M._test_set_dependencies()

local function add_candidate(candidates, seen, path)
    if type(path) ~= "string" then
        return
    end

    path = path:gsub("%s+$", "")
    if path == "" or path == "%{_dbpath}" or seen[path] then
        return
    end

    seen[path] = true
    candidates[#candidates + 1] = path
end

function M.detect_dbpath(rpm)
    if cached_dbpath_checked then
        return cached_dbpath
    end

    cached_dbpath_checked = true

    local candidates = {}
    local seen = {}

    local ok, configured_dbpath = pcall(rpm.getpath, "%{_dbpath}")
    if ok then
        add_candidate(candidates, seen, configured_dbpath)
    end

    add_candidate(candidates, seen, "/usr/lib/sysimage/rpm")
    add_candidate(candidates, seen, "/var/lib/rpm")

    for _, path in ipairs(candidates) do
        if _dependencies.lfs_attributes(path, "mode") == "directory" then
            cached_dbpath = path
            return path
        end
    end

    return nil
end

function M.create_ts(rpm)
    local dbpath = M.detect_dbpath(rpm)
    if dbpath then
        log.debug("Using RPM dbpath: %s", dbpath)
        if applied_dbpath ~= dbpath then
            rpm.pushmacro('_dbpath', dbpath)
            applied_dbpath = dbpath
        end
    else
        log.warn("RPM dbpath not detected; falling back to rpm defaults")
    end

    local ts = rpm.tscreate()
    ts:rootdir('/')
    return ts
end

return M
