local kmod = require('kmod')
local log = require('runtime.log')
local M = {}

local _default_dependencies = {
    ctx_new = function()
        return kmod.ctx_new()
    end
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.ctx_new = deps.ctx_new or _default_dependencies.ctx_new
end

M._test_set_dependencies()

local function get_ctx()
    log.debug("kmod.lua: Creating fresh kmod context...")
    local ctx = _dependencies.ctx_new()
    if not ctx then
        log.error("Failed to create new kmod context.")
    end
    return ctx
end

function M.is_loaded(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.is_loaded' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe is_loaded: Checking for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then return { loaded = false } end

    for mod in ctx:modules_from_loaded() do
        if mod:name() == module_name then
            log.debug(" -> Result for '%s': loaded = true", module_name)
            return { loaded = true }
        end
    end

    log.debug(" -> Result for '%s': loaded = false", module_name)
    return { loaded = false }
end

function M.is_blacklisted(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.is_blacklisted' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe is_blacklisted: Checking for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then return { blacklisted = false } end

    for name in ctx:config_blacklists() do
        if name == module_name then
            log.debug(" -> Result for '%s': blacklisted = true", module_name)
            return { blacklisted = true }
        end
    end

    log.debug(" -> Result for '%s': blacklisted = false", module_name)
    return { blacklisted = false }
end

function M.get_install_command(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.get_install_command' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe get_install_command: Checking for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then return { command = "none" } end

    for name, cmd in ctx:config_install_commands() do
        if name == module_name then
            log.debug(" -> Result for '%s': command = '%s'", module_name, cmd)
            return { command = cmd }
        end
    end

    log.debug(" -> Result for '%s': command = 'none'", module_name)
    return { command = "none" }
end

return M
