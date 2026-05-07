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

local function is_loaded_in_context(ctx, module_name)
    local requested_name = module_name:gsub("-", "_")
    for mod in ctx:modules_from_loaded() do
        if tostring(mod:name()):gsub("-", "_") == requested_name then
            return true
        end
    end
    return false
end

local function is_blacklisted_in_context(ctx, module_name)
    local requested_name = module_name:gsub("-", "_")
    for name in ctx:config_blacklists() do
        if tostring(name):gsub("-", "_") == requested_name then
            return true
        end
    end
    return false
end

local function get_install_command_in_context(ctx, module_name)
    local requested_name = module_name:gsub("-", "_")
    for name, cmd in ctx:config_install_commands() do
        if tostring(name):gsub("-", "_") == requested_name then
            return cmd
        end
    end
    return "none"
end

local function lookup_module_in_context(ctx, module_name)
    local candidates = { module_name, module_name:gsub("-", "_") }
    local seen = {}
    local last_errno
    local last_err

    for _, candidate in ipairs(candidates) do
        if not seen[candidate] then
            local mod, errno, err = ctx:module_from_name_lookup(candidate)
            if mod then
                return mod, nil, nil, candidate
            end
            last_errno = errno
            last_err = err
            seen[candidate] = true
        end
    end

    return nil, last_errno, last_err
end

local function get_availability_in_context(ctx, module_name)
    local mod, errno, err, lookup_name = lookup_module_in_context(ctx, module_name)
    if not mod then
        return {
            available = false,
            builtin = false,
            errno = errno,
            reason = err,
        }
    end

    local state = "unknown"
    if type(mod.initstate) == "function" then
        state = mod:initstate() or "unknown"
    end

    local path
    if type(mod.path) == "function" then
        path = mod:path()
    end

    return {
        available = true,
        builtin = state == "builtin",
        state = state,
        path = path,
        lookup_name = lookup_name,
    }
end

local function is_disabled_install_command(command)
    return command == "/bin/true" or command == "/bin/false"
end

function M.is_loaded(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.is_loaded' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe is_loaded: Checking for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then return { loaded = false } end

    local loaded = is_loaded_in_context(ctx, module_name)
    log.debug(" -> Result for '%s': loaded = %s", module_name, tostring(loaded))
    return { loaded = loaded }
end

function M.is_blacklisted(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.is_blacklisted' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe is_blacklisted: Checking for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then return { blacklisted = false } end

    local blacklisted = is_blacklisted_in_context(ctx, module_name)
    log.debug(" -> Result for '%s': blacklisted = %s", module_name, tostring(blacklisted))
    return { blacklisted = blacklisted }
end

function M.get_install_command(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.get_install_command' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe get_install_command: Checking for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then return { command = "none" } end

    local command = get_install_command_in_context(ctx, module_name)
    log.debug(" -> Result for '%s': command = '%s'", module_name, command)
    return { command = command }
end

function M.get_availability(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.get_availability' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe get_availability: Checking for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then
        return nil, "Failed to create kmod context."
    end

    local availability = get_availability_in_context(ctx, module_name)
    log.debug(
        " -> Result for '%s': available = %s, state = '%s'",
        module_name,
        tostring(availability.available),
        tostring(availability.state)
    )
    return availability
end

function M.get_disable_state(params)
    if not params or not params.name then
        return nil, "Probe 'kmod.get_disable_state' requires a 'name' parameter."
    end

    local module_name = params.name
    log.debug("Probe get_disable_state: Checking disable state for module '%s'", module_name)

    local ctx = get_ctx()
    if not ctx then
        return nil, "Failed to create kmod context."
    end

    local availability = get_availability_in_context(ctx, module_name)
    local loaded = is_loaded_in_context(ctx, module_name)
    local blacklisted = is_blacklisted_in_context(ctx, module_name)
    local install_command = get_install_command_in_context(ctx, module_name)
    local install_command_disabled = is_disabled_install_command(install_command)
    local disabled = (not availability.available) or (
        not availability.builtin and
        not loaded and
        blacklisted and
        install_command_disabled
    )

    log.debug(" -> Result for '%s': disabled = %s", module_name, tostring(disabled))
    return {
        available = availability.available,
        builtin = availability.builtin,
        state = availability.state,
        path = availability.path,
        lookup_name = availability.lookup_name,
        errno = availability.errno,
        reason = availability.reason,
        loaded = loaded,
        blacklisted = blacklisted,
        install_command = install_command,
        install_command_disabled = install_command_disabled,
        disabled = disabled,
    }
end

return M
