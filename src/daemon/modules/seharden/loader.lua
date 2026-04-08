local M = {}

local PROBE_CACHE = {}
local ENFORCER_CACHE = {}

local function get_from(module_kind, module_path, cache, path)
    if type(path) ~= "string" then
        return nil, string.format("%s path must be a string in 'module.function' format.", module_kind)
    end

    local module_name, func_name = path:match("^([^.]+)%.([^.]+)$")
    if not module_name or not func_name then
        return nil, string.format("Invalid %s path '%s': expected 'module.function' format.",
            module_kind:lower(), path)
    end

    if not cache[module_name] then
        local ok, mod = pcall(require, module_path .. module_name)
        if not ok then
            return nil, "Module not found: " .. tostring(mod)
        end
        if type(mod) ~= "table" then
            return nil, string.format("%s module '%s' is not a valid module (did not return a table).",
                module_kind, module_name)
        end
        cache[module_name] = mod
    end

    local mod = cache[module_name]
    return mod and mod[func_name], module_name .. "." .. func_name
end

function M.get_probe(path)
    return get_from("Probe", "seharden.probes.", PROBE_CACHE, path)
end

function M.get_enforcer(path)
    return get_from("Enforcer", "seharden.enforcers.", ENFORCER_CACHE, path)
end

return M
