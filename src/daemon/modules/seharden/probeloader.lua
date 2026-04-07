local M = {}
local cache = {}
local PROBE_MODULE_PATH = "seharden.probes."

-- ToDo: maybe this func do not need a single lua file
-- just put it in seharden.engine
function M.get(probe_path)
    if type(probe_path) ~= "string" then
        return nil, "Probe path must be a string in 'module.function' format."
    end

    local probe_name, func_name = probe_path:match("^([^.]+)%.([^.]+)$")
    if not probe_name or not func_name then
        return nil, string.format("Invalid probe path '%s': expected 'module.function' format.", probe_path)
    end

    if not cache[probe_name] then
        local ok, mod = pcall(require, PROBE_MODULE_PATH .. probe_name)
        if not ok then
            return nil, "Module not found: " .. tostring(mod)
        end
        if type(mod) ~= 'table' then
            return nil, string.format("Probe module '%s' is not a valid module (did not return a table).", probe_name)
        end
        cache[probe_name] = mod
    end

    local probe = cache[probe_name]
    return probe and probe[func_name], probe_name .. "." .. func_name
end

return M
