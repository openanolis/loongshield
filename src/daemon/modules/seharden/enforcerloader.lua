local M = {}
local cache = {}
local ENFORCER_MODULE_PATH = "seharden.enforcers."

function M.get(action_path)
    if type(action_path) ~= "string" then
        return nil, "Enforcer path must be a string in 'module.function' format."
    end

    local mod_name, func_name = action_path:match("^([^.]+)%.([^.]+)$")
    if not mod_name or not func_name then
        return nil, string.format("Invalid enforcer path '%s': expected 'module.function' format.", action_path)
    end

    if not cache[mod_name] then
        local ok, mod = pcall(require, ENFORCER_MODULE_PATH .. mod_name)
        if not ok then
            return nil, "Module not found: " .. tostring(mod)
        end
        if type(mod) ~= 'table' then
            return nil, string.format("Enforcer module '%s' is not a valid module (did not return a table).", mod_name)
        end
        cache[mod_name] = mod
    end

    local m = cache[mod_name]
    return m and m[func_name], mod_name .. "." .. func_name
end

return M
