local M = {}

function M.lookup_context_value(key, contexts)
    local value = contexts
    for part in key:gmatch("([^.]+)") do
        if type(value) == "table" and value[part] ~= nil then
            value = value[part]
        else
            return nil
        end
    end
    return value
end

function M.resolve_value(template, contexts)
    if type(template) ~= "string" then
        if type(template) == "table" then
            local resolved = {}
            for key, value in pairs(template) do
                resolved[M.resolve_value(key, contexts)] = M.resolve_value(value, contexts)
            end
            return resolved
        end
        return template
    end

    local full_key = template:match("^%%{([^}]+)}$")
    if full_key then
        local value = M.lookup_context_value(full_key, contexts)
        if value == nil then
            return template
        end
        return value
    end

    return template:gsub("%%{([^}]+)}", function(key)
        local value = M.lookup_context_value(key, contexts)

        if value == nil or type(value) == "table" then
            return "%{" .. key .. "}"
        end

        return tostring(value)
    end)
end

return M
