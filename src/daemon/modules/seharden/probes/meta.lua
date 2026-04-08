local loader = require('seharden.loader')
local log = require('runtime.log')
local M = {}

local function resolve_item_template(template, item)
    if type(template) == "table" then
        local resolved = {}
        for k, v in pairs(template) do
            resolved[resolve_item_template(k, item)] = resolve_item_template(v, item)
        end
        return resolved
    end

    if type(template) ~= 'string' then
        return template
    end

    local full_key = template:match("^%%{item%.([^}]+)}$")
    if full_key then
        local value = item[full_key]
        if value == nil then
            return template
        end
        return value
    end

    return template:gsub("%%{item%.([^}]+)}", function(key)
        local value = item[key]
        if value == nil or type(value) == "table" then
            return "%{item." .. key .. "}"
        end
        return tostring(value)
    end)
end

---
-- A meta-probe that applies a given probe function to each item of a source list.
-- This enables a powerful data pipeline pattern in the YAML rules.
function M.map(params, probed_data)
    if not params or not probed_data or
        not (params.source_probe and params.apply_func and params.params_template) then
        return nil, "probe.map requires 'source_probe', 'apply_func', and 'params_template' parameters."
    end

    local source_list = probed_data[params.source_probe]
    if type(source_list) == "table" and source_list[1] == nil and type(source_list.details) == "table" then
        source_list = source_list.details
    end

    if not source_list or type(source_list) ~= 'table' then
        return nil, string.format("Source probe '%s' for map did not return a list.", params.source_probe)
    end

    local probe_func = loader.get_probe(params.apply_func)
    if not probe_func then
        return nil, string.format("Function '%s' not found for map.", params.apply_func)
    end

    local results = {}
    for _, item in ipairs(source_list) do
        local dynamic_params = resolve_item_template(params.params_template, item)
        local ok, res, err = pcall(probe_func, dynamic_params, probed_data)
        if not ok then
            return nil, string.format("Probe '%s' failed in map loop: %s",
                params.apply_func, tostring(res))
        end
        if res == nil and err ~= nil then
            return nil, string.format("Probe '%s' failed in map loop: %s",
                params.apply_func, tostring(err))
        end
        if type(res) ~= "table" then
            return nil, string.format("Probe '%s' in map loop returned non-table result", params.apply_func)
        end

        -- Merge the original item's data with the new result for context.
        table.insert(results, setmetatable(res, { __index = item }))
    end
    return results
end

return M
