local comparators = require('seharden.comparators')

local M = {}

local MODULE_FUNCTION_PATTERN = "^[%w_]+%.[%w_]+$"

local function is_non_empty_string(value)
    return type(value) == "string" and value ~= ""
end

local function is_list(value)
    if type(value) ~= "table" then
        return false
    end

    local count = 0
    for key, _ in pairs(value) do
        if type(key) ~= "number" or key < 1 or key % 1 ~= 0 then
            return false
        end
        count = count + 1
    end

    for index = 1, count do
        if value[index] == nil then
            return false
        end
    end

    return true
end

local function validate_module_function_path(value, field_name)
    if not is_non_empty_string(value) then
        return nil, string.format("%s must be a non-empty string in 'module.function' format.", field_name)
    end

    if not value:match(MODULE_FUNCTION_PATTERN) then
        return nil, string.format("%s must be in 'module.function' format.", field_name)
    end

    return true
end

function M.normalize_probe_tasks(rule_probes)
    if type(rule_probes) ~= "table" then
        return {}
    end

    if rule_probes.func ~= nil then
        return { rule_probes }
    end

    return rule_probes
end

local function validate_probe_tasks(rule_probes, field_name)
    if rule_probes == nil then
        return true
    end

    if type(rule_probes) ~= "table" then
        return nil, string.format("%s must be a probe task or list of probe tasks.", field_name)
    end

    local uses_single_task_shorthand = rule_probes.func ~= nil
    local tasks = M.normalize_probe_tasks(rule_probes)

    if not uses_single_task_shorthand and not is_list(tasks) then
        return nil, string.format("%s must be a probe task or list of probe tasks.", field_name)
    end

    local seen_names = {}
    for index, task in ipairs(tasks) do
        local task_field_name = uses_single_task_shorthand
            and field_name
            or string.format("%s[%d]", field_name, index)

        if type(task) ~= "table" then
            return nil, string.format("%s must be a table.", task_field_name)
        end
        if not is_non_empty_string(task.name) then
            return nil, string.format("%s.name must be a non-empty string.", task_field_name)
        end
        if seen_names[task.name] then
            return nil, string.format("%s.name duplicates probe name '%s'.", task_field_name, task.name)
        end

        local ok, err = validate_module_function_path(task.func, task_field_name .. ".func")
        if not ok then
            return nil, err
        end
        if task.params ~= nil and type(task.params) ~= "table" then
            return nil, string.format("%s.params must be a table if present.", task_field_name)
        end

        seen_names[task.name] = true
    end

    return true
end

local function validate_reinforce_steps(reinforce, field_name)
    if reinforce == nil then
        return true
    end

    if not is_list(reinforce) then
        return nil, string.format("%s must be a list of reinforce steps.", field_name)
    end

    for index, task in ipairs(reinforce) do
        local task_field_name = string.format("%s[%d]", field_name, index)

        if type(task) ~= "table" then
            return nil, string.format("%s must be a table.", task_field_name)
        end

        local ok, err = validate_module_function_path(task.action, task_field_name .. ".action")
        if not ok then
            return nil, err
        end
        if task.params ~= nil and type(task.params) ~= "table" then
            return nil, string.format("%s.params must be a table if present.", task_field_name)
        end
    end

    return true
end

-- Owns the executable rule DSL shape. Comparator payloads remain opaque,
-- except for for_all.expected, which is itself another assertion node.
local function validate_assertion_node(node, field_name, opts)
    opts = opts or {}

    if type(node) ~= "table" then
        return nil, string.format("%s must be a table.", field_name)
    end

    local shape_count = 0
    if node.all_of ~= nil then
        shape_count = shape_count + 1
    end
    if node.any_of ~= nil then
        shape_count = shape_count + 1
    end
    if node.compare ~= nil then
        shape_count = shape_count + 1
    end

    if shape_count ~= 1 then
        return nil, string.format(
            "%s must define exactly one of 'all_of', 'any_of', or 'compare'.",
            field_name)
    end

    if node.message ~= nil and not is_non_empty_string(node.message) then
        return nil, string.format("%s.message must be a non-empty string if present.", field_name)
    end
    if node.key ~= nil and not is_non_empty_string(node.key) then
        return nil, string.format("%s.key must be a non-empty string if present.", field_name)
    end

    if node.all_of ~= nil then
        if not is_list(node.all_of) then
            return nil, string.format("%s.all_of must be a list.", field_name)
        end

        for index, child in ipairs(node.all_of) do
            local ok, err = validate_assertion_node(child, string.format("%s.all_of[%d]", field_name, index), opts)
            if not ok then
                return nil, err
            end
        end

        return true
    end

    if node.any_of ~= nil then
        if not is_list(node.any_of) then
            return nil, string.format("%s.any_of must be a list.", field_name)
        end

        for index, child in ipairs(node.any_of) do
            local ok, err = validate_assertion_node(child, string.format("%s.any_of[%d]", field_name, index), opts)
            if not ok then
                return nil, err
            end
        end

        return true
    end

    if not is_non_empty_string(node.compare) then
        return nil, string.format("%s.compare must be a non-empty string.", field_name)
    end
    if opts.validate_comparators ~= false and type(comparators[node.compare]) ~= "function" then
        return nil, string.format("%s.compare references unknown comparator '%s'.", field_name, node.compare)
    end

    if node.compare == "for_all" then
        if type(node.expected) ~= "table" then
            return nil, string.format(
                "%s.expected must be an assertion table when compare is 'for_all'.",
                field_name)
        end

        local ok, err = validate_assertion_node(node.expected, field_name .. ".expected", opts)
        if not ok then
            return nil, err
        end
    end

    return true
end

function M.validate_rule(rule, field_name, opts)
    field_name = field_name or "rule"
    opts = opts or {}

    if type(rule) ~= "table" then
        return nil, string.format("%s must be a table.", field_name)
    end
    if not is_non_empty_string(rule.id) then
        return nil, string.format("%s.id must be a non-empty string.", field_name)
    end
    if not is_non_empty_string(rule.desc) then
        return nil, string.format("%s.desc must be a non-empty string.", field_name)
    end

    local ok, err = validate_assertion_node(rule.assertion, field_name .. ".assertion", opts)
    if not ok then
        return nil, err
    end

    ok, err = validate_probe_tasks(rule.probes, field_name .. ".probes")
    if not ok then
        return nil, err
    end

    ok, err = validate_reinforce_steps(rule.reinforce, field_name .. ".reinforce")
    if not ok then
        return nil, err
    end

    return true
end

return M
