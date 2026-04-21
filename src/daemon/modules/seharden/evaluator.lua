local log = require('runtime.log')
local template = require('seharden.shared.template')
local utils = require('seharden.shared.util')
local comparators = require('seharden.comparators')
local output = require('seharden.output')

local M = {}

local function get_actual_value(node, contexts)
    if node.actual == nil and node.key and contexts.item then
        log.debug("Resolving 'actual' from implicit item context with key '%s'", node.key)
        return contexts.item[node.key]
    end

    if type(node.actual) == 'string' then
        local probe_name = node.actual:match('^%%{probe%.([^}]+)}$')
        if probe_name then
            log.debug("Resolving 'actual' from probe '%s'", probe_name)
            local source_data = contexts.probe[probe_name]
            if source_data == nil then
                return nil
            end

            if node.key then
                log.debug("Extracting key '%s' from probe data.", node.key)
                return source_data[node.key]
            end

            return source_data
        end
    end

    return template.resolve_value(node.actual, contexts)
end

local function evaluate_node(node, contexts, indent)
    indent = indent or ""
    if node.all_of then
        log.debug("%sEvaluating 'all_of' block...", indent)
        for i, child_node in ipairs(node.all_of) do
            local passed, err = evaluate_node(child_node, contexts, indent .. "  ")
            if not passed then
                log.debug("%s'all_of' child #%d failed.", indent, i)
                return false, err
            end
        end
        log.debug("%s'all_of' block passed.", indent)
        return true
    end

    if node.any_of then
        log.debug("%sEvaluating 'any_of' block...", indent)
        local failure_reasons = {}
        for i, child_node in ipairs(node.any_of) do
            local passed, reason = evaluate_node(child_node, contexts, indent .. "  ")
            if passed then
                log.debug("%s'any_of' child #%d passed.", indent, i)
                return true
            end
            table.insert(failure_reasons, string.format("  - Child #%d failed: %s", i, tostring(reason)))
        end
        log.debug("%s'any_of' block failed.", indent)
        local combined_reason = "No conditions in 'any_of' were met:\n" .. table.concat(failure_reasons, "\n")
        return false, combined_reason
    end

    if node.compare then
        local comparator_func = comparators[node.compare]
        if not comparator_func then
            local err = string.format("Comparator not found: '%s'", node.compare)
            log.error(err)
            return false, err
        end

        local actual = get_actual_value(node, contexts)
        local expected

        if node.compare == "for_all" then
            expected = function(item)
                local item_contexts = { probe = contexts.probe, item = item }
                return evaluate_node(node.expected, item_contexts, indent .. "    ")
            end
        else
            expected = template.resolve_value(node.expected, contexts)
        end

        log.debug("%s -> ACTUAL value: %s", indent, utils.serialize_for_log(actual))
        log.debug("%s -> EXPECTED value: %s", indent, utils.serialize_for_log(expected))

        local result, err = comparator_func(actual, expected)
        log.debug("%sComparison result: %s", indent, tostring(result))

        if result then
            return true
        end

        local msg = node.message or "Assertion failed"
        return false, string.format("%s (%s)", msg,
            output.format_failure_detail(node, contexts, actual, err))
    end

    return false, "Invalid node structure"
end

function M.evaluate(node, contexts)
    return evaluate_node(node, contexts or {})
end

return M
