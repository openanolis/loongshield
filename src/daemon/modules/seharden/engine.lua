local log = require('runtime.log')
local utils = require('seharden.util')
local loader = require('seharden.loader')
local comparators = require('seharden.comparators')
local output = require('seharden.output')
local rule_schema = require('seharden.rule_schema')

local M = {}

--------------------------------------------------------------------------------
-- Core Helper Functions
--------------------------------------------------------------------------------

local function lookup_context_value(key, contexts)
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

local function resolve_value(template, contexts)
    if type(template) ~= "string" then
        if type(template) == "table" then
            local new_table = {}
            for k, v in pairs(template) do
                -- Recursively resolve both keys and values for full coverage
                new_table[resolve_value(k, contexts)] = resolve_value(v, contexts)
            end
            return new_table
        end
        return template
    end

    local full_key = template:match("^%%{([^}]+)}$")
    if full_key then
        local value = lookup_context_value(full_key, contexts)
        if value == nil then
            return template
        end
        return value
    end

    return template:gsub("%%{([^}]+)}", function(key)
        local value = lookup_context_value(key, contexts)

        if value == nil then
            return "%{" .. key .. "}"
        elseif type(value) == 'table' then
            return "%{" .. key .. "}"
        else
            return tostring(value)
        end
    end)
end

local function _get_actual_value(node, contexts)
    if node.actual == nil and node.key and contexts.item then
        log.debug("Resolving 'actual' from implicit item context with key '%s'", node.key)
        return contexts.item[node.key]
    end

    if type(node.actual) == 'string' then
        local probe_name = node.actual:match('^%%{probe%.([^}]+)}$')
        if probe_name then
            log.debug("Resolving 'actual' from probe '%s'", probe_name)
            local source_data = contexts.probe[probe_name]
            if source_data == nil then return nil end

            if node.key then
                log.debug("Extracting key '%s' from probe data.", node.key)
                return source_data[node.key]
            else
                return source_data
            end
        end
    end

    return resolve_value(node.actual, contexts)
end

--------------------------------------------------------------------------------
-- The Recursive Evaluator
--------------------------------------------------------------------------------

local evaluate_node -- Forward declaration for recursion

evaluate_node = function(node, contexts, indent)
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
    elseif node.any_of then
        log.debug("%sEvaluating 'any_of' block...", indent)
        local failure_reasons = {}
        for i, child_node in ipairs(node.any_of) do
            local passed, reason = evaluate_node(child_node, contexts, indent .. "  ")
            if passed then
                log.debug("%s'any_of' child #%d passed.", indent, i)
                return true
            else
                table.insert(failure_reasons, string.format("  - Child #%d failed: %s", i, tostring(reason)))
            end
        end
        log.debug("%s'any_of' block failed.", indent)
        local combined_reason = "No conditions in 'any_of' were met:\n" .. table.concat(failure_reasons, "\n")
        return false, combined_reason
    elseif node.compare then
        local comparator_func = comparators[node.compare]
        if not comparator_func then
            local err = string.format("Comparator not found: '%s'", node.compare)
            log.error(err)
            return false, err
        end

        local actual = _get_actual_value(node, contexts)
        local expected

        if node.compare == "for_all" then
            expected = function(item)
                local item_contexts = { probe = contexts.probe, item = item }
                return evaluate_node(node.expected, item_contexts, indent .. "    ")
            end
        else
            expected = resolve_value(node.expected, contexts)
        end

        log.debug("%s -> ACTUAL value: %s", indent, utils.serialize_for_log(actual))
        log.debug("%s -> EXPECTED value: %s", indent, utils.serialize_for_log(expected))

        local result, err = comparator_func(actual, expected)
        log.debug("%sComparison result: %s", indent, tostring(result))

        if result then
            return true
        else
            local msg = node.message or "Assertion failed"
            return false, string.format("%s (%s)", msg,
                output.format_failure_detail(node, contexts, actual, err))
        end
    end
    return false, "Invalid node structure"
end

--------------------------------------------------------------------------------
-- The Main Audit Logic
--------------------------------------------------------------------------------

local function run_audit(rule, opts)
    local probed_data = {}

    if rule.probes then
        log.debug("--- Probing Data for Rule ID: %s ---", rule.id)
        local probes_to_run = rule_schema.normalize_probe_tasks(rule.probes)

        for _, task in ipairs(probes_to_run) do
            local probe_func = loader.get_probe(task.func)
            if not probe_func then
                return "ERROR", string.format("Probe '%s' not found", task.func)
            end

            local resolved_params = resolve_value(task.params, { probe = probed_data })
            local ok, res, err = pcall(probe_func, resolved_params, probed_data)

            if not ok then
                return "ERROR", string.format("Probe '%s' failed: %s", task.func, tostring(res))
            end
            if res == nil and err ~= nil then
                return "ERROR", string.format("Probe '%s' failed: %s", task.func, tostring(err))
            end
            probed_data[task.name] = res
        end
    end

    log.debug("--- Evaluating Rule ID: %s ---", rule.id)
    local initial_contexts = { probe = probed_data }
    local passed, reason = evaluate_node(rule.assertion, initial_contexts)

    if passed then
        log.debug("[%s] PASS: %s", rule.id, rule.desc)
        return "PASS", string.format("[%s] %s", rule.id, rule.desc), probed_data
    else
        if not (opts and opts.verbose) then
            log.warn("[%s] FAIL: %s - Reason: %s", rule.id, rule.desc, reason)
        end
        return "FAIL", string.format("[%s] %s: %s", rule.id, rule.desc, reason), probed_data, reason
    end
end

local function run_enforce(rule, probed_data, dry_run)
    if not rule.reinforce then
        return "MANUAL", "No reinforce steps defined for this rule."
    end

    for _, task in ipairs(rule.reinforce) do
        local resolved_params = resolve_value(task.params, { probe = probed_data })
        local enforcer_func, path = loader.get_enforcer(task.action)

        if dry_run then
            if not enforcer_func then
                log.warn("[DRY-RUN] WARNING: Enforcer '%s' not found — action would fail at runtime",
                    task.action)
            else
                log.info("[DRY-RUN] Would apply: %s with params: %s",
                    task.action, utils.serialize_for_log(resolved_params))
            end
        else
            if not enforcer_func then
                return "ERROR", string.format("Enforcer '%s' not found", task.action)
            end
            local pcall_ok, result, err = pcall(enforcer_func, resolved_params)
            if not pcall_ok then
                -- enforcer raised an exception (result holds the error message)
                return "ERROR", string.format("Enforcer '%s' raised: %s", tostring(path), tostring(result))
            end
            if result == nil then
                -- enforcer returned nil, err (normal failure path)
                return "ERROR", string.format("Enforcer '%s' failed: %s", tostring(path), tostring(err))
            end
        end
    end

    return dry_run and "SKIP" or "DONE"
end

--------------------------------------------------------------------------------
-- The Engine's Public API
--------------------------------------------------------------------------------

function M.run(mode, rules, opts)
    opts = opts or {}
    local dry_run = opts.dry_run or false

    if not opts.verbose then
        log.info(string.format("Starting SEHarden Engine. Mode: %s%s",
            mode, dry_run and " (dry-run)" or ""))
    end

    if mode == "reinforce" and not dry_run then
        local notice = "NOTICE: Reinforce mode is non-transactional. Changes are applied " ..
            "incrementally with no automatic rollback. A partially-applied run may " ..
            "leave the system in an intermediate state."
        if opts.verbose then
            print(notice)
        else
            log.warn(notice)
        end
    end

    local passed          = 0
    local fixed           = 0
    local manual          = 0
    local dry_run_pending = 0
    local hard_failures   = 0
    local total_checks    = #rules
    log.debug("Executing %d rules.", total_checks)

    for _, rule in ipairs(rules) do
        local valid, schema_err = rule_schema.validate_rule(rule)
        local probe_tasks = valid and rule_schema.normalize_probe_tasks(rule.probes) or {}
        local rule_id = type(rule) == "table" and rule.id or "<unknown>"

        if not valid then
            log.error("[%s] Engine Error: Invalid rule schema: %s", tostring(rule_id), schema_err)
            hard_failures = hard_failures + 1
        else
            local status, message, probed_data, reason = run_audit(rule, opts)

            if status == "ERROR" then
                log.error("[%s] Engine Error: %s", rule.id, message)
                hard_failures = hard_failures + 1
            elseif status == "PASS" then
                if opts.verbose then
                    output.emit_verbose_rule_details(
                        rule, status, probed_data, nil, probe_tasks)
                end
                passed = passed + 1
            elseif mode == "reinforce" then
                if opts.verbose then
                    output.emit_verbose_rule_details(
                        rule, status, probed_data, reason, probe_tasks)
                end
                local enforce_status, enforce_err = run_enforce(rule, probed_data, dry_run)

                if enforce_status == "MANUAL" then
                    log.info("[%s] MANUAL: %s", rule.id, enforce_err)
                    manual = manual + 1
                elseif enforce_status == "ERROR" then
                    log.error("[%s] ENFORCE-ERROR: %s", rule.id, enforce_err)
                    hard_failures = hard_failures + 1
                elseif enforce_status == "SKIP" then
                    log.info("[%s] DRY-RUN: would apply %d action(s)",
                        rule.id, #(rule.reinforce or {}))
                    dry_run_pending = dry_run_pending + 1
                elseif enforce_status == "DONE" then
                    local verify_status, verify_msg = run_audit(rule)
                    if verify_status == "PASS" then
                        log.info("[%s] FIXED: %s", rule.id, rule.desc)
                        fixed = fixed + 1
                    else
                        log.error("[%s] FAILED-TO-FIX: %s", rule.id, verify_msg)
                        hard_failures = hard_failures + 1
                    end
                end
            else
                if opts.verbose then
                    output.emit_verbose_rule_details(
                        rule, status, probed_data, reason, probe_tasks)
                end
                hard_failures = hard_failures + 1
            end
        end
    end

    if opts.verbose then
        output.emit_verbose_summary(passed, fixed, hard_failures, manual, dry_run_pending, total_checks)
    else
        log.info("SEHarden Finished. %d passed, %d fixed, %d failed, %d manual, %d dry-run-pending / %d total.",
            passed, fixed, hard_failures, manual, dry_run_pending, total_checks)
    end
    return (hard_failures == 0 and dry_run_pending == 0) and 0 or 1
end

return M
