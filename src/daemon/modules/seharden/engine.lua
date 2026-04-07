local log = require('runtime.log')
local lyaml = require('lyaml')
local utils = require('seharden.util')
local probes = require('seharden.probeloader')
local enforcers = require('seharden.enforcerloader')
local comparators = require('seharden.comparators')

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

local function _get_probe_data(node, contexts)
    if type(node.actual) ~= "string" then
        return nil, nil
    end

    local probe_name = node.actual:match('^%%{probe%.([^}]+)}$')
    if not probe_name then
        return nil, nil
    end

    return probe_name, contexts.probe[probe_name]
end

local function _format_item_value(key, value)
    if key == "mode" and type(value) == "number" then
        return string.format("0%03o", value)
    end

    return utils.serialize_for_log(value)
end

local function _format_verbose_value(key, value)
    if key == "mode" and type(value) == "number" then
        return string.format("0%03o", value)
    end

    if type(value) == "string" then
        return string.format("'%s'", value)
    end

    if value == nil then
        return "nil"
    end

    return tostring(value)
end

local function _summarize_item(item)
    if type(item) ~= "table" then
        return utils.serialize_for_log(item)
    end

    local summary = {}
    local seen = {}
    local preferred_keys = {
        "path", "user", "name", "uid", "gid", "mode", "shell", "value", "found"
    }

    local function append_value(source, key)
        if type(source) ~= "table" or source[key] == nil or seen[key] then
            return
        end

        seen[key] = true
        summary[#summary + 1] = string.format("%s=%s", key, _format_item_value(key, source[key]))
    end

    local meta = getmetatable(item)
    local inherited = meta and type(meta.__index) == "table" and meta.__index or nil

    for _, key in ipairs(preferred_keys) do
        append_value(item, key)
        append_value(inherited, key)
    end

    if #summary == 0 then
        return utils.serialize_for_log(item)
    end

    return table.concat(summary, ", ")
end

local function _format_failure_detail(node, contexts, actual, comparator_detail)
    local probe_name, probe_data = _get_probe_data(node, contexts)

    if type(comparator_detail) == "table" and comparator_detail.item ~= nil then
        local item_summary = _summarize_item(comparator_detail.item)
        if comparator_detail.index ~= nil then
            return string.format("first failing item #%d: %s", comparator_detail.index, item_summary)
        end
        return "first failing item: " .. item_summary
    end

    if actual == nil and probe_name and type(probe_data) == "table" and probe_data.error ~= nil then
        return "probe error: " .. tostring(probe_data.error)
    end

    return "actual: " .. utils.serialize_for_log(actual)
end

local function _normalize_probe_tasks(rule_probes)
    if type(rule_probes) ~= "table" then
        return {}
    end

    if rule_probes.func then
        return { rule_probes }
    end

    return rule_probes
end

local function _collect_probe_focus_keys(node, focus)
    if type(node) ~= "table" then
        return focus
    end

    focus = focus or {}

    local actual = node.actual
    if type(actual) == "string" then
        local probe_name = actual:match('^%%{probe%.([^}]+)}$')
        if probe_name and type(node.key) == "string" and node.key ~= "" then
            focus[probe_name] = focus[probe_name] or {}
            focus[probe_name][node.key] = true
        end
    end

    if type(node.all_of) == "table" then
        for _, child in ipairs(node.all_of) do
            _collect_probe_focus_keys(child, focus)
        end
    end

    if type(node.any_of) == "table" then
        for _, child in ipairs(node.any_of) do
            _collect_probe_focus_keys(child, focus)
        end
    end

    if type(node.expected) == "table" then
        _collect_probe_focus_keys(node.expected, focus)
    end

    return focus
end

local function _summarize_probe_value(value, focus_keys)
    if type(value) ~= "table" then
        return _format_verbose_value(nil, value)
    end

    if next(value) == nil then
        return "empty"
    end

    local parts = {}
    local seen = {}
    local preferred_keys = {
        "available",
        "value",
        "count",
        "conflicting_count",
        "found",
        "compliant",
        "UnitFileState",
        "ActiveState",
        "error",
        "path",
        "path_type",
        "user",
        "name",
        "uid",
        "gid",
        "mode",
        "shell",
    }

    local function append_part(key)
        if key == nil or seen[key] or value[key] == nil then
            return
        end

        seen[key] = true
        parts[#parts + 1] = string.format("%s=%s", key, _format_verbose_value(key, value[key]))
    end

    if type(focus_keys) == "table" then
        local keys = {}
        for key in pairs(focus_keys) do
            keys[#keys + 1] = key
        end
        table.sort(keys)
        for _, key in ipairs(keys) do
            append_part(key)
        end
    end

    for _, key in ipairs(preferred_keys) do
        append_part(key)
    end

    if type(value.details) == "table" then
        if value.count == nil then
            parts[#parts + 1] = string.format("count=%d", #value.details)
        end
        if #value.details > 0 then
            parts[#parts + 1] = string.format("first=%s", _summarize_item(value.details[1]))
        end
    elseif value[1] ~= nil then
        if value.count == nil then
            parts[#parts + 1] = string.format("count=%d", #value)
        end
        parts[#parts + 1] = string.format("first=%s", _summarize_item(value[1]))
    end

    if #parts == 0 then
        local extra_keys = {}
        local total_keys = 0
        for key, map_value in pairs(value) do
            total_keys = total_keys + 1
            if not seen[key] and type(key) == "string" and type(map_value) ~= "table" then
                extra_keys[#extra_keys + 1] = key
            end
        end

        table.sort(extra_keys)
        if #extra_keys > 0 and #extra_keys <= 4 then
            for _, key in ipairs(extra_keys) do
                append_part(key)
            end
        elseif total_keys > 0 then
            return string.format("table(%d keys)", total_keys)
        end
    end

    if #parts == 0 then
        return "table"
    end

    return table.concat(parts, ", ")
end

local function _emit_verbose_rule_details(rule, status, probed_data, reason)
    local label

    if status == "PASS" then
        label = "PASS"
    elseif status == "FAIL" then
        label = "FAIL"
    else
        return
    end

    local styled_label = label == "PASS"
        and log.style(label, "bold", "green")
        or log.style(label, "bold", "red")

    print(string.format("  %s [%s] %s", styled_label, tostring(rule.id), tostring(rule.desc)))
    if label == "FAIL" and reason then
        local formatted_reason = tostring(reason):gsub("\n%s*", "\n      ")
        print(string.format("    %s %s", log.style("reason:", "yellow"), formatted_reason))
    end

    local probe_tasks = _normalize_probe_tasks(rule.probes)
    local focus_keys = _collect_probe_focus_keys(rule.assertion)
    if #probe_tasks == 0 then
        return
    end

    for _, task in ipairs(probe_tasks) do
        if type(task) == "table" and type(task.name) == "string" then
            local value = probed_data and probed_data[task.name]
            if value ~= nil then
                print(string.format("    - %s: %s", task.name,
                    _summarize_probe_value(value, focus_keys[task.name])))
            end
        end
    end
end

local function _emit_verbose_summary(passed, fixed, failed, manual, dry_run_pending, total)
    local summary = log.style("Summary:", "bold", "cyan")
    local passed_text = log.style(string.format("%d passed", passed), "green")
    local fixed_text = log.style(string.format("%d fixed", fixed), "green")
    local failed_text = log.style(string.format("%d failed", failed), failed > 0 and "red" or "green")
    local manual_text = log.style(string.format("%d manual", manual), manual > 0 and "yellow" or "dim")
    local pending_text = log.style(
        string.format("%d dry-run-pending", dry_run_pending),
        dry_run_pending > 0 and "yellow" or "dim")

    print(string.format(
        "%s %s, %s, %s, %s, %s / %d total",
        summary, passed_text, fixed_text, failed_text, manual_text, pending_text, total))
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
                _format_failure_detail(node, contexts, actual, err))
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
        local probes_to_run = _normalize_probe_tasks(rule.probes)

        for _, task in ipairs(probes_to_run) do
            local probe_func = probes.get(task.func)
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

--------------------------------------------------------------------------------
-- The Reinforce Logic
--------------------------------------------------------------------------------

local function validate_reinforce_steps(rule)
    if not rule.reinforce then return true end
    if type(rule.reinforce) ~= "table" then
        return false, "rule.reinforce must be a list"
    end
    for i, task in ipairs(rule.reinforce) do
        if type(task.action) ~= "string" or task.action == "" then
            return false, string.format("reinforce[%d] missing or empty 'action' string", i)
        end
        if not task.action:match("^[%w_]+%.[%w_]+$") then
            return false, string.format("reinforce[%d] action '%s' must be in 'module.function' format", i, task.action)
        end
        if task.params ~= nil and type(task.params) ~= "table" then
            return false, string.format("reinforce[%d] 'params' must be a table if present", i)
        end
    end
    return true
end

local function run_enforce(rule, probed_data, dry_run)
    if not rule.reinforce then
        return "MANUAL", "No reinforce steps defined for this rule."
    end

    local valid, schema_err = validate_reinforce_steps(rule)
    if not valid then
        return "ERROR", string.format("Invalid reinforce schema: %s", schema_err)
    end

    for _, task in ipairs(rule.reinforce) do
        local resolved_params = resolve_value(task.params, { probe = probed_data })
        local enforcer_func, path = enforcers.get(task.action)

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
        local status, message, probed_data, reason = run_audit(rule, opts)

        if status == "ERROR" then
            log.error("[%s] Engine Error: %s", rule.id, message)
            hard_failures = hard_failures + 1
        elseif status == "PASS" then
            if opts.verbose then
                _emit_verbose_rule_details(rule, status, probed_data)
            end
            passed = passed + 1
        elseif mode == "reinforce" then
            if opts.verbose then
                _emit_verbose_rule_details(rule, status, probed_data, reason)
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
                _emit_verbose_rule_details(rule, status, probed_data, reason)
            end
            hard_failures = hard_failures + 1
        end
    end

    if opts.verbose then
        _emit_verbose_summary(passed, fixed, hard_failures, manual, dry_run_pending, total_checks)
    else
        log.info("SEHarden Finished. %d passed, %d fixed, %d failed, %d manual, %d dry-run-pending / %d total.",
            passed, fixed, hard_failures, manual, dry_run_pending, total_checks)
    end
    return (hard_failures == 0 and dry_run_pending == 0) and 0 or 1
end

return M
