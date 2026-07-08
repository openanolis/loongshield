local log = require('runtime.log')
local template = require('seharden.shared.template')
local utils = require('seharden.shared.util')
local loader = require('seharden.loader')
local rule_schema = require('seharden.rule_schema')
local evaluator = require('seharden.evaluator')

local M = {}

function M.audit(rule, opts)
    local probed_data = {}
    local probe_tasks = rule_schema.normalize_probe_tasks(rule.probes)

    if #probe_tasks > 0 then
        log.debug("--- Probing Data for Rule ID: %s ---", rule.id)

        for _, task in ipairs(probe_tasks) do
            local probe_func = loader.get_probe(task.func)
            if not probe_func then
                return "ERROR", string.format("Probe '%s' not found", task.func), nil, nil, probe_tasks
            end

            local resolved_params = template.resolve_value(task.params, { probe = probed_data })
            local ok, res, err = pcall(probe_func, resolved_params, probed_data)

            if not ok then
                return "ERROR", string.format("Probe '%s' failed: %s", task.func, tostring(res)), nil, nil, probe_tasks
            end
            if res == nil and err ~= nil then
                return "ERROR", string.format("Probe '%s' failed: %s", task.func, tostring(err)), nil, nil, probe_tasks
            end
            probed_data[task.name] = res
        end
    end

    log.debug("--- Evaluating Rule ID: %s ---", rule.id)
    local passed, reason = evaluator.evaluate(rule.assertion, { probe = probed_data })

    if passed then
        log.debug("[%s] PASS: %s", rule.id, rule.desc)
        return "PASS", string.format("[%s] %s", rule.id, rule.desc), probed_data, nil, probe_tasks
    end

    if not (opts and (opts.verbose or opts.quiet)) then
        log.warn("[%s] FAIL: %s - Reason: %s", rule.id, rule.desc, reason)
    end
    return "FAIL", string.format("[%s] %s: %s", rule.id, rule.desc, reason), probed_data, reason, probe_tasks
end

--- Evaluate an optional reinforce_guard probe.
-- Returns nil when no guard is defined or the guard did not trigger.
-- Returns a skip-message string when the guard returned truthy.
local function evaluate_guard(rule, probed_data)
    local guard = rule.reinforce_guard
    if not guard then
        return nil
    end

    local tasks = rule_schema.normalize_probe_tasks(guard)
    for _, task in ipairs(tasks) do
        local probe_func = loader.get_probe(task.func)
        if not probe_func then
            local msg = string.format(
                "reinforce_guard probe '%s' not found; skipping reinforce to avoid unsafe execution",
                task.func)
            log.warn("[%s] GUARD-SKIP [%s]: %s",
                rule.id or "?", task.name or "guard", msg)
            return msg
        end

        local resolved_params = template.resolve_value(task.params, { probe = probed_data })
        local pcall_ok, guard_result, guard_reason = pcall(probe_func, resolved_params, probed_data)
        if not pcall_ok then
            local msg = string.format(
                "reinforce_guard probe '%s' raised: %s; skipping reinforce to avoid unsafe execution",
                task.func, tostring(guard_result))
            log.warn("[%s] GUARD-SKIP [%s]: %s",
                rule.id or "?", task.name or "guard", msg)
            return msg
        end

        if guard_result then
            local skip_msg
            -- Prefer explicit skip_message from the YAML (guard-level for
            -- single-task shorthand, task-level for list format), then fall
            -- back to the reason string returned by the probe itself.
            if type(guard.skip_message) == "string" and guard.skip_message ~= "" then
                skip_msg = guard.skip_message
            elseif type(task.skip_message) == "string" and task.skip_message ~= "" then
                skip_msg = task.skip_message
            elseif type(guard_reason) == "string" then
                skip_msg = guard_reason
            else
                skip_msg = "Reinforce skipped by guard condition."
            end
            local guard_name = task.name or guard.name or "guard"
            log.info("[%s] GUARD-SKIP [%s]: %s", rule.id or "?", guard_name, skip_msg)
            return skip_msg
        end

    end

    return nil
end

function M.enforce(rule, probed_data, dry_run)
    if not rule.reinforce then
        return "MANUAL", "No reinforce steps defined for this rule."
    end

    -- Evaluate optional reinforce_guard before executing any actions.
    local guard_skip = evaluate_guard(rule, probed_data)
    if guard_skip then
        return "MANUAL", guard_skip
    end

    for _, task in ipairs(rule.reinforce) do
        local resolved_params = template.resolve_value(task.params, { probe = probed_data })
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
                return "ERROR", string.format("Enforcer '%s' raised: %s", tostring(path), tostring(result))
            end
            if result == nil or result == false then
                local msg = err or "enforcer returned false"
                return "ERROR", string.format("Enforcer '%s' failed: %s", tostring(path), tostring(msg))
            end
        end
    end

    return dry_run and "SKIP" or "DONE"
end

return M
