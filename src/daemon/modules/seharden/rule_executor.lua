local log = require('runtime.log')
local template = require('seharden.template')
local utils = require('seharden.util')
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

    if not (opts and opts.verbose) then
        log.warn("[%s] FAIL: %s - Reason: %s", rule.id, rule.desc, reason)
    end
    return "FAIL", string.format("[%s] %s: %s", rule.id, rule.desc, reason), probed_data, reason, probe_tasks
end

function M.enforce(rule, probed_data, dry_run)
    if not rule.reinforce then
        return "MANUAL", "No reinforce steps defined for this rule."
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
            if result == nil then
                return "ERROR", string.format("Enforcer '%s' failed: %s", tostring(path), tostring(err))
            end
        end
    end

    return dry_run and "SKIP" or "DONE"
end

return M
