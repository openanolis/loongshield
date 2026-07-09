local log = require('runtime.log')
local template = require('seharden.shared.template')
local utils = require('seharden.shared.util')
local loader = require('seharden.loader')
local rule_schema = require('seharden.rule_schema')
local evaluator = require('seharden.evaluator')

local M = {}

local function invalidate_probe_state_after_enforce()
    local ssh_probe = require('seharden.probes.ssh')
    if type(ssh_probe.clear_cache) == 'function' then
        ssh_probe.clear_cache()
    end
end

local function guard_skip_message(guard, task, guard_reason)
    -- Guard-level messages are used by single-task shorthand; task-level
    -- messages support list-format guards.
    if type(guard.skip_message) == 'string' and guard.skip_message ~= '' then
        return guard.skip_message
    end
    if type(task.skip_message) == 'string' and task.skip_message ~= '' then
        return task.skip_message
    end
    if type(guard_reason) == 'string' then
        return guard_reason
    end
    return 'Reinforce skipped by guard condition.'
end

function M.audit(rule, opts)
    local probed_data = {}
    local probe_tasks = rule_schema.get_probe_tasks(rule, 'probes')

    if #probe_tasks > 0 then
        log.debug('--- Probing Data for Rule ID: %s ---', rule.id)

        for _, task in ipairs(probe_tasks) do
            local probe_func = loader.get_probe(task.func)
            if not probe_func then
                return 'ERROR', string.format("Probe '%s' not found", task.func), nil, nil, probe_tasks
            end

            local resolved_params = template.resolve_value(task.params, { probe = probed_data })
            local ok, res, err = pcall(probe_func, resolved_params, probed_data)

            if not ok then
                return 'ERROR', string.format("Probe '%s' failed: %s", task.func, tostring(res)), nil, nil, probe_tasks
            end
            if res == nil and err ~= nil then
                return 'ERROR', string.format("Probe '%s' failed: %s", task.func, tostring(err)), nil, nil, probe_tasks
            end
            probed_data[task.name] = res
        end
    end

    log.debug('--- Evaluating Rule ID: %s ---', rule.id)
    local passed, reason = evaluator.evaluate(rule.assertion, { probe = probed_data })

    if passed then
        log.debug('[%s] PASS: %s', rule.id, rule.desc)
        return 'PASS', string.format('[%s] %s', rule.id, rule.desc), probed_data, nil, probe_tasks
    end

    if not (opts and (opts.verbose or opts.quiet)) then
        log.warn('[%s] FAIL: %s - Reason: %s', rule.id, rule.desc, reason)
    end
    return 'FAIL', string.format('[%s] %s: %s', rule.id, rule.desc, reason), probed_data, reason, probe_tasks
end

--- Evaluate an optional reinforce_guard probe.
-- Returns nil when no guard is defined or the guard did not trigger.
-- Returns a skip-message string when the guard returned truthy.
local function evaluate_guard(rule, probed_data)
    local tasks = rule_schema.get_probe_tasks(rule, 'reinforce_guard')
    if #tasks == 0 then
        return nil
    end
    local guard = type(rule.reinforce_guard) == 'table' and rule.reinforce_guard or {}

    for _, task in ipairs(tasks) do
        local probe_func = loader.get_probe(task.func)
        if not probe_func then
            local msg = string.format(
                "reinforce_guard probe '%s' not found; skipping reinforce to avoid unsafe execution",
                task.func
            )
            log.warn('[%s] GUARD-SKIP [%s]: %s', rule.id or '?', task.name or 'guard', msg)
            return msg
        end

        local resolved_params = template.resolve_value(task.params, { probe = probed_data })
        local pcall_ok, guard_result, guard_reason = pcall(probe_func, resolved_params, probed_data)
        if not pcall_ok then
            local msg = string.format(
                "reinforce_guard probe '%s' raised: %s; skipping reinforce to avoid unsafe execution",
                task.func,
                tostring(guard_result)
            )
            log.warn('[%s] GUARD-SKIP [%s]: %s', rule.id or '?', task.name or 'guard', msg)
            return msg
        end

        if guard_result then
            local skip_msg = guard_skip_message(guard, task, guard_reason)
            local guard_name = task.name or 'guard'
            log.info('[%s] GUARD-SKIP [%s]: %s', rule.id or '?', guard_name, skip_msg)
            return skip_msg
        end
    end

    return nil
end

function M.enforce(rule, probed_data, dry_run)
    if not rule.reinforce then
        return 'MANUAL', 'No reinforce steps defined for this rule.'
    end

    -- Evaluate optional reinforce_guard before executing any actions.
    local guard_skip = evaluate_guard(rule, probed_data)
    if guard_skip then
        return 'MANUAL', guard_skip
    end

    for _, task in ipairs(rule.reinforce) do
        local resolved_params = template.resolve_value(task.params, { probe = probed_data })
        local enforcer_func, path = loader.get_enforcer(task.action)

        if dry_run then
            if not enforcer_func then
                log.warn("[DRY-RUN] WARNING: Enforcer '%s' not found — action would fail at runtime", task.action)
            else
                log.info(
                    '[DRY-RUN] Would apply: %s with params: %s',
                    task.action,
                    utils.serialize_for_log(resolved_params)
                )
            end
        else
            if not enforcer_func then
                return 'ERROR', string.format("Enforcer '%s' not found", task.action)
            end

            local pcall_ok, result, err = pcall(enforcer_func, resolved_params)
            if not pcall_ok then
                return 'ERROR', string.format("Enforcer '%s' raised: %s", tostring(path), tostring(result))
            end
            if result == nil or result == false then
                local msg = err or 'enforcer returned false'
                return 'ERROR', string.format("Enforcer '%s' failed: %s", tostring(path), tostring(msg))
            end
        end
    end

    if not dry_run then
        invalidate_probe_state_after_enforce()
    end

    return dry_run and 'SKIP' or 'DONE'
end

return M
