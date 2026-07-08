local log = require('runtime.log')
local output = require('seharden.output')
local rule_executor = require('seharden.rule_executor')
local rule_schema = require('seharden.rule_schema')

local M = {}

--------------------------------------------------------------------------------
-- Internal Helpers
--------------------------------------------------------------------------------

local function process_single_rule(rule, mode, opts, report, counters)
    local quiet = opts.quiet or false
    local valid, schema_err = rule_schema.validate_rule(rule)
    local rule_id = type(rule) == 'table' and rule.id or '<unknown>'

    if not valid then
        if not quiet then
            log.error('[%s] Engine Error: Invalid rule schema: %s', tostring(rule_id), schema_err)
        end
        local item = {
            id = rule_id,
            desc = type(rule) == 'table' and rule.desc or nil,
            status = 'ERROR',
            reason = string.format('Invalid rule schema: %s', schema_err),
        }
        report.rules[#report.rules + 1] = item
        counters.hard_failures = counters.hard_failures + 1
        return
    end

    local status, message, probed_data, reason, probe_tasks = rule_executor.audit(rule, opts)

    if status == 'ERROR' then
        if not quiet then
            log.error('[%s] Engine Error: %s', rule.id, message)
        end
        local item = {
            id = rule.id,
            desc = rule.desc,
            status = 'ERROR',
            reason = message,
        }
        report.rules[#report.rules + 1] = item
        counters.hard_failures = counters.hard_failures + 1
    elseif status == 'PASS' then
        if opts.verbose and not quiet then
            output.emit_verbose_rule_details(rule, status, probed_data, nil, probe_tasks)
        end
        local item = {
            id = rule.id,
            desc = rule.desc,
            status = 'PASS',
        }
        report.rules[#report.rules + 1] = item
        counters.passed = counters.passed + 1
    elseif mode == 'reinforce' then
        if opts.verbose and not quiet then
            output.emit_verbose_rule_details(rule, status, probed_data, reason, probe_tasks)
        end
        local item = {
            id = rule.id,
            desc = rule.desc,
            status = 'FAIL',
            reason = reason,
        }
        report.rules[#report.rules + 1] = item

        local enforce_status, enforce_err = rule_executor.enforce(rule, probed_data, opts.dry_run)

        if enforce_status == 'MANUAL' then
            if not quiet then
                log.info('[%s] MANUAL: %s', rule.id, enforce_err)
            end
            item.status = 'MANUAL'
            item.reason = tostring(enforce_err)
            counters.manual = counters.manual + 1
        elseif enforce_status == 'ERROR' then
            if not quiet then
                log.error('[%s] ENFORCE-ERROR: %s', rule.id, enforce_err)
            end
            item.status = 'ENFORCE-ERROR'
            item.reason = tostring(enforce_err)
            counters.hard_failures = counters.hard_failures + 1
        elseif enforce_status == 'SKIP' then
            if not quiet then
                log.info('[%s] DRY-RUN: would apply %d action(s)', rule.id, #(rule.reinforce or {}))
            end
            item.status = 'DRY-RUN'
            item.reason = string.format('would apply %d action(s)', #(rule.reinforce or {}))
            counters.dry_run_pending = counters.dry_run_pending + 1
        elseif enforce_status == 'DONE' then
            -- Clear SSH probe cache to force fresh sshd -T execution after config changes
            local ssh_probe = require('seharden.probes.ssh')
            if type(ssh_probe.clear_cache) == 'function' then
                ssh_probe.clear_cache()
                if not quiet then
                    log.debug('Cleared SSH probe cache for fresh verification.')
                end
            end

            local verify_status, verify_msg = rule_executor.audit(rule, opts)
            if verify_status == 'PASS' then
                if not quiet then
                    log.info('[%s] FIXED: %s', rule.id, rule.desc)
                end
                item.status = 'FIXED'
                item.reason = nil
                counters.fixed = counters.fixed + 1
            else
                if not quiet then
                    log.error('[%s] FAILED-TO-FIX: %s', rule.id, verify_msg)
                end
                item.status = 'FAILED-TO-FIX'
                item.reason = tostring(verify_msg)
                counters.hard_failures = counters.hard_failures + 1
            end
        end
    else
        if opts.verbose and not quiet then
            output.emit_verbose_rule_details(rule, status, probed_data, reason, probe_tasks)
        end
        local item = {
            id = rule.id,
            desc = rule.desc,
            status = 'FAIL',
            reason = reason,
        }
        report.rules[#report.rules + 1] = item
        counters.hard_failures = counters.hard_failures + 1
    end
end

--------------------------------------------------------------------------------
-- The Engine's Public API
--------------------------------------------------------------------------------

function M.run(mode, rules, opts)
    opts = opts or {}
    local dry_run = opts.dry_run or false
    local quiet = opts.quiet or false

    if not opts.verbose and not quiet then
        log.info(string.format('Starting SEHarden Engine. Mode: %s%s', mode, dry_run and ' (dry-run)' or ''))
    end

    if mode == 'reinforce' and not dry_run then
        local notice = 'NOTICE: Reinforce mode is non-transactional. Changes are applied '
            .. 'incrementally with no automatic rollback. A partially-applied run may '
            .. 'leave the system in an intermediate state.'
        if opts.verbose and not quiet then
            print(notice)
        elseif not quiet then
            log.warn(notice)
        end
    end

    local total_checks = #rules
    if not quiet then
        log.debug('Executing %d rules.', total_checks)
    end

    local report = {
        mode = mode,
        dry_run = dry_run,
        rules = {},
        summary = {
            passed = 0,
            fixed = 0,
            failed = 0,
            manual = 0,
            dry_run_pending = 0,
            total = total_checks,
        },
    }

    local counters = {
        passed = 0,
        fixed = 0,
        manual = 0,
        dry_run_pending = 0,
        hard_failures = 0,
        mode = mode,
        dry_run = dry_run,
    }

    for _, rule in ipairs(rules) do
        process_single_rule(rule, mode, opts, report, counters)
    end

    report.summary.passed = counters.passed
    report.summary.fixed = counters.fixed
    report.summary.failed = counters.hard_failures
    report.summary.manual = counters.manual
    report.summary.dry_run_pending = counters.dry_run_pending

    if opts.verbose and not quiet then
        output.emit_verbose_summary(
            counters.passed,
            counters.fixed,
            counters.hard_failures,
            counters.manual,
            counters.dry_run_pending,
            total_checks
        )
    elseif not quiet then
        log.info(
            'SEHarden Finished. %d passed, %d fixed, %d failed, %d manual, %d dry-run-pending / %d total.',
            counters.passed,
            counters.fixed,
            counters.hard_failures,
            counters.manual,
            counters.dry_run_pending,
            total_checks
        )
    end
    local exit_code = (counters.hard_failures == 0 and counters.dry_run_pending == 0) and 0 or 1
    report.exit_code = exit_code
    return exit_code, report
end

return M
