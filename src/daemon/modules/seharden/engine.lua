local log = require('runtime.log')
local output = require('seharden.output')
local rule_executor = require('seharden.rule_executor')
local rule_schema = require('seharden.rule_schema')

local M = {}

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
        local rule_id = type(rule) == "table" and rule.id or "<unknown>"

        if not valid then
            log.error("[%s] Engine Error: Invalid rule schema: %s", tostring(rule_id), schema_err)
            hard_failures = hard_failures + 1
        else
            local status, message, probed_data, reason, probe_tasks = rule_executor.audit(rule, opts)

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
                local enforce_status, enforce_err = rule_executor.enforce(rule, probed_data, dry_run)

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
                    local verify_status, verify_msg = rule_executor.audit(rule)
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
