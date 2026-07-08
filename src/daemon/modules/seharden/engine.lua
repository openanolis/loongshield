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
    local quiet = opts.quiet or false

    if not opts.verbose and not quiet then
        log.info(string.format("Starting SEHarden Engine. Mode: %s%s",
            mode, dry_run and " (dry-run)" or ""))
    end

    if mode == "reinforce" and not dry_run then
        local notice = "NOTICE: Reinforce mode is non-transactional. Changes are applied " ..
            "incrementally with no automatic rollback. A partially-applied run may " ..
            "leave the system in an intermediate state."
        if opts.verbose and not quiet then
            print(notice)
        elseif not quiet then
            log.warn(notice)
        end
    end

    local passed          = 0
    local fixed           = 0
    local manual          = 0
    local dry_run_pending = 0
    local hard_failures   = 0
    local total_checks    = #rules
    if not quiet then
        log.debug("Executing %d rules.", total_checks)
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

    local function add_rule_result(rule, status, reason)
        local item = {
            id = type(rule) == "table" and rule.id or "<unknown>",
            desc = type(rule) == "table" and rule.desc or nil,
            status = status,
        }
        if reason ~= nil then
            item.reason = tostring(reason)
        end
        report.rules[#report.rules + 1] = item
        return item
    end

    for _, rule in ipairs(rules) do
        local valid, schema_err = rule_schema.validate_rule(rule)
        local rule_id = type(rule) == "table" and rule.id or "<unknown>"

        if not valid then
            if not quiet then
                log.error("[%s] Engine Error: Invalid rule schema: %s", tostring(rule_id), schema_err)
            end
            add_rule_result(rule, "ERROR", string.format("Invalid rule schema: %s", schema_err))
            hard_failures = hard_failures + 1
        else
            local status, message, probed_data, reason, probe_tasks = rule_executor.audit(rule, opts)

            if status == "ERROR" then
                if not quiet then
                    log.error("[%s] Engine Error: %s", rule.id, message)
                end
                add_rule_result(rule, "ERROR", message)
                hard_failures = hard_failures + 1
            elseif status == "PASS" then
                if opts.verbose and not quiet then
                    output.emit_verbose_rule_details(
                        rule, status, probed_data, nil, probe_tasks)
                end
                add_rule_result(rule, "PASS")
                passed = passed + 1
            elseif mode == "reinforce" then
                if opts.verbose and not quiet then
                    output.emit_verbose_rule_details(
                        rule, status, probed_data, reason, probe_tasks)
                end
                local result = add_rule_result(rule, "FAIL", reason)
                local enforce_status, enforce_err = rule_executor.enforce(rule, probed_data, dry_run)

                if enforce_status == "MANUAL" then
                    if not quiet then
                        log.info("[%s] MANUAL: %s", rule.id, enforce_err)
                    end
                    result.status = "MANUAL"
                    result.reason = tostring(enforce_err)
                    manual = manual + 1
                elseif enforce_status == "ERROR" then
                    if not quiet then
                        log.error("[%s] ENFORCE-ERROR: %s", rule.id, enforce_err)
                    end
                    result.status = "ENFORCE-ERROR"
                    result.reason = tostring(enforce_err)
                    hard_failures = hard_failures + 1
                elseif enforce_status == "SKIP" then
                    if not quiet then
                        log.info("[%s] DRY-RUN: would apply %d action(s)",
                            rule.id, #(rule.reinforce or {}))
                    end
                    result.status = "DRY-RUN"
                    result.reason = string.format("would apply %d action(s)", #(rule.reinforce or {}))
                    dry_run_pending = dry_run_pending + 1
                elseif enforce_status == "DONE" then
                    -- Clear SSH probe cache to force fresh sshd -T execution after config changes
                    local ssh_probe = require('seharden.probes.ssh')
                    if type(ssh_probe.clear_cache) == "function" then
                        ssh_probe.clear_cache()
                        if not quiet then
                            log.debug("Cleared SSH probe cache for fresh verification.")
                        end
                    end

                    local verify_status, verify_msg = rule_executor.audit(rule, opts)
                    if verify_status == "PASS" then
                        if not quiet then
                            log.info("[%s] FIXED: %s", rule.id, rule.desc)
                        end
                        result.status = "FIXED"
                        result.reason = nil
                        fixed = fixed + 1
                    else
                        if not quiet then
                            log.error("[%s] FAILED-TO-FIX: %s", rule.id, verify_msg)
                        end
                        result.status = "FAILED-TO-FIX"
                        result.reason = tostring(verify_msg)
                        hard_failures = hard_failures + 1
                    end
                end
            else
                if opts.verbose and not quiet then
                    output.emit_verbose_rule_details(
                        rule, status, probed_data, reason, probe_tasks)
                end
                add_rule_result(rule, "FAIL", reason)
                hard_failures = hard_failures + 1
            end
        end
    end

    report.summary.passed = passed
    report.summary.fixed = fixed
    report.summary.failed = hard_failures
    report.summary.manual = manual
    report.summary.dry_run_pending = dry_run_pending

    if opts.verbose and not quiet then
        output.emit_verbose_summary(passed, fixed, hard_failures, manual, dry_run_pending, total_checks)
    elseif not quiet then
        log.info("SEHarden Finished. %d passed, %d fixed, %d failed, %d manual, %d dry-run-pending / %d total.",
            passed, fixed, hard_failures, manual, dry_run_pending, total_checks)
    end
    local exit_code = (hard_failures == 0 and dry_run_pending == 0) and 0 or 1
    report.exit_code = exit_code
    return exit_code, report
end

return M
