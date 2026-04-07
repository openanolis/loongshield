-- Unit tests for the seharden engine reinforce mode.
-- Tests FIXED / FAILED-TO-FIX / MANUAL / DRY-RUN result categories.

local engine = require('seharden.engine')
local enforcerloader = require('seharden.enforcerloader')

-- Helper: build a minimal rule that always FAILs the audit
local function make_failing_rule(id, reinforce_steps)
    return {
        id   = id or "test.rule",
        desc = "Test rule",
        probes = {
            { name = "val", func = "meta.always_fail", params = {} }
        },
        assertion = {
            all_of = {
                { actual = "%{probe.val}", compare = "is_true",
                  message = "always fails" }
            }
        },
        reinforce = reinforce_steps,
    }
end

-- Helper: build a rule that always PASSes
local function make_passing_rule(id)
    return {
        id   = id or "test.pass",
        desc = "Always passing rule",
        probes = {
            { name = "val", func = "meta.always_pass", params = {} }
        },
        assertion = {
            all_of = {
                { actual = "%{probe.val}", compare = "is_true",
                  message = "should not fail" }
            }
        },
    }
end

-- Stub probeloader so we don't need real system probes
local probeloader = require('seharden.probeloader')
local original_get = probeloader.get

local function with_probe_stubs(overrides, fn)
    local saved = probeloader.get
    probeloader.get = function(path)
        if overrides[path] then
            return overrides[path]
        end
        return saved(path)
    end
    local ok, err = pcall(fn)
    probeloader.get = saved
    if not ok then error(err, 2) end
end

-- Stub enforcerloader
local function with_enforcer_stubs(overrides, fn)
    local saved = enforcerloader.get
    enforcerloader.get = function(path)
        if overrides[path] then
            return overrides[path], path
        end
        return saved(path)
    end
    local ok, err = pcall(fn)
    enforcerloader.get = saved
    if not ok then error(err, 2) end
end

--------------------------------------------------------------------------------

function test_reinforce_pass_skips_enforcement()
    -- A passing rule should not invoke any enforcer
    local enforcer_called = false
    local rule = make_passing_rule("t.1")

    with_probe_stubs({
        ["meta.always_pass"] = function() return true end,
    }, function()
        with_enforcer_stubs({}, function()
            local ret = engine.run("reinforce", { rule }, {})
            assert(ret == 0, "Expected exit 0 for all-pass run")
        end)
    end)
    assert(enforcer_called == false, "Enforcer should not be called for passing rule")
end

function test_reinforce_manual_when_no_reinforce_field()
    -- A failing rule without a reinforce field → MANUAL, not a hard failure (exit 0)
    local rule = make_failing_rule("t.2", nil)

    with_probe_stubs({
        ["meta.always_fail"] = function() return false end,
    }, function()
        with_enforcer_stubs({}, function()
            local ret = engine.run("reinforce", { rule }, {})
            assert(ret == 0, "Expected exit 0 for MANUAL rule (informational, not hard failure)")
        end)
    end)
end

function test_reinforce_dry_run_does_not_call_enforcer()
    local enforcer_called = false
    local rule = make_failing_rule("t.3", {
        { action = "fake.action", params = {} }
    })

    with_probe_stubs({
        ["meta.always_fail"] = function() return false end,
    }, function()
        with_enforcer_stubs({
            ["fake.action"] = function()
                enforcer_called = true
                return true
            end,
        }, function()
            engine.run("reinforce", { rule }, { dry_run = true })
        end)
    end)
    assert(enforcer_called == false, "Enforcer must not be called in dry-run mode")
end

function test_reinforce_fixed_when_enforcer_succeeds_and_audit_passes()
    local probe_call_count = 0

    local rule = make_failing_rule("t.4", {
        { action = "fake.fix", params = {} }
    })

    -- First audit: FAIL. Second audit (re-verify): PASS.
    with_probe_stubs({
        ["meta.always_fail"] = function()
            probe_call_count = probe_call_count + 1
            return probe_call_count > 1  -- false first call, true on re-audit
        end,
    }, function()
        with_enforcer_stubs({
            ["fake.fix"] = function() return true end,
        }, function()
            local ret = engine.run("reinforce", { rule }, {})
            assert(ret == 0, "Expected exit 0 when rule is FIXED")
        end)
    end)
end

function test_reinforce_failed_to_fix_when_audit_still_fails()
    local rule = make_failing_rule("t.5", {
        { action = "fake.bad_fix", params = {} }
    })

    with_probe_stubs({
        ["meta.always_fail"] = function() return false end,
    }, function()
        with_enforcer_stubs({
            ["fake.bad_fix"] = function() return true end,
        }, function()
            local ret = engine.run("reinforce", { rule }, {})
            assert(ret == 1, "Expected exit 1 when rule FAILED-TO-FIX")
        end)
    end)
end

function test_reinforce_error_when_enforcer_not_found()
    local rule = make_failing_rule("t.6", {
        { action = "nonexistent.action", params = {} }
    })

    with_probe_stubs({
        ["meta.always_fail"] = function() return false end,
    }, function()
        -- Don't stub the enforcer — let enforcerloader return nil
        local ret = engine.run("reinforce", { rule }, {})
        assert(ret == 1, "Expected exit 1 when enforcer not found")
    end)
end

function test_reinforce_error_when_enforcer_throws()
    local rule = make_failing_rule("t.7", {
        { action = "fake.throws", params = {} }
    })

    with_probe_stubs({
        ["meta.always_fail"] = function() return false end,
    }, function()
        with_enforcer_stubs({
            ["fake.throws"] = function() error("something went wrong") end,
        }, function()
            local ret = engine.run("reinforce", { rule }, {})
            assert(ret == 1, "Expected exit 1 when enforcer throws")
        end)
    end)
end

function test_scan_mode_does_not_enforce()
    -- In scan mode, failing rules should not call enforcers
    local enforcer_called = false
    local rule = make_failing_rule("t.8", {
        { action = "fake.action", params = {} }
    })

    with_probe_stubs({
        ["meta.always_fail"] = function() return false end,
    }, function()
        with_enforcer_stubs({
            ["fake.action"] = function()
                enforcer_called = true
                return true
            end,
        }, function()
            engine.run("scan", { rule }, {})
        end)
    end)
    assert(enforcer_called == false, "Enforcer must not be called in scan mode")
end
