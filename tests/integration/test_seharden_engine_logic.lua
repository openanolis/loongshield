local engine = require('seharden.engine')

local function run_rule(rule)
    return engine.run("scan", { rule })
end

local function run_rule_with_opts(rule, opts)
    return engine.run("scan", { rule }, opts)
end

local function capture_print(fn)
    local saved_print = _G.print
    local lines = {}

    _G.print = function(...)
        local parts = {}
        for i = 1, select("#", ...) do
            parts[#parts + 1] = tostring(select(i, ...))
        end
        lines[#lines + 1] = table.concat(parts, " ")
    end

    local ok, result = pcall(fn)
    _G.print = saved_print

    if not ok then
        error(result, 2)
    end

    return lines, result
end

local function capture_print_without_color(fn)
    local log = require("runtime.log")
    local saved_usecolor = log.usecolor

    log.usecolor = false
    local ok, lines, result = pcall(capture_print, fn)
    log.usecolor = saved_usecolor

    if not ok then
        error(lines, 2)
    end

    return lines, result
end

function test_engine_all_of_passes()
    local rule = {
        id = "TEST-ALL-OF",
        desc = "all_of pass",
        assertion = {
            all_of = {
                { actual = 1, compare = "equals", expected = 1 },
                { actual = "ok", compare = "equals", expected = "ok" }
            }
        }
    }
    local rc = run_rule(rule)
    assert(rc == 0, "Expected all_of to pass")
end

function test_engine_any_of_passes()
    local rule = {
        id = "TEST-ANY-OF",
        desc = "any_of pass",
        assertion = {
            any_of = {
                { actual = 1, compare = "equals", expected = 2 },
                { actual = "ok", compare = "equals", expected = "ok" }
            }
        }
    }
    local rc = run_rule(rule)
    assert(rc == 0, "Expected any_of to pass when one condition matches")
end

function test_engine_for_all_passes()
    local rule = {
        id = "TEST-FOR-ALL",
        desc = "for_all pass",
        assertion = {
            compare = "for_all",
            actual = {
                { val = "ok" },
                { val = "ok" }
            },
            expected = {
                compare = "equals",
                actual = "%{item.val}",
                expected = "ok"
            }
        }
    }
    local rc = run_rule(rule)
    assert(rc == 0, "Expected for_all to pass when all items match")
end

function test_engine_for_all_fails()
    local rule = {
        id = "TEST-FOR-ALL-FAIL",
        desc = "for_all fail",
        assertion = {
            compare = "for_all",
            actual = {
                { val = "ok" },
                { val = "no" }
            },
            expected = {
                compare = "equals",
                actual = "%{item.val}",
                expected = "ok"
            }
        }
    }
    local rc = run_rule(rule)
    assert(rc == 1, "Expected for_all to fail when any item mismatches")
end

function test_engine_for_all_preserves_boolean_item_values()
    local rule = {
        id = "TEST-FOR-ALL-BOOL",
        desc = "for_all bool pass",
        assertion = {
            compare = "for_all",
            actual = {
                { flag = false },
                { flag = false }
            },
            expected = {
                compare = "is_false",
                actual = "%{item.flag}"
            }
        }
    }
    local rc = run_rule(rule)
    assert(rc == 0, "Expected exact item template to preserve boolean false")
end

function test_engine_explicit_false_actual_is_not_replaced_by_item_context()
    local rule = {
        id = "TEST-LITERAL-FALSE",
        desc = "literal false actual",
        assertion = {
            compare = "for_all",
            actual = {
                { flag = true }
            },
            expected = {
                compare = "is_false",
                actual = false,
                key = "flag"
            }
        }
    }
    local rc = run_rule(rule)
    assert(rc == 0, "Expected literal false actual to remain false")
end

function test_engine_preserves_false_probe_values()
    local rule = {
        id = "TEST-FALSE-PROBE",
        desc = "false probe value",
        probes = {
            { name = "p1", func = "meta.always_false", params = {} }
        },
        assertion = {
            all_of = {
                { actual = "%{probe.p1}", compare = "is_false" }
            }
        }
    }

    local loader = require('seharden.loader')
    local saved = loader.get_probe
    loader.get_probe = function(path)
        if path == "meta.always_false" then
            return function() return false end, path
        end
        return saved(path)
    end

    local ok, rc = pcall(run_rule, rule)
    loader.get_probe = saved

    assert(ok, "Expected false-valued probe test to run without throwing")
    assert(rc == 0, "Expected false probe value to remain false in assertions")
end

function test_engine_unknown_comparator_fails()
    local rule = {
        id = "TEST-BAD-COMP",
        desc = "bad comparator",
        assertion = {
            compare = "does_not_exist",
            actual = 1,
            expected = 1
        }
    }
    local rc = run_rule(rule)
    assert(rc == 1, "Expected unknown comparator to fail")
end

function test_engine_probe_error_fails()
    local loader = require('seharden.loader')
    local saved = loader.get_probe
    loader.get_probe = function(path)
        if path == "file.find_pattern" then
            return function()
                error("probe failed")
            end, path
        end
        return saved(path)
    end

    local rule = {
        id = "TEST-PROBE-ERR",
        desc = "probe error",
        probes = {
            { name = "p1", func = "file.find_pattern", params = { paths = { "/tmp" }, pattern = "x" } }
        },
        assertion = {
            all_of = {
                { actual = "%{probe.p1}", key = "found", compare = "is_true" }
            }
        }
    }

    local ok, rc = pcall(run_rule, rule)
    loader.get_probe = saved

    assert(ok, "Expected probe error test to complete without throwing")
    assert(rc == 1, "Expected engine to fail when probe errors")
end

function test_engine_probe_nil_error_fails()
    local rc = run_rule({
        id = "TEST-PROBE-NIL-ERR",
        desc = "probe nil error",
        probes = {
            { name = "bad", func = "file.parse_key_values", params = {} }
        },
        assertion = {
            compare = "is_truthy",
            actual = "%{probe.bad}"
        }
    })
    assert(rc == 1, "Expected engine to fail when a probe returns nil,error")
end

function test_engine_failure_message_formats_actual_once()
    local lines, rc = capture_print(function()
        return run_rule({
            id = "TEST-ACTUAL-FORMAT",
            desc = "actual formatting",
            assertion = {
                compare = "equals",
                actual = "unknown",
                expected = "disabled",
                message = "Expected service state"
            }
        })
    end)
    local output = table.concat(lines, "\n")

    assert(rc == 1, "Expected failing rule to return exit code 1")
    assert(output:find("actual: 'unknown'", 1, true),
        "Expected failure output to include a single quoted actual value")
    assert(not output:find("actual: ''unknown''", 1, true),
        "Expected failure output to avoid double-quoted actual value")
end

function test_engine_failure_message_uses_probe_error_when_actual_is_nil()
    local loader = require('seharden.loader')
    local saved = loader.get_probe
    loader.get_probe = function(path)
        if path == "meta.probe_error" then
            return function()
                return {
                    value = nil,
                    error = "sshd command failed with exit code: 13",
                }
            end, path
        end
        return saved(path)
    end

    local lines, rc = capture_print(function()
        return run_rule({
            id = "TEST-PROBE-DETAIL",
            desc = "probe detail formatting",
            probes = {
                { name = "ssh_value", func = "meta.probe_error", params = {} }
            },
            assertion = {
                compare = "equals",
                actual = "%{probe.ssh_value}",
                key = "value",
                expected = "no",
                message = "Expected SSH setting"
            }
        })
    end)
    loader.get_probe = saved

    local output = table.concat(lines, "\n")

    assert(rc == 1, "Expected rule with probe error to fail")
    assert(output:find("probe error: sshd command failed with exit code: 13", 1, true),
        "Expected failure output to surface the probe error instead of nil")
    assert(not output:find("actual: nil", 1, true),
        "Expected failure output to avoid the unhelpful 'actual: nil' text when a probe error exists")
end

function test_engine_for_all_failure_reports_first_failing_item()
    local lines, rc = capture_print(function()
        return run_rule({
            id = "TEST-FOR-ALL-HUMAN",
            desc = "for_all human formatting",
            assertion = {
                compare = "for_all",
                actual = {
                    { path = "/ok", mode = 360 },
                    { path = "/bad", mode = 493 },
                },
                expected = {
                    compare = "mode_is_no_more_permissive",
                    actual = "%{item.mode}",
                    expected = 488
                },
                message = "Permissions are too open"
            }
        })
    end)

    local output = table.concat(lines, "\n")

    assert(rc == 1, "Expected for_all mismatch to fail")
    assert(output:find("first failing item #2", 1, true),
        "Expected failure output to identify the first failing list item")
    assert(output:find("path='/bad'", 1, true),
        "Expected failure output to include the failing item's path")
    assert(output:find("mode=0755", 1, true),
        "Expected failure output to format permission modes in octal")
    assert(not output:find("path='/ok'", 1, true),
        "Expected failure output to avoid dumping compliant items")
end

function test_engine_verbose_mode_prints_human_friendly_probe_summaries()
    local loader = require('seharden.loader')
    local saved = loader.get_probe
    loader.get_probe = function(path)
        if path == "meta.verbose_failure_probe" then
            return function()
                return { value = "yes", available = true }
            end, path
        end
        return saved(path)
    end

    local lines, rc = capture_print_without_color(function()
        return run_rule_with_opts({
            id = "TEST-VERBOSE-HUMAN",
            desc = "verbose formatting",
            probes = {
                {
                    name = "ssh_effective",
                    func = "meta.verbose_failure_probe",
                    params = {}
                }
            },
            assertion = {
                compare = "equals",
                actual = "%{probe.ssh_effective}",
                key = "value",
                expected = "no",
                message = "Expected SSH setting"
            }
        }, { verbose = true })
    end)
    loader.get_probe = saved
    local output = table.concat(lines, "\n")

    assert(rc == 1, "Expected verbose failure rule to fail")
    assert(output:find("FAIL [TEST-VERBOSE-HUMAN] verbose formatting", 1, true),
        "Expected verbose mode to print a concise rule heading")
    assert(output:find("reason: Expected SSH setting (actual: 'yes')", 1, true),
        "Expected verbose mode to print the failure reason inline")
    assert(output:find("- ssh_effective:", 1, true),
        "Expected verbose mode to print per-probe headings")
    assert(output:find("value='yes'", 1, true),
        "Expected verbose mode to print summarized probe values")
    assert(not output:find("[WARN", 1, true),
        "Expected verbose mode to avoid duplicate warn log lines for rule failures")
    assert(not output:find("Evaluating 'all_of' block", 1, true),
        "Expected verbose mode to avoid developer debug traces")
    assert(not output:find("\27%[", 1),
        "Expected non-TTY verbose output to remain plain text without ANSI escapes")
end

function test_engine_verbose_mode_prints_passed_rule_headings()
    local loader = require('seharden.loader')
    local saved = loader.get_probe
    loader.get_probe = function(path)
        if path == "meta.verbose_pass_probe" then
            return function()
                return { value = "ok" }
            end, path
        end
        return saved(path)
    end

    local lines, rc = capture_print_without_color(function()
        return run_rule_with_opts({
            id = "TEST-VERBOSE-PASS",
            desc = "verbose pass formatting",
            probes = {
                {
                    name = "pass_probe",
                    func = "meta.verbose_pass_probe",
                    params = {}
                }
            },
            assertion = {
                compare = "equals",
                actual = "%{probe.pass_probe}",
                key = "value",
                expected = "ok"
            }
        }, { verbose = true })
    end)
    loader.get_probe = saved
    local output = table.concat(lines, "\n")

    assert(rc == 0, "Expected verbose passing rule to succeed")
    assert(output:find("PASS [TEST-VERBOSE-PASS] verbose pass formatting", 1, true),
        "Expected verbose mode to print passing rule headings")
    assert(output:find("- pass_probe: value='ok'", 1, true),
        "Expected verbose mode to print summarized evidence for passing rules")
end

function test_engine_verbose_mode_focuses_relevant_probe_keys_and_compacts_large_maps()
    local loader = require('seharden.loader')
    local saved = loader.get_probe
    loader.get_probe = function(path)
        if path == "meta.login_defs_verbose" then
            return function()
                return {
                    CREATE_HOME = "yes",
                    ENCRYPT_METHOD = "YESCRYPT",
                    GID_MAX = "60000",
                    GID_MIN = "1000",
                    PASS_MAX_DAYS = "99999",
                    PASS_MIN_DAYS = "0",
                }
            end, path
        elseif path == "meta.login_defs_settings_verbose" then
            return function()
                return {
                    CREATE_HOME = "yes",
                    ENCRYPT_METHOD = "YESCRYPT",
                    GID_MAX = "60000",
                    GID_MIN = "1000",
                    PASS_MAX_DAYS = "99999",
                    PASS_MIN_DAYS = "0",
                }
            end, path
        elseif path == "meta.login_defs_umask_verbose" then
            return function()
                return {
                    compliant = false,
                    value = "022"
                }
            end, path
        end
        return saved(path)
    end

    local lines, rc = capture_print_without_color(function()
        return run_rule_with_opts({
            id = "TEST-VERBOSE-FOCUS",
            desc = "verbose focus formatting",
            probes = {
                {
                    name = "login_defs",
                    func = "meta.login_defs_verbose",
                    params = {}
                },
                {
                    name = "login_defs_settings",
                    func = "meta.login_defs_settings_verbose",
                    params = {}
                },
                {
                    name = "login_defs_umask",
                    func = "meta.login_defs_umask_verbose",
                    params = {}
                }
            },
            assertion = {
                all_of = {
                    {
                        compare = "less_than_or_equal",
                        actual = "%{probe.login_defs}",
                        key = "PASS_MAX_DAYS",
                        expected = 90,
                        message = "Expected PASS_MAX_DAYS to be 90 or less"
                    },
                    {
                        compare = "is_true",
                        actual = "%{probe.login_defs_umask}",
                        key = "compliant",
                        message = "Expected a compliant umask"
                    }
                }
            }
        }, { verbose = true })
    end)
    loader.get_probe = saved
    local output = table.concat(lines, "\n")

    assert(rc == 1, "Expected focused verbose rule to fail")
    assert(output:find("login_defs: PASS_MAX_DAYS='99999'", 1, true),
        "Expected verbose mode to show only the relevant login_defs key")
    assert(output:find("login_defs_settings: table(6 keys)", 1, true),
        "Expected verbose mode to compact unrelated large maps")
    assert(output:find("login_defs_umask:", 1, true)
        and output:find("compliant=false", 1, true)
        and output:find("value='022'", 1, true),
        "Expected verbose mode to keep concise summaries for small relevant probes")
    assert(not output:find("CREATE_HOME='yes'", 1, true),
        "Expected verbose mode to avoid dumping unrelated large-map entries")
end

function test_engine_verbose_mode_indents_multiline_failure_reasons()
    local lines, rc = capture_print_without_color(function()
        return run_rule_with_opts({
            id = "TEST-VERBOSE-MULTILINE",
            desc = "verbose multiline reason",
            assertion = {
                any_of = {
                    {
                        compare = "equals",
                        actual = "enabled",
                        expected = "disabled",
                        message = "Expected disabled"
                    },
                    {
                        compare = "equals",
                        actual = "present",
                        expected = "absent",
                        message = "Expected absent"
                    }
                }
            }
        }, { verbose = true })
    end)
    local output = table.concat(lines, "\n")

    assert(rc == 1, "Expected verbose multiline rule to fail")
    assert(output:find("reason: No conditions in 'any_of' were met:", 1, true),
        "Expected verbose mode to print the any_of failure summary")
    assert(output:find("\n      - Child #1 failed: Expected disabled", 1, true),
        "Expected verbose mode to indent multiline reason children")
    assert(output:find("\n      - Child #2 failed: Expected absent", 1, true),
        "Expected verbose mode to indent each multiline reason child")
end

function test_engine_verbose_mode_prints_plain_summary_without_info_prefix()
    local lines, rc = capture_print_without_color(function()
        return run_rule_with_opts({
            id = "TEST-VERBOSE-SUMMARY",
            desc = "verbose summary",
            assertion = {
                compare = "equals",
                actual = "enabled",
                expected = "disabled",
                message = "Expected disabled"
            }
        }, { verbose = true })
    end)
    local output = table.concat(lines, "\n")

    assert(rc == 1, "Expected verbose summary rule to fail")
    assert(output:find("Summary: 0 passed, 0 fixed, 1 failed, 0 manual, 0 dry%-run%-pending / 1 total"),
        "Expected verbose mode to print a plain-text summary")
    assert(not output:find("%[INFO", 1),
        "Expected verbose mode summary not to use info log formatting")
end
