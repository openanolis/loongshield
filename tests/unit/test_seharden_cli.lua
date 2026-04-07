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

local function with_stubbed_cli(stubs, fn)
    local saved_cli = package.loaded["seharden.cli"]
    local saved_profile = package.loaded["seharden.profile"]
    local saved_engine = package.loaded["seharden.engine"]

    package.loaded["seharden.cli"] = nil
    package.loaded["seharden.profile"] = stubs.profile
    package.loaded["seharden.engine"] = stubs.engine

    local ok, err = pcall(function()
        local cli = require("seharden.cli")
        fn(cli)
    end)

    package.loaded["seharden.cli"] = saved_cli
    package.loaded["seharden.profile"] = saved_profile
    package.loaded["seharden.engine"] = saved_engine

    if not ok then
        error(err, 2)
    end
end

function test_help_output_includes_examples_and_exit_codes()
    with_stubbed_cli({
        profile = {
            load = function() error("profile.load should not be called for --help") end,
            get_rules_for_level = function() error("profile.get_rules_for_level should not be called for --help") end,
        },
        engine = {
            run = function() error("engine.run should not be called for --help") end,
        }
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ "--help" })
        end)
        local output = table.concat(lines, "\n")

        assert(ret == 0, "Expected --help to return exit code 0")
        assert(output:find("SEHarden Security Benchmark Scanning & OS Hardening", 1, true),
            "Expected descriptive SEHarden header in help output")
        assert(output:find("--verbose           Show rule-level evidence", 1, true),
            "Expected verbose option in help output")
        assert(not output:find("--debug", 1, true),
            "Expected help output to avoid the removed debug shortcut")
        assert(output:find("Exit Codes:", 1, true), "Expected exit code section in help output")
        assert(output:find("Examples:", 1, true), "Expected examples section in help output")
        assert(output:find("Current default: /etc/loongshield/seharden", 1, true),
            "Expected ruleset search path in help output")
    end)
end

function test_unknown_option_prints_error_and_usage()
    with_stubbed_cli({
        profile = {
            load = function() error("profile.load should not be called on parse errors") end,
            get_rules_for_level = function() error("profile.get_rules_for_level should not be called on parse errors") end,
        },
        engine = {
            run = function() error("engine.run should not be called on parse errors") end,
        }
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ "--bogus" })
        end)
        local output = table.concat(lines, "\n")

        assert(ret == 1, "Expected unknown option to return exit code 1")
        assert(output:find("Unknown option: --bogus", 1, true),
            "Expected unknown option message in output")
        assert(output:find("Usage: loongshield seharden", 1, true),
            "Expected usage text after parse error")
    end)
end

function test_equals_form_options_flow_into_engine()
    local seen = {}

    with_stubbed_cli({
        profile = {
            load = function(config_name)
                seen.config_name = config_name
                return {
                    id = "agentos_baseline",
                    levels = {
                        { id = "baseline" }
                    }
                }
            end,
            get_rules_for_level = function(_, level)
                seen.level = level
                return {
                    { id = "rule.1", desc = "demo rule" }
                }
            end,
        },
        engine = {
            run = function(mode, rules, opts)
                seen.mode = mode
                seen.rule_count = #rules
                seen.dry_run = opts.dry_run
                return 0
            end,
        }
    }, function(cli)
        local _, ret = capture_print(function()
            return cli.run({
                "--reinforce",
                "--config=agentos_baseline",
                "--level=baseline",
                "--dry-run"
            })
        end)

        assert(ret == 0, "Expected successful CLI run")
        assert(seen.config_name == "agentos_baseline", "Expected inline --config value to be parsed")
        assert(seen.level == "baseline", "Expected inline --level value to be parsed")
        assert(seen.mode == "reinforce", "Expected reinforce mode to be selected")
        assert(seen.rule_count == 1, "Expected rule list to flow into engine")
        assert(seen.dry_run == true, "Expected --dry-run to reach the engine")
    end)
end

function test_invalid_level_lists_available_levels()
    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = "agentos_baseline",
                    levels = {
                        { id = "baseline" },
                        { id = "strict" }
                    }
                }
            end,
            get_rules_for_level = function()
                return nil
            end,
        },
        engine = {
            run = function() error("engine.run should not be called when level resolution fails") end,
        }
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ "--config", "agentos_baseline", "--level", "missing" })
        end)
        local output = table.concat(lines, "\n")

        assert(ret == 1, "Expected invalid level to return exit code 1")
        assert(output:find("Available levels for profile 'agentos_baseline': baseline, strict", 1, true),
            "Expected available level list in output")
    end)
end

function test_scan_surfaces_manual_review_items_from_profile()
    local seen = {}

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = "dengbao_alinux3_l3",
                    levels = {
                        { id = "l1_server" }
                    }
                }
            end,
            get_rules_for_level = function(_, level)
                seen.rule_level = level
                return {
                    { id = "1.1.1", desc = "demo rule" }
                }
            end,
            get_manual_review_items_for_level = function(_, level)
                seen.manual_level = level
                return {
                    {
                        area = "intrusion_prevention",
                        item = "Review approved service exposure and file-sharing exceptions.",
                        reason = "Approved listening services depend on deployment topology."
                    },
                    {
                        area = "audit",
                        item = "Verify periodic audit backup evidence.",
                        reason = "External retention evidence is outside host-local coverage."
                    }
                }
            end,
        },
        engine = {
            run = function(_, _, opts)
                seen.verbose = opts.verbose
                return 0
            end,
        }
    }, function(cli)
        local lines, ret = capture_print_without_color(function()
            return cli.run({ "--config", "dengbao_3", "--verbose" })
        end)
        local output = table.concat(lines, "\n")

        assert(ret == 0, "Expected scan with manual review items to succeed")
        assert(seen.rule_level == nil, "Expected all-level scan to omit explicit level selector")
        assert(seen.manual_level == nil, "Expected manual review filtering to use the same all-level scope")
        assert(seen.verbose == true, "Expected verbose flag to still reach the engine")
        assert(output:find("SEHarden scan: profile='dengbao_alinux3_l3', level='all', 1 rule(s), 2 manual-review item(s)", 1, true),
            "Expected verbose scan header to include manual-review count")
        assert(output:find("Manual Review Summary: 2 item(s) outside automated coverage", 1, true),
            "Expected scan output to include a manual review summary")
        assert(output:find("  - [intrusion_prevention] Review approved service exposure and file-sharing exceptions.", 1, true),
            "Expected scan output to enumerate manual-review items")
        assert(output:find("    reason: Approved listening services depend on deployment topology.", 1, true),
            "Expected scan output to include manual-review reasons")
    end)
end

function test_verbose_reaches_engine_without_forcing_debug_log_level()
    local log = require("runtime.log")
    local saved_level = log.level
    local seen = {}

    log.level = "info"

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = "agentos_baseline",
                    levels = {
                        { id = "baseline" }
                    }
                }
            end,
            get_rules_for_level = function()
                return {
                    { id = "rule.1", desc = "demo rule" }
                }
            end,
        },
        engine = {
            run = function(_, _, opts)
                seen.verbose = opts.verbose
                return 0
            end,
        }
    }, function(cli)
        local lines, ret = capture_print_without_color(function()
            return cli.run({ "--verbose" })
        end)
        local output = table.concat(lines, "\n")

        assert(ret == 0, "Expected --verbose run to succeed")
        assert(seen.verbose == true, "Expected --verbose to reach the engine")
        assert(log.level == "info", "Expected --verbose not to force debug log level")
        assert(output:find("SEHarden scan: profile='agentos_baseline', level='all', 1 rule%(s%)"),
            "Expected --verbose to print a plain-text run header")
        assert(not output:find("%[INFO", 1),
            "Expected --verbose run header not to use info log formatting")
    end)

    log.level = saved_level
end

function test_removed_debug_shortcut_is_rejected()
    with_stubbed_cli({
        profile = {
            load = function() error("profile.load should not be called for removed --debug shortcut") end,
            get_rules_for_level = function() error("profile.get_rules_for_level should not be called for removed --debug shortcut") end,
        },
        engine = {
            run = function() error("engine.run should not be called for removed --debug shortcut") end,
        }
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ "--debug" })
        end)
        local output = table.concat(lines, "\n")

        assert(ret == 1, "Expected removed --debug shortcut to fail")
        assert(output:find("Unknown option: --debug", 1, true),
            "Expected removed --debug shortcut to be treated as an unknown option")
    end)
end

function test_log_level_debug_sets_debug_log_level()
    local log = require("runtime.log")
    local saved_level = log.level

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = "agentos_baseline",
                    levels = {
                        { id = "baseline" }
                    }
                }
            end,
            get_rules_for_level = function()
                return {
                    { id = "rule.1", desc = "demo rule" }
                }
            end,
        },
        engine = {
            run = function()
                return 0
            end,
        }
    }, function(cli)
        local _, ret = capture_print(function()
            return cli.run({ "--log-level", "debug" })
        end)

        assert(ret == 0, "Expected --log-level debug run to succeed")
        assert(log.level == "debug", "Expected --log-level debug to set log level to debug")
    end)

    log.level = saved_level
end
