local function capture_print(fn)
    local saved_print = _G.print
    local lines = {}

    _G.print = function(...)
        local parts = {}
        for i = 1, select('#', ...) do
            parts[#parts + 1] = tostring(select(i, ...))
        end
        lines[#lines + 1] = table.concat(parts, ' ')
    end

    local ok, result = pcall(fn)
    _G.print = saved_print

    if not ok then
        error(result, 2)
    end

    return lines, result
end

local function capture_print_without_color(fn)
    local log = require('runtime.log')
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
    local saved_cli = package.loaded['seharden.cli']
    local saved_profile = package.loaded['seharden.profile']
    local saved_engine = package.loaded['seharden.engine']

    package.loaded['seharden.cli'] = nil
    package.loaded['seharden.profile'] = stubs.profile
    package.loaded['seharden.engine'] = stubs.engine

    local ok, err = pcall(function()
        local cli = require('seharden.cli')
        fn(cli)
    end)

    package.loaded['seharden.cli'] = saved_cli
    package.loaded['seharden.profile'] = saved_profile
    package.loaded['seharden.engine'] = saved_engine

    if not ok then
        error(err, 2)
    end
end

function test_help_output_includes_examples_and_exit_codes()
    with_stubbed_cli({
        profile = {
            load = function()
                error('profile.load should not be called for --help')
            end,
            get_rules_for_level = function()
                error('profile.get_rules_for_level should not be called for --help')
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called for --help')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--help' })
        end)
        local output = table.concat(lines, '\n')

        assert(ret == 0, 'Expected --help to return exit code 0')
        assert(
            output:find('SEHarden Security Benchmark Scanning & OS Hardening', 1, true),
            'Expected descriptive SEHarden header in help output'
        )
        assert(
            output:find('--verbose           Show rule-level evidence', 1, true),
            'Expected verbose option in help output'
        )
        assert(
            output:find('--format <format>   Output format: text or json', 1, true),
            'Expected output format option in help output'
        )
        assert(not output:find('--debug', 1, true), 'Expected help output to avoid the removed debug shortcut')
        assert(output:find('Exit Codes:', 1, true), 'Expected exit code section in help output')
        assert(output:find('Examples:', 1, true), 'Expected examples section in help output')
        assert(
            output:find('Current default: /etc/loongshield/seharden', 1, true),
            'Expected ruleset search path in help output'
        )
    end)
end

function test_json_format_outputs_machine_readable_report()
    local cjson = require('cjson.safe')
    local seen = {}

    with_stubbed_cli({
        profile = {
            load = function(config_name)
                seen.config_name = config_name
                return {
                    id = 'agentos_baseline',
                    default_level = 'baseline',
                    levels = {
                        { id = 'baseline' },
                    },
                }
            end,
            resolve_target_level = function(profile_data)
                return profile_data.default_level
            end,
            get_rules_for_level = function(_, level)
                seen.level = level
                return {
                    { id = 'rule.1', desc = 'demo rule' },
                }
            end,
            get_manual_review_items_for_level = function(_, level)
                seen.manual_level = level
                return {
                    {
                        area = 'operator',
                        item = 'Review external approval evidence.',
                        reason = 'External evidence is not host-local.',
                    },
                }
            end,
        },
        engine = {
            run = function(mode, rules, opts)
                seen.mode = mode
                seen.rule_count = #rules
                seen.quiet = opts.quiet
                return 1,
                    {
                        mode = mode,
                        dry_run = opts.dry_run or false,
                        rules = {
                            {
                                id = 'rule.1',
                                desc = 'demo rule',
                                status = 'FAIL',
                                reason = 'demo reason',
                            },
                        },
                        summary = {
                            passed = 0,
                            fixed = 0,
                            failed = 1,
                            manual = 0,
                            dry_run_pending = 0,
                            total = 1,
                        },
                        exit_code = 1,
                    }
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--config', 'agentos_baseline', '--format=json' })
        end)
        local output = table.concat(lines, '\n')
        local decoded, err = cjson.decode(output)

        assert(ret == 1, 'Expected JSON scan to preserve the engine exit code')
        assert(decoded ~= nil, 'Expected JSON output to decode: ' .. tostring(err))
        assert(decoded.schema_version == 1, 'Expected JSON schema version')
        assert(decoded.format == 'json', 'Expected JSON report to declare its format')
        assert(decoded.tool == 'loongshield', 'Expected JSON report tool id')
        assert(decoded.command == 'seharden', 'Expected JSON report command id')
        assert(decoded.status == 'failed', 'Expected non-zero JSON report status')
        assert(decoded.profile == 'agentos_baseline', 'Expected profile id in JSON report')
        assert(decoded.level == 'baseline', 'Expected resolved level in JSON report')
        assert(decoded.request.config == 'agentos_baseline', 'Expected requested config in JSON report')
        assert(decoded.request.profile == 'agentos_baseline', 'Expected resolved profile in JSON request')
        assert(decoded.request.level == 'baseline', 'Expected resolved level in JSON request')
        assert(decoded.request.mode == 'scan', 'Expected request mode in JSON report')
        assert(decoded.request.requested_level == cjson.null, 'Expected missing requested level to be JSON null')
        assert(decoded.rule_count == 1, 'Expected rule count in JSON report')
        assert(decoded.summary.failed == 1, 'Expected failed summary count in JSON report')
        assert(decoded.rules[1].id == 'rule.1', 'Expected rule id in JSON report')
        assert(decoded.rules[1].status == 'FAIL', 'Expected rule status in JSON report')
        assert(decoded.manual_review_count == 1, 'Expected manual review count in JSON report')
        assert(decoded.manual_review[1].area == 'operator', 'Expected manual review items in JSON report')
        assert(decoded.available_levels == cjson.null, 'Expected absent available levels to be JSON null')
        assert(decoded.error == cjson.null, 'Expected absent CLI error to be JSON null')
        assert(seen.config_name == 'agentos_baseline', 'Expected --config to reach profile.load')
        assert(seen.level == 'baseline', 'Expected default level to reach rule selection')
        assert(seen.manual_level == 'baseline', 'Expected default level to reach manual review filtering')
        assert(seen.mode == 'scan', 'Expected scan mode')
        assert(seen.rule_count == 1, 'Expected rules to reach engine')
        assert(seen.quiet == true, 'Expected JSON mode to request quiet engine output')
    end)
end

function test_json_format_reinforce_suppresses_enforcer_command_noise()
    local cjson = require('cjson.safe')
    local loader = require('seharden.loader')
    local packages_enforcer = require('seharden.enforcers.packages')
    local saved_dependencies = packages_enforcer._test_set_dependencies
    local saved_get_probe = loader.get_probe
    local package_installed = false

    packages_enforcer._test_set_dependencies({
        io_popen = function(cmd)
            assert(cmd:find("dnf install %-y audit 2>&1", 1) ~= nil,
                'Expected reinforce path to capture dnf output via io.popen')
            return {
                read = function()
                    return 'Last metadata expiration check: 1:00:00 ago.\nNothing to do.\n'
                end,
                close = function()
                    package_installed = true
                    return true, nil, 0
                end,
            }
        end,
    })

    loader.get_probe = function(path)
        if path == 'meta.package_installed' then
            return function()
                return package_installed
            end, path
        end
        return saved_get_probe(path)
    end

    local ok, err = pcall(function()
        with_stubbed_cli({
            profile = {
                load = function()
                    return {
                        id = 'agentos_baseline',
                        default_level = 'baseline',
                        levels = {
                            { id = 'baseline' },
                        },
                    }
                end,
                resolve_target_level = function(profile_data)
                    return profile_data.default_level
                end,
                get_rules_for_level = function()
                    return {
                        {
                            id = 'rule.install',
                            desc = 'Install a package through reinforce',
                            probes = {
                                { name = 'pkg', func = 'meta.package_installed', params = {} },
                            },
                            assertion = {
                                compare = 'is_true',
                                actual = '%{probe.pkg}',
                                message = 'package missing',
                            },
                            reinforce = {
                                { action = 'packages.install', params = { name = 'audit' } },
                            },
                        },
                    }
                end,
                get_manual_review_items_for_level = function()
                    return {}
                end,
            },
            engine = package.loaded['seharden.engine'] or require('seharden.engine'),
        }, function(cli)
            local lines, ret = capture_print(function()
                return cli.run({ '--reinforce', '--config', 'agentos_baseline', '--format=json' })
            end)
            local output = table.concat(lines, '\n')
            local decoded, decode_err = cjson.decode(output)

            assert(ret == 0, 'Expected reinforce JSON run to succeed after fix')
            assert(decoded ~= nil, 'Expected reinforce JSON output to decode: ' .. tostring(decode_err) .. '\n' .. output)
            assert(decoded.mode == 'reinforce', 'Expected reinforce mode in JSON report')
            assert(decoded.rule_count == 1, 'Expected one rule in JSON report')
            assert(decoded.rules[1].status == 'FIXED', 'Expected reinforce rule to verify as fixed')
            assert(decoded.summary.fixed == 1, 'Expected fixed summary count')
            assert(not output:find('Last metadata expiration check', 1, true),
                'Expected noisy enforcer stdout not to leak into JSON output')
            assert(not output:find('Nothing to do.', 1, true),
                'Expected enforcer chatter not to leak into JSON output')
        end)
    end)

    packages_enforcer._test_set_dependencies()
    loader.get_probe = saved_get_probe

    if not ok then
        error(err, 0)
    end
end

function test_json_format_parse_error_is_json()
    local cjson = require('cjson.safe')

    with_stubbed_cli({
        profile = {
            load = function()
                error('profile.load should not be called on parse errors')
            end,
            get_rules_for_level = function()
                error('profile.get_rules_for_level should not be called on parse errors')
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called on parse errors')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--format', 'json', '--bogus' })
        end)
        local decoded = cjson.decode(table.concat(lines, '\n'))

        assert(ret == 1, 'Expected parse error to return exit code 1')
        assert(decoded ~= nil, 'Expected parse error output to be JSON')
        assert(decoded.schema_version == 1, 'Expected JSON parse error schema version')
        assert(decoded.format == 'json', 'Expected JSON parse error format')
        assert(decoded.tool == 'loongshield', 'Expected JSON parse error tool id')
        assert(decoded.command == 'seharden', 'Expected JSON parse error command id')
        assert(decoded.status == 'failed', 'Expected JSON parse error status')
        assert(decoded.exit_code == 1, 'Expected JSON parse error exit code')
        assert(decoded.profile == cjson.null, 'Expected JSON parse error profile to be null')
        assert(decoded.request.config == cjson.null, 'Expected JSON parse error config to be null')
        assert(decoded.request.requested_level == cjson.null, 'Expected JSON parse error requested level to be null')
        assert(decoded.error == 'Unknown option: --bogus', 'Expected unknown option in JSON error')
        assert(decoded.summary.total == 0, 'Expected JSON parse error empty summary')
        assert(decoded.rule_count == 0, 'Expected JSON parse error empty rules')
        assert(type(decoded.rules) == 'table' and #decoded.rules == 0, 'Expected JSON parse error rules to be []')
        assert(
            type(decoded.manual_review) == 'table' and #decoded.manual_review == 0,
            'Expected JSON parse error manual_review to be []'
        )
        assert(decoded.available_levels == cjson.null, 'Expected JSON parse error available levels to be null')
    end)
end

function test_json_format_invalid_format_error_is_json()
    local cjson = require('cjson.safe')

    with_stubbed_cli({
        profile = {
            load = function()
                error('profile.load should not be called for invalid format')
            end,
            get_rules_for_level = function()
                error('profile.get_rules_for_level should not be called')
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called for invalid format')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--format', 'json', '--format', 'xml' })
        end)
        local decoded = cjson.decode(table.concat(lines, '\n'))

        assert(ret == 1, 'Expected invalid format to return exit code 1')
        assert(decoded ~= nil, 'Expected invalid format output to be JSON')
        assert(decoded.schema_version == 1, 'Expected JSON schema version')
        assert(decoded.format == 'json', 'Expected JSON format')
        assert(decoded.status == 'failed', 'Expected failed status')
        assert(
            decoded.error == "Unsupported output format 'xml'. Expected 'text' or 'json'.",
            'Expected unsupported format error'
        )
        assert(decoded.rules ~= nil and #decoded.rules == 0, 'Expected empty rules array')
        assert(decoded.manual_review ~= nil and #decoded.manual_review == 0, 'Expected empty manual_review array')
    end)
end

function test_json_format_mutually_exclusive_modes_is_json_contract()
    local cjson = require('cjson.safe')

    with_stubbed_cli({
        profile = {
            load = function()
                error('profile.load should not be called for mutually exclusive modes')
            end,
            get_rules_for_level = function()
                error('profile.get_rules_for_level should not be called')
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called for mutually exclusive modes')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--scan', '--reinforce', '--format', 'json' })
        end)
        local decoded = cjson.decode(table.concat(lines, '\n'))

        assert(ret == 1, 'Expected mutually exclusive modes to return exit code 1')
        assert(decoded.schema_version == 1, 'Expected JSON schema version')
        assert(decoded.tool == 'loongshield', 'Expected JSON tool id')
        assert(decoded.command == 'seharden', 'Expected JSON command id')
        assert(decoded.status == 'failed', 'Expected failed status')
        assert(decoded.rules ~= nil and #decoded.rules == 0, 'Expected empty rules array')
        assert(decoded.rule_count == 0, 'Expected empty rule count')
        assert(
            decoded.error == 'Options --scan and --reinforce are mutually exclusive.',
            'Expected mutually exclusive mode error'
        )
    end)
end

function test_unknown_option_prints_error_and_usage()
    with_stubbed_cli({
        profile = {
            load = function()
                error('profile.load should not be called on parse errors')
            end,
            get_rules_for_level = function()
                error('profile.get_rules_for_level should not be called on parse errors')
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called on parse errors')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--bogus' })
        end)
        local output = table.concat(lines, '\n')

        assert(ret == 1, 'Expected unknown option to return exit code 1')
        assert(output:find('Unknown option: --bogus', 1, true), 'Expected unknown option message in output')
        assert(output:find('Usage: loongshield seharden', 1, true), 'Expected usage text after parse error')
    end)
end

function test_equals_form_options_flow_into_engine()
    local seen = {}

    with_stubbed_cli({
        profile = {
            load = function(config_name)
                seen.config_name = config_name
                return {
                    id = 'agentos_baseline',
                    levels = {
                        { id = 'baseline' },
                    },
                }
            end,
            get_rules_for_level = function(_, level)
                seen.level = level
                return {
                    { id = 'rule.1', desc = 'demo rule' },
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
        },
    }, function(cli)
        local _, ret = capture_print(function()
            return cli.run({
                '--reinforce',
                '--config=agentos_baseline',
                '--level=baseline',
                '--dry-run',
            })
        end)

        assert(ret == 0, 'Expected successful CLI run')
        assert(seen.config_name == 'agentos_baseline', 'Expected inline --config value to be parsed')
        assert(seen.level == 'baseline', 'Expected inline --level value to be parsed')
        assert(seen.mode == 'reinforce', 'Expected reinforce mode to be selected')
        assert(seen.rule_count == 1, 'Expected rule list to flow into engine')
        assert(seen.dry_run == true, 'Expected --dry-run to reach the engine')
    end)
end

function test_invalid_level_lists_available_levels()
    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = 'agentos_baseline',
                    levels = {
                        { id = 'baseline' },
                        { id = 'strict' },
                    },
                }
            end,
            get_rules_for_level = function()
                return nil
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called when level resolution fails')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--config', 'agentos_baseline', '--level', 'missing' })
        end)
        local output = table.concat(lines, '\n')

        assert(ret == 1, 'Expected invalid level to return exit code 1')
        assert(
            output:find("Available levels for profile 'agentos_baseline': baseline, strict", 1, true),
            'Expected available level list in output'
        )
    end)
end

function test_json_format_invalid_level_lists_available_levels()
    local cjson = require('cjson.safe')

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = 'agentos_baseline',
                    levels = {
                        { id = 'baseline' },
                        { id = 'strict' },
                    },
                }
            end,
            get_rules_for_level = function()
                return nil
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called when no rules are available')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--config', 'agentos_baseline', '--level', 'missing', '--format', 'json' })
        end)
        local decoded = cjson.decode(table.concat(lines, '\n'))

        assert(ret == 1, 'Expected invalid level to return exit code 1')
        assert(decoded.schema_version == 1, 'Expected JSON schema version')
        assert(decoded.error:find("No rules available for level 'missing'.", 1, true), 'Expected invalid level error')
        assert(decoded.request.config == 'agentos_baseline', 'Expected requested config')
        assert(decoded.request.requested_level == 'missing', 'Expected requested level')
        assert(decoded.available_levels[1] == 'baseline', 'Expected sorted available level')
        assert(decoded.available_levels[2] == 'strict', 'Expected sorted available level')
        assert(decoded.rules ~= nil and #decoded.rules == 0, 'Expected empty rules array')
        assert(decoded.manual_review ~= nil and #decoded.manual_review == 0, 'Expected empty manual_review array')
    end)
end

function test_scan_surfaces_manual_review_items_from_profile()
    local seen = {}

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = 'dengbao_alinux3_l3',
                    levels = {
                        { id = 'l1_server' },
                    },
                }
            end,
            get_rules_for_level = function(_, level)
                seen.rule_level = level
                return {
                    { id = '1.1.1', desc = 'demo rule' },
                }
            end,
            get_manual_review_items_for_level = function(_, level)
                seen.manual_level = level
                return {
                    {
                        area = 'intrusion_prevention',
                        item = 'Review approved service exposure and file-sharing exceptions.',
                        reason = 'Approved listening services depend on deployment topology.',
                    },
                    {
                        area = 'audit',
                        item = 'Verify periodic audit backup evidence.',
                        reason = 'External retention evidence is outside host-local coverage.',
                    },
                }
            end,
        },
        engine = {
            run = function(_, _, opts)
                seen.verbose = opts.verbose
                return 0
            end,
        },
    }, function(cli)
        local lines, ret = capture_print_without_color(function()
            return cli.run({ '--config', 'dengbao_3', '--verbose' })
        end)
        local output = table.concat(lines, '\n')

        assert(ret == 0, 'Expected scan with manual review items to succeed')
        assert(seen.rule_level == nil, 'Expected all-level scan to omit explicit level selector')
        assert(seen.manual_level == nil, 'Expected manual review filtering to use the same all-level scope')
        assert(seen.verbose == true, 'Expected verbose flag to still reach the engine')
        assert(
            output:find(
                "SEHarden scan: profile='dengbao_alinux3_l3', level='all', 1 rule(s), 2 manual-review item(s)",
                1,
                true
            ),
            'Expected verbose scan header to include manual-review count'
        )
        assert(
            output:find('Manual Review Summary: 2 item(s) outside automated coverage', 1, true),
            'Expected scan output to include a manual review summary'
        )
        assert(
            output:find(
                '  - [intrusion_prevention] Review approved service exposure and file-sharing exceptions.',
                1,
                true
            ),
            'Expected scan output to enumerate manual-review items'
        )
        assert(
            output:find('    reason: Approved listening services depend on deployment topology.', 1, true),
            'Expected scan output to include manual-review reasons'
        )
    end)
end

function test_profile_default_level_applies_when_level_is_omitted()
    local seen = {}

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = 'agentos_baseline',
                    default_level = 'baseline',
                    levels = {
                        { id = 'baseline' },
                        { id = 'openclaw', inherits_from = { 'baseline' } },
                    },
                }
            end,
            resolve_target_level = function(profile_data, requested_level)
                seen.requested_level = requested_level
                return profile_data.default_level
            end,
            get_rules_for_level = function(_, level)
                seen.rule_level = level
                return {
                    { id = 'rule.1', desc = 'demo rule' },
                }
            end,
            get_manual_review_items_for_level = function(_, level)
                seen.manual_level = level
                return {}
            end,
        },
        engine = {
            run = function(_, _, _)
                return 0
            end,
        },
    }, function(cli)
        local lines, ret = capture_print_without_color(function()
            return cli.run({ '--config', 'agentos_baseline', '--verbose' })
        end)
        local output = table.concat(lines, '\n')

        assert(ret == 0, 'Expected scan with profile default level to succeed')
        assert(seen.requested_level == nil, 'Expected omitted --level to remain nil before defaulting')
        assert(seen.rule_level == 'baseline', 'Expected profile default level to scope rule selection')
        assert(seen.manual_level == 'baseline', 'Expected profile default level to scope manual review selection')
        assert(
            output:find("SEHarden scan: profile='agentos_baseline', level='baseline', 1 rule%(s%)", 1) ~= nil,
            'Expected verbose scan header to show the resolved default level'
        )
    end)
end

function test_verbose_reaches_engine_without_forcing_debug_log_level()
    local log = require('runtime.log')
    local saved_level = log.level
    local seen = {}

    log.level = 'info'

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = 'agentos_baseline',
                    levels = {
                        { id = 'baseline' },
                    },
                }
            end,
            get_rules_for_level = function()
                return {
                    { id = 'rule.1', desc = 'demo rule' },
                }
            end,
        },
        engine = {
            run = function(_, _, opts)
                seen.verbose = opts.verbose
                return 0
            end,
        },
    }, function(cli)
        local lines, ret = capture_print_without_color(function()
            return cli.run({ '--verbose' })
        end)
        local output = table.concat(lines, '\n')

        assert(ret == 0, 'Expected --verbose run to succeed')
        assert(seen.verbose == true, 'Expected --verbose to reach the engine')
        assert(log.level == 'info', 'Expected --verbose not to force debug log level')
        assert(
            output:find("SEHarden scan: profile='agentos_baseline', level='all', 1 rule%(s%)"),
            'Expected --verbose to print a plain-text run header'
        )
        assert(not output:find('%[INFO', 1), 'Expected --verbose run header not to use info log formatting')
    end)

    log.level = saved_level
end

function test_removed_debug_shortcut_is_rejected()
    with_stubbed_cli({
        profile = {
            load = function()
                error('profile.load should not be called for removed --debug shortcut')
            end,
            get_rules_for_level = function()
                error('profile.get_rules_for_level should not be called for removed --debug shortcut')
            end,
        },
        engine = {
            run = function()
                error('engine.run should not be called for removed --debug shortcut')
            end,
        },
    }, function(cli)
        local lines, ret = capture_print(function()
            return cli.run({ '--debug' })
        end)
        local output = table.concat(lines, '\n')

        assert(ret == 1, 'Expected removed --debug shortcut to fail')
        assert(
            output:find('Unknown option: --debug', 1, true),
            'Expected removed --debug shortcut to be treated as an unknown option'
        )
    end)
end

function test_log_level_debug_sets_debug_log_level()
    local log = require('runtime.log')
    local saved_level = log.level

    with_stubbed_cli({
        profile = {
            load = function()
                return {
                    id = 'agentos_baseline',
                    levels = {
                        { id = 'baseline' },
                    },
                }
            end,
            get_rules_for_level = function()
                return {
                    { id = 'rule.1', desc = 'demo rule' },
                }
            end,
        },
        engine = {
            run = function()
                return 0
            end,
        },
    }, function(cli)
        local _, ret = capture_print(function()
            return cli.run({ '--log-level', 'debug' })
        end)

        assert(ret == 0, 'Expected --log-level debug run to succeed')
        assert(log.level == 'debug', 'Expected --log-level debug to set log level to debug')
    end)

    log.level = saved_level
end
