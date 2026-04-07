local log = require('runtime.log')
local engine = require('seharden.engine')
local profile = require('seharden.profile')
local os = require('os')

local M = {}

local DEFAULT_CONFIG = "cis_alinux_3"
local DEFAULT_RULES_PATH = os.getenv("LOONGSHIELD_SEHARDEN_RULES_PATH")
    or "/etc/loongshield/seharden"

local USAGE = string.format([[
Usage: loongshield seharden [--scan|--reinforce] [options]

SEHarden Security Benchmark Scanning & OS Hardening

Modes:
  --scan              Audit the selected profile and report failing rules. (Default)
  --reinforce         Apply reinforce actions for failing rules.

Options:
  --config <ruleset>  Profile name or YAML path to load. (Default: %s)
  --level <level>     Limit execution to a profile level (for example: l1_server).
  --dry-run           Preview reinforce actions without changing the system.
  --verbose           Show rule-level evidence in a human-friendly format.
  --log-level <level> Set the logging level (trace, debug, info, warn, error).
  -h, --help          Show this help message.

Ruleset Search Path:
  $LOONGSHIELD_SEHARDEN_RULES_PATH
  Current default: %s

Notes:
  The default profile '%s' targets Alibaba Cloud Linux 3 / OpenAnolis-style hosts.
  Use --config to select a different profile on other RPM-based systems.
  If --level is omitted, seharden runs all rules in the selected profile.
  --dry-run only affects --reinforce mode.

Exit Codes:
  0 - Scan passed, or reinforce completed with no remaining failures
  1 - CLI error, profile load error, scan failures, or dry-run pending changes

Examples:
  loongshield seharden
  loongshield seharden --config agentos_baseline
  loongshield seharden --config cis_alinux_3 --level l1_server
  loongshield seharden --config agentos_baseline --verbose
  loongshield seharden --reinforce --config agentos_baseline --dry-run
  loongshield seharden --reinforce --config /etc/loongshield/seharden/dengbao_3.yml
]], DEFAULT_CONFIG, DEFAULT_RULES_PATH, DEFAULT_CONFIG)

local function print_usage()
    print(USAGE)
end

local function get_level_ids(profile_data)
    local level_ids = {}

    if type(profile_data) ~= "table" or type(profile_data.levels) ~= "table" then
        return level_ids
    end

    for _, level in ipairs(profile_data.levels) do
        if type(level) == "table" and type(level.id) == "string" and level.id ~= "" then
            table.insert(level_ids, level.id)
        end
    end

    table.sort(level_ids)
    return level_ids
end

local function format_level_ids(profile_data)
    local level_ids = get_level_ids(profile_data)
    if #level_ids == 0 then
        return nil
    end

    return table.concat(level_ids, ", ")
end

local function get_manual_review_items(profile_data, target_level)
    if type(profile.get_manual_review_items_for_level) ~= "function" then
        return {}
    end

    local items, err = profile.get_manual_review_items_for_level(profile_data, target_level)
    if items == nil then
        log.warn("Failed to resolve manual review items: %s", tostring(err))
        return {}
    end

    return items
end

local function format_manual_review_suffix(mode, count)
    if mode ~= "scan" or count <= 0 then
        return ""
    end

    return string.format(", %d manual-review item(s)", count)
end

local function emit_manual_review_summary(items)
    if #items == 0 then
        return
    end

    print(string.format(
        "Manual Review Summary: %d item(s) outside automated coverage",
        #items))
    for _, entry in ipairs(items) do
        print(string.format("  - [%s] %s", entry.area, entry.item))
        print(string.format("    reason: %s", entry.reason))
    end
end

local function parse_args(argv)
    local opts = {}
    local i = 1

    while i <= #argv do
        local arg = argv[i]
        local inline_key, inline_value = arg:match("^%-%-([%w%-]+)=(.+)$")

        if inline_key == "config" or inline_key == "level" or inline_key == "log-level" then
            opts[inline_key] = inline_value
            i = i + 1
        elseif arg == "--config" or arg == "--log-level" or arg == "--level" then
            if i >= #argv then
                return nil, string.format("Option '%s' requires a value.", arg)
            end

            local key = arg:sub(3)
            opts[key] = argv[i + 1]
            i = i + 2
        elseif arg == "--scan" or arg == "--reinforce" or arg == "--help" or arg == "--dry-run" then
            opts[arg:sub(3)] = true
            i = i + 1
        elseif arg == "--verbose" then
            opts.verbose = true
            i = i + 1
        elseif arg == "-h" then
            opts.help = true
            i = i + 1
        else
            return nil, string.format("Unknown option: %s", arg)
        end
    end

    return opts
end

function M.run(argv)
    local opts, err = parse_args(argv)
    if not opts then
        log.error(err)
        print("")
        print_usage()
        return 1
    end

    local log_level = opts['log-level'] or os.getenv("LOG_LEVEL")
    if log_level then
        log.setLevel(log_level)
    end

    if opts.help then
        print_usage()
        return 0
    end

    if opts.scan and opts.reinforce then
        log.error("Options --scan and --reinforce are mutually exclusive.")
        print("")
        print_usage()
        return 1
    end

    local mode = opts.reinforce and "reinforce" or "scan"
    if opts["dry-run"] and mode ~= "reinforce" then
        log.warn("Option '--dry-run' only affects --reinforce mode. Continuing with scan.")
    end

    local config_name = opts.config or DEFAULT_CONFIG
    local target_level = opts.level

    local profile_data = profile.load(config_name)
    if not profile_data then
        return 1
    end

    local rules_to_run = profile.get_rules_for_level(profile_data, target_level)
    if not rules_to_run then
        local available_levels = format_level_ids(profile_data)
        if target_level and available_levels then
            log.info("Available levels for profile '%s': %s",
                profile_data.id or config_name, available_levels)
        end
        return 1
    end

    local manual_review_items = get_manual_review_items(profile_data, target_level)
    local manual_review_suffix = format_manual_review_suffix(mode, #manual_review_items)

    if opts.verbose then
        print(string.format("%s: profile='%s', level='%s', %d rule(s)%s",
            log.style("SEHarden " .. mode, "bold", "cyan"),
            profile_data.id or config_name,
            target_level or "all",
            #rules_to_run,
            manual_review_suffix))
    else
        log.info("Running SEHarden %s with profile '%s' at level '%s' (%d rule(s)%s).",
            mode,
            profile_data.id or config_name,
            target_level or "all",
            #rules_to_run,
            manual_review_suffix)
    end

    local exit_code = engine.run(mode, rules_to_run, {
        dry_run = opts["dry-run"],
        verbose = opts.verbose or false,
    })

    if mode == "scan" then
        emit_manual_review_summary(manual_review_items)
    end

    return exit_code
end

return M
