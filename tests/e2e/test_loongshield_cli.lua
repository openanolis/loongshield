local T = {}

local EXIT_MARKER = '__LOONGSHIELD_E2E_EXIT__:'

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function join_path(root, path)
    if path:sub(1, 1) == '/' then
        return path
    end
    return root:gsub('/$', '') .. '/' .. path
end

T.SRC_DIR = os.getenv('LOONGSHIELD_SRC_DIR') or '.'
T.BIN = join_path(
    T.SRC_DIR,
    os.getenv('LOONGSHIELD_E2E_BIN') or os.getenv('LOONGSHIELD_BIN') or 'build/src/daemon/loongshield'
)

local function create_temp_dir()
    local cmd = 'mktemp -d ' .. shell_escape((os.getenv('TMPDIR') or '/tmp') .. '/loongshield_e2e_cli.XXXXXX')
    local pipe = assert(io.popen(cmd, 'r'), 'Failed to create temporary directory')
    local path = (pipe:read('*l') or ''):gsub('%s+$', '')
    local ok = pipe:close()

    assert(ok and path ~= '', 'Failed to create temporary directory')
    return path
end

local function set_fixture_root(path)
    T.ROOT = path
    T.PROFILE = T.ROOT .. '/profile.yml'
    T.CONFIG = T.ROOT .. '/sshd_config'
    T.BANNER = T.ROOT .. '/issue'
end

local function write_file(path, content)
    local file = assert(io.open(path, 'w'), 'Failed to open for write: ' .. path)
    file:write(content)
    file:close()
end

local function read_file(path)
    local file = assert(io.open(path, 'r'), 'Failed to open for read: ' .. path)
    local content = file:read('*a')
    file:close()
    return content
end

local function assert_contains(haystack, needle, message)
    assert(haystack:find(needle, 1, true), message or ('Expected output to contain: ' .. needle))
end

local function assert_not_contains(haystack, needle, message)
    assert(not haystack:find(needle, 1, true), message or ('Expected output not to contain: ' .. needle))
end

local function assert_no_runtime_errors(output)
    assert_not_contains(output, 'Engine Error', 'Expected profile scan to finish without SEHarden engine errors')
    assert_not_contains(output, 'Runtime error', 'Expected profile scan to finish without Lua runtime errors')
    assert_not_contains(output, 'Failed to load suite', 'Expected profile scan to avoid test loader failures')
end

local function assert_file_exists(path)
    local file = io.open(path, 'r')
    if file then
        file:close()
        return
    end
    error('Expected file to exist: ' .. path, 2)
end

local function is_running_as_root()
    local pipe = io.popen('id -u 2>/dev/null', 'r')
    if not pipe then
        return false
    end

    local uid = pipe:read('*l')
    pipe:close()
    return uid == '0'
end

local function profile_path(path)
    return join_path(T.SRC_DIR, path)
end

local function seharden_scan_case(name, config_path, level, rules, manual)
    local args = {
        'seharden',
        '--scan',
        '--config',
        profile_path(config_path),
        '--verbose',
    }

    if level then
        args[#args + 1] = '--level'
        args[#args + 1] = level
    end

    return {
        name = name,
        level = level,
        rules = rules,
        manual = manual or 0,
        args = args,
    }
end

local function assert_scan_header(output, profile)
    local manual_suffix = profile.manual > 0 and string.format(', %d manual-review item(s)', profile.manual) or ''

    assert_contains(
        output,
        string.format(
            "SEHarden scan: profile='%s', level='%s', %d rule(s)%s",
            profile.name,
            profile.level,
            profile.rules,
            manual_suffix
        )
    )
end

local function run_loongshield(args, env)
    assert_file_exists(T.BIN)

    env = env or {}
    env.LOG_LEVEL = env.LOG_LEVEL or 'info'

    local cmd_parts = {}
    for key, value in pairs(env or {}) do
        assert(key:match('^[A-Za-z_][A-Za-z0-9_]*$'), 'Invalid environment variable name: ' .. tostring(key))
        cmd_parts[#cmd_parts + 1] = key .. '=' .. shell_escape(value)
    end
    cmd_parts[#cmd_parts + 1] = shell_escape(T.BIN)
    for _, arg in ipairs(args or {}) do
        cmd_parts[#cmd_parts + 1] = shell_escape(arg)
    end

    local marker = EXIT_MARKER .. tostring(os.time()) .. '_' .. tostring(math.random(1000000, 9999999)) .. ':'
    local cmd = table.concat(cmd_parts, ' ') .. " 2>&1; code=$?; printf '\\n" .. marker .. '%s\\n\' "$code"'
    local pipe = assert(io.popen(cmd, 'r'), 'Failed to run loongshield command')
    local output = pipe:read('*a') or ''
    pipe:close()

    local code = tonumber(output:match('\n' .. marker .. '(%d+)\n?$'))
    output = output:gsub('\n' .. marker .. '%d+\n?$', '')

    assert(code ~= nil, 'Failed to parse loongshield exit code from output:\n' .. output)
    return code, output
end

function T.setup(config_value, banner_value)
    set_fixture_root(create_temp_dir())

    write_file(T.CONFIG, 'MaxAuthTries=' .. tostring(config_value) .. '\n')
    write_file(T.BANNER, tostring(banner_value or 'development host') .. '\n')
    write_file(
        T.PROFILE,
        ([[
id: loongshield_e2e
version: "0.1.0"
default_level: baseline
levels:
  - id: baseline
  - id: strict
    inherits_from:
      - baseline
manual_review_required:
  - area: operator_procedure
    item: Review production exception approvals for the fixture profile.
    reason: Approval evidence is intentionally outside host-local automation.
    level:
      - baseline
rules:
  - id: e2e.max_auth_tries
    desc: Ensure fixture MaxAuthTries is hardened
    level:
      - baseline
    probes:
      - name: sshd
        func: file.parse_key_values
        params:
          path: %s
    assertion:
      actual: "%%{probe.sshd}"
      key: MaxAuthTries
      compare: equals
      expected: "4"
      message: MaxAuthTries must be 4
    reinforce:
      - action: file.set_key_value
        params:
          path: %s
          key: MaxAuthTries
          value: "4"
  - id: e2e.strict_banner
    desc: Ensure strict level sees the expected banner
    level:
      - strict
    probes:
      - name: banner
        func: file.find_pattern
        params:
          paths:
            - %s
          pattern: "^Authorized access only"
    assertion:
      actual: "%%{probe.banner}"
      key: found
      compare: is_true
      message: Strict banner must be present
]]):format(T.CONFIG, T.CONFIG, T.BANNER)
    )
end

function T.teardown()
    if T.ROOT then
        os.execute('rm -rf ' .. shell_escape(T.ROOT))
        T.ROOT = nil
    end
end

function test_top_level_cli_help_version_and_error_paths()
    local help_code, help_output = run_loongshield({ '--help' })
    assert(help_code == 0, 'Expected top-level --help to exit 0')
    assert_contains(help_output, 'Usage: loongshield <subcommand> [options]')
    assert_contains(help_output, 'version       Show loongshield version information')
    assert_contains(help_output, 'seharden      OS Security benchmarks & hardening')
    assert_contains(help_output, 'rpm           RPM package SBOM verification')

    local version_code, version_output = run_loongshield({ 'version' })
    assert(version_code == 0, 'Expected version command to exit 0')
    assert_contains(version_output, 'loongshield ')
    assert_contains(version_output, ' commit ')

    local missing_code, missing_output = run_loongshield({})
    assert(missing_code == 1, 'Expected no-argument invocation to exit 1')
    assert_contains(missing_output, 'Usage: loongshield <subcommand> [options]')

    local bad_code, bad_output = run_loongshield({ 'does-not-exist' })
    assert(bad_code == 1, 'Expected unknown subcommand to exit 1')
    assert_contains(bad_output, "Unknown subcommand: 'does-not-exist'")
    assert_contains(bad_output, 'Subcommands:')
end

function test_subcommand_help_is_reachable_through_bundled_binary()
    local seharden_code, seharden_output = run_loongshield({ 'seharden', '--help' })
    assert(seharden_code == 0, 'Expected seharden --help to exit 0')
    assert_contains(seharden_output, 'Usage: loongshield seharden [--scan|--reinforce] [options]')
    assert_contains(seharden_output, '--reinforce         Apply reinforce actions for failing rules.')
    assert_contains(seharden_output, 'Exit Codes:')

    local rpm_code, rpm_output = run_loongshield({ 'rpm', '--help' })
    assert(rpm_code == 0, 'Expected rpm --help to exit 0')
    assert_contains(rpm_output, 'Usage: loongshield rpm [options]')
    assert_contains(rpm_output, 'OpenAnolis / Alibaba Cloud Linux SBOM service')
    assert_contains(rpm_output, 'For other RPM repositories, pass --sbom-url explicitly.')
end

function test_seharden_missing_profile_returns_nonzero()
    local missing_name = 'this_config_does_not_exist_xyz'
    local code, output = run_loongshield({
        'seharden',
        '--scan',
        '--config',
        missing_name,
    })

    assert(code == 1, 'Expected missing profile to exit 1')
    assert_contains(output, "Failed to read profile file '/etc/loongshield/seharden/" .. missing_name .. ".yml'")
end

function test_seharden_scan_dry_run_reinforce_and_level_selection_flow()
    local ok, err = pcall(function()
        T.setup('6', 'development host')

        local scan_code, scan_output = run_loongshield({
            'seharden',
            '--config',
            T.PROFILE,
            '--verbose',
        })
        assert(scan_code == 1, 'Expected initial scan to fail against insecure fixture')
        assert_contains(
            scan_output,
            "SEHarden scan: profile='loongshield_e2e', level='baseline', 1 rule(s), 1 manual-review item(s)"
        )
        assert_contains(scan_output, 'FAIL [e2e.max_auth_tries]')
        assert_contains(scan_output, 'Manual Review Summary: 1 item(s) outside automated coverage')
        assert_contains(scan_output, 'Review production exception approvals for the fixture profile.')
        assert_contains(read_file(T.CONFIG), 'MaxAuthTries=6', 'Scan must not change the fixture config')

        local dry_run_code, dry_run_output = run_loongshield({
            'seharden',
            '--reinforce',
            '--dry-run',
            '--config',
            T.PROFILE,
        })
        assert(dry_run_code == 1, 'Expected dry-run reinforce to report pending changes')
        assert_contains(dry_run_output, 'DRY-RUN: would apply 1 action(s)')
        assert_contains(read_file(T.CONFIG), 'MaxAuthTries=6', 'Dry-run must not change the fixture config')

        local reinforce_code, reinforce_output = run_loongshield({
            'seharden',
            '--reinforce',
            '--config',
            T.PROFILE,
        })
        assert(reinforce_code == 0, 'Expected reinforce to fix the baseline rule')
        assert_contains(reinforce_output, 'FIXED: Ensure fixture MaxAuthTries is hardened')
        assert_contains(read_file(T.CONFIG), 'MaxAuthTries=4', 'Reinforce must harden the fixture config')

        local pass_code, pass_output = run_loongshield({
            'seharden',
            '--scan',
            '--config',
            T.PROFILE,
            '--verbose',
        })
        assert(pass_code == 0, 'Expected scan to pass after reinforce')
        assert_contains(pass_output, 'PASS [e2e.max_auth_tries]')
        assert_contains(pass_output, 'Summary: 1 passed, 0 fixed, 0 failed, 0 manual, 0 dry-run-pending / 1 total')

        local strict_code, strict_output = run_loongshield({
            'seharden',
            '--scan',
            '--config',
            T.PROFILE,
            '--level',
            'strict',
            '--verbose',
        })
        assert(strict_code == 1, 'Expected strict level to include and fail the banner rule')
        assert_contains(
            strict_output,
            "SEHarden scan: profile='loongshield_e2e', level='strict', 2 rule(s), 1 manual-review item(s)"
        )
        assert_contains(strict_output, 'PASS [e2e.max_auth_tries]')
        assert_contains(strict_output, 'FAIL [e2e.strict_banner]')
    end)

    T.teardown()

    if not ok then
        error(err, 0)
    end
end

function test_rpm_command_handles_missing_package_before_sbom_fetch()
    local missing_name = 'loongshield-e2e-package-that-should-not-exist'
    local code, output = run_loongshield({
        'rpm',
        '--verify',
        missing_name,
        '--sbom-url',
        'http://127.0.0.1:9/{name}.spdx.json',
    })

    assert(code == 1, 'Expected missing package verification to exit 1')
    assert_contains(output, 'Starting verification for package: ' .. missing_name)
    assert_contains(output, 'Package not found: ' .. missing_name)
    assert_not_contains(output, 'Downloading SBOM from:', 'Missing package flow must stop before network fetch')
end

function test_bundled_seharden_profiles_scan_without_engine_errors()
    if not is_running_as_root() then
        print('skipping bundled SEHarden profile scans; root privileges are required for host-sensitive files')
        return
    end

    local profiles = {
        seharden_scan_case('agentos_baseline', 'profiles/seharden/agentos_baseline.yml', 'baseline', 23, 0),
        seharden_scan_case('agentos_baseline', 'profiles/seharden/agentos_baseline.yml', 'openclaw', 32, 7),
        seharden_scan_case('cis_alinux_3', 'profiles/seharden/cis_alinux_3.yml', 'l1_server', 236, 3),
        seharden_scan_case('cis_alinux_3', 'profiles/seharden/cis_alinux_3.yml', 'l2_server', 280, 4),
        seharden_scan_case('cis_alinux_3', 'profiles/seharden/cis_alinux_3.yml', 'l1_workstation', 167, 3),
        seharden_scan_case('cis_alinux_3', 'profiles/seharden/cis_alinux_3.yml', 'l2_workstation', 184, 3),
        seharden_scan_case('dengbao_alinux3_l3', 'profiles/seharden/dengbao_3.yml', 'l1_server', 48, 15),
        seharden_scan_case('dengbao_alinux3_l3', 'profiles/seharden/dengbao_3.yml', 'l2_server', 48, 15),
        seharden_scan_case('dengbao_alinux3_l3', 'profiles/seharden/dengbao_3.yml', 'l1_workstation', 48, 15),
        seharden_scan_case('dengbao_alinux3_l3', 'profiles/seharden/dengbao_3.yml', 'l2_workstation', 48, 15),
    }

    for _, profile in ipairs(profiles) do
        local code, output = run_loongshield(profile.args)

        assert(code == 0 or code == 1, 'Expected scan to return a documented scan exit code')
        assert_scan_header(output, profile)
        assert_contains(output, 'Summary:')
        assert_no_runtime_errors(output)
    end
end
