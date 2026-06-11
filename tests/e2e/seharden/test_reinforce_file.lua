local T = {}

T.TEST_ROOT = '/tmp/loongshield_e2e_reinforce_file_test'
T.PROFILE = T.TEST_ROOT .. '/profile.yml'
T.CONFIG = T.TEST_ROOT .. '/sshd_config'

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function write_file(path, content)
    local file = assert(io.open(path, 'w'))
    file:write(content)
    file:close()
end

local function read_file(path)
    local file = assert(io.open(path, 'r'))
    local content = file:read('*a')
    file:close()
    return content
end

function T.setup(config_value)
    os.execute('rm -rf ' .. shell_escape(T.TEST_ROOT))
    os.execute('mkdir -p ' .. shell_escape(T.TEST_ROOT))

    write_file(T.CONFIG, 'MaxAuthTries=' .. tostring(config_value) .. '\n')
    write_file(
        T.PROFILE,
        ([[
id: e2e_reinforce_file
version: "0.1.0"
levels:
  - id: baseline
rules:
  - id: file.kv
    desc: Ensure MaxAuthTries is 4
    level: [baseline]
    status: automated
    probes:
      - name: cfg
        func: file.parse_key_values
        params:
          path: %s
    assertion:
      actual: "%%{probe.cfg}"
      key: MaxAuthTries
      compare: equals
      expected: "4"
    reinforce:
      - action: file.set_key_value
        params:
          path: %s
          key: MaxAuthTries
          value: "4"
]]):format(T.CONFIG, T.CONFIG)
    )
end

function T.teardown()
    os.execute('rm -rf ' .. shell_escape(T.TEST_ROOT))
end

local function run_seharden(args)
    local cmd = 'build/src/daemon/loongshield seharden --config '
        .. shell_escape(T.PROFILE)
        .. ' '
        .. args
        .. ' >/dev/null 2>&1'
    return os.execute(cmd)
end

function test_reinforce_file_end_to_end_flow()
    local ok, err = pcall(function()
        T.setup('6')

        local initial_content = read_file(T.CONFIG)
        assert(
            initial_content == 'MaxAuthTries=6\n',
            'Expected test fixture to start with a non-compliant MaxAuthTries value'
        )

        local scan_ok, scan_reason, scan_code = run_seharden('')
        assert(scan_ok == nil, 'Expected initial scan to fail before reinforce')
        assert(scan_reason == 'exit', 'Expected failing scan to report an exit status')
        assert(scan_code == 1, 'Expected failing scan to exit with code 1')

        local dry_run_ok, dry_run_reason, dry_run_code = run_seharden('--reinforce --dry-run')
        assert(dry_run_ok == nil, 'Expected dry-run to report pending changes')
        assert(dry_run_reason == 'exit', 'Expected dry-run to report an exit status')
        assert(dry_run_code == 1, 'Expected dry-run to exit with code 1 while changes are pending')
        assert(read_file(T.CONFIG) == initial_content, 'Expected dry-run not to modify the target configuration file')

        local reinforce_ok, reinforce_reason, reinforce_code = run_seharden('--reinforce')
        assert(reinforce_ok == true, 'Expected reinforce to succeed once changes are applied')
        assert(reinforce_reason == 'exit', 'Expected reinforce to report an exit status')
        assert(reinforce_code == 0, 'Expected reinforce to exit with code 0 after fixing the rule')
        assert(
            read_file(T.CONFIG) == 'MaxAuthTries=4\n',
            'Expected reinforce to update MaxAuthTries to the target value'
        )

        local rescan_ok, rescan_reason, rescan_code = run_seharden('')
        assert(rescan_ok == true, 'Expected scan to pass after reinforce')
        assert(rescan_reason == 'exit', 'Expected passing scan to report an exit status')
        assert(rescan_code == 0, 'Expected passing scan to exit with code 0')

        local post_fix_content = read_file(T.CONFIG)
        local second_reinforce_ok, second_reinforce_reason, second_reinforce_code = run_seharden('--reinforce')
        assert(second_reinforce_ok == true, 'Expected reinforce to remain successful after the rule is already fixed')
        assert(second_reinforce_reason == 'exit', 'Expected idempotent reinforce to report an exit status')
        assert(second_reinforce_code == 0, 'Expected idempotent reinforce to exit with code 0')
        assert(
            read_file(T.CONFIG) == post_fix_content,
            'Expected a second reinforce run to leave the configuration unchanged'
        )
    end)

    T.teardown()

    if not ok then
        error(err, 0)
    end
end
