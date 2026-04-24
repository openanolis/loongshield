local T = {}

T.TEST_ROOT = "/tmp/loongshield_seharden_process_test"
T.PROFILE = T.TEST_ROOT .. "/profile.yml"
T.CONFIG = T.TEST_ROOT .. "/sshd_config"

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function write_file(path, content)
    local file = assert(io.open(path, "w"))
    file:write(content)
    file:close()
end

function T.setup(config_value)
    os.execute("rm -rf " .. shell_escape(T.TEST_ROOT))
    os.execute("mkdir -p " .. shell_escape(T.TEST_ROOT))

    write_file(T.CONFIG, "MaxAuthTries=" .. tostring(config_value) .. "\n")
    write_file(T.PROFILE, ([[
id: seharden_process_exit_code
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
]]):format(T.CONFIG))
end

function T.teardown()
    os.execute("rm -rf " .. shell_escape(T.TEST_ROOT))
end

local function run_scan()
    local cmd = "build/src/daemon/loongshield seharden --config "
        .. shell_escape(T.PROFILE) .. " >/dev/null 2>&1"
    return os.execute(cmd)
end

function test_loongshield_process_exit_code_tracks_seharden_result()
    local ok, err = pcall(function()
        T.setup("6")

        local scan_ok, scan_reason, scan_code = run_scan()
        assert(scan_ok == nil, "Expected failing seharden scan to return a non-zero process status")
        assert(scan_reason == "exit", "Expected process failure to report an exit status")
        assert(scan_code == 1, "Expected failing seharden scan to exit with code 1")

        write_file(T.CONFIG, "MaxAuthTries=4\n")

        local pass_ok, pass_reason, pass_code = run_scan()
        assert(pass_ok == true, "Expected passing seharden scan to return process success")
        assert(pass_reason == "exit", "Expected process success to report an exit status")
        assert(pass_code == 0, "Expected passing seharden scan to exit with code 0")
    end)

    T.teardown()

    if not ok then
        error(err, 0)
    end
end
