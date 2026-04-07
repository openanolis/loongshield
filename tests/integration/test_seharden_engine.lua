local engine = require('seharden.engine')

local T = {}
T.TEST_ROOT = "/tmp/loongshield_seharden_engine_test"
T.OS_RELEASE = T.TEST_ROOT .. "/os-release"
T.MOTD = T.TEST_ROOT .. "/motd"

local function write_file(path, content)
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
end

function T.setup()
    os.execute("rm -rf " .. T.TEST_ROOT)
    os.execute("mkdir -p " .. T.TEST_ROOT)
end

function T.teardown()
    os.execute("rm -rf " .. T.TEST_ROOT)
end

function test_engine_resolves_probe_templates_in_params()
    T.setup()
    write_file(T.OS_RELEASE, "ID=alinux\n")
    write_file(T.MOTD, "Welcome to ALINUX\n")

    local rule = {
        id = "TEST-TEMPLATE",
        desc = "Template substitution in probe params",
        probes = {
            {
                name = "os_info",
                func = "file.parse_key_values",
                params = { path = T.OS_RELEASE }
            },
            {
                name = "motd_info_leak_check",
                func = "file.find_pattern",
                params = {
                    paths = { T.MOTD },
                    pattern = "(?i)(%{probe.os_info.ID})"
                }
            }
        },
        assertion = {
            all_of = {
                {
                    actual = "%{probe.motd_info_leak_check}",
                    key = "found",
                    compare = "is_true",
                    message = "Expected pattern to be found"
                }
            }
        }
    }

    local rc = engine.run("scan", { rule })
    assert(rc == 0, "Expected engine run to pass when template resolves")

    T.teardown()
end
