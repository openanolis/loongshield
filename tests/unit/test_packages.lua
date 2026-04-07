local packages_probe = require('seharden.probes.packages')

local Mocks = {}

local function setup(mock_output, close_ok, close_code)
    Mocks = {
        output = mock_output or "",
        close_ok = close_ok ~= false,
        close_code = close_code or 0
    }

    local function fake_io_popen(cmd)
        return {
            lines = function()
                return Mocks.output:gmatch("([^\n]+)")
            end,
            close = function()
                return Mocks.close_ok, "exit", Mocks.close_code
            end
        }
    end

    packages_probe._test_set_dependencies({
        io_popen = fake_io_popen
    })
end

function test_get_installed_exact_match()
    setup("bash\ncoreutils\n")
    local result = packages_probe.get_installed({ name = "bash" })
    assert(result.count == 1, "Expected bash to be found")
    assert(result.details[1].name == "bash", "Expected details to contain bash")
end

function test_get_installed_glob_match()
    setup("xorg-x11-server-Xorg\nxorg-x11-server-common\n")
    local result = packages_probe.get_installed({ name = "xorg-x11-server-*" })
    assert(result.count == 2, "Expected glob to match both xorg packages")
end

function test_get_installed_gpg_pubkey_special_case()
    setup("gpg-pubkey\n")
    local result = packages_probe.get_installed({ name = "gpg-pubkey-*" })
    assert(result.count == 1, "Expected gpg-pubkey special case to match")
end

function test_get_installed_handles_rpm_failure()
    setup("", false, 1)
    local result, err = packages_probe.get_installed({ name = "bash" })
    assert(result == nil, "Expected rpm failures to be surfaced")
    assert(err:find("rpm %-qa"), "Expected error to mention the failed rpm query")
end

function test_get_installed_reloads_packages_on_each_call()
    local outputs = {
        "bash\n",
        "coreutils\n",
    }
    local popen_calls = 0

    packages_probe._test_set_dependencies({
        io_popen = function()
            popen_calls = popen_calls + 1
            local output = outputs[popen_calls] or ""
            return {
                lines = function()
                    return output:gmatch("([^\n]+)")
                end,
                close = function()
                    return true, "exit", 0
                end
            }
        end
    })

    local first = packages_probe.get_installed({ name = "bash" })
    local second = packages_probe.get_installed({ name = "bash" })

    assert(first.count == 1, "Expected first package list to include bash")
    assert(second.count == 0, "Expected second package list to reflect updated state")
    assert(popen_calls == 2, "Expected rpm query to run on each call")
end
