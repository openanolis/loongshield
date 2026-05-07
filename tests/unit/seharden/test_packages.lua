local packages_probe = require('seharden.probes.packages')

local Mocks = {}

local function make_reader(lines, close_ok, close_code)
    local output = table.concat(lines or {}, "\n")
    if output ~= "" then
        output = output .. "\n"
    end

    return {
        lines = function()
            return output:gmatch("([^\n]+)")
        end,
        close = function()
            return close_ok ~= false, "exit", close_code or 0
        end
    }
end

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

function test_get_installed_glob_supports_negated_character_classes()
    setup("pkg1\npkga\n")
    local result = packages_probe.get_installed({ name = "pkg[!0-9]" })
    assert(result.count == 1, "Expected negated character classes to exclude numeric suffixes")
    assert(result.details[1].name == "pkga", "Expected the negated class match to preserve the matching package name")
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

function test_inspect_min_version_accepts_installed_package_meeting_rpm_requirement()
    packages_probe._test_set_dependencies({
        io_popen = function(cmd)
            if cmd:find("rpm -q --qf", 1, true) and cmd:find("'pam'", 1, true) then
                return make_reader({ "pam\t0\t1.5.1\t28.el9\tx86_64" }, true, 0)
            end
            error("Unexpected command: " .. cmd)
        end,
    })

    local result = packages_probe.inspect_min_version({ name = "pam", minimum = "1.3.1-25" })

    assert(result.available == true, "Expected rpm evidence to be available")
    assert(result.installed == true, "Expected pam to be installed")
    assert(result.version_ok == true, "Expected rpm dependency comparison to pass")
    assert(result.installed_evr == "1.5.1-28.el9", "Expected installed EVR to be reported")
end

function test_inspect_min_version_reports_installed_but_too_old_package()
    packages_probe._test_set_dependencies({
        io_popen = function(cmd)
            if cmd:find("rpm -q --qf", 1, true) then
                return make_reader({ "authselect\t0\t1.2.5\t1.el8\tx86_64" }, true, 0)
            end
            error("Unexpected command: " .. cmd)
        end,
    })

    local result = packages_probe.inspect_min_version({ name = "authselect", minimum = "1.2.6-1" })

    assert(result.available == true, "Expected rpm evidence to be available")
    assert(result.installed == true, "Expected authselect installation evidence")
    assert(result.version_ok == false, "Expected too-old authselect package to fail the minimum")
end

function test_inspect_min_version_reports_missing_package_in_band()
    packages_probe._test_set_dependencies({
        io_popen = function(cmd)
            if cmd:find("rpm -q --qf", 1, true) then
                return make_reader({}, false, 1)
            end
            error("Unexpected command: " .. cmd)
        end,
    })

    local result = packages_probe.inspect_min_version({ name = "authselect", minimum = "1.2.6-1" })

    assert(result.available == true, "Expected rpm command failures for missing packages to remain in-band")
    assert(result.installed == false, "Expected missing package to be reported")
    assert(result.version_ok == false, "Expected missing package not to satisfy minimum version")
end

function test_inspect_min_version_reports_rpm_query_unavailable_in_band()
    packages_probe._test_set_dependencies({
        io_popen = function(cmd)
            if cmd:find("rpm -q --qf", 1, true) then
                return make_reader({}, false, 127)
            end
            error("Unexpected command: " .. cmd)
        end,
    })

    local result = packages_probe.inspect_min_version({ name = "pam", minimum = "1.3.1-25" })

    assert(result.available == false, "Expected rpm command execution errors to be evidence-unavailable")
    assert(result.version_ok == false, "Expected unavailable rpm evidence not to pass")
    assert(result.error ~= nil, "Expected unavailable evidence to carry a diagnostic")
end
