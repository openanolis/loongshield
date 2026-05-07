local authselect_probe = require('seharden.probes.authselect')

local function make_reader(lines)
    local index = 0
    return {
        lines = function()
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function()
            return true
        end
    }
end

local function with_dependencies(deps, fn)
    authselect_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    authselect_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_inspect_profile_modules_accepts_custom_profile_with_required_modules()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/authselect/authselect.conf" then
                return make_reader({
                    "custom/hardening",
                    "with-faillock",
                })
            end
            if path == "/etc/authselect/custom/hardening/system-auth"
                or path == "/etc/authselect/custom/hardening/password-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth silent {include if \"with-faillock\"}",
                    "auth sufficient pam_unix.so {if not \"without-nullok\":nullok}",
                    "auth required pam_faillock.so authfail {include if \"with-faillock\"}",
                    "account required pam_faillock.so {include if \"with-faillock\"}",
                    "account required pam_unix.so",
                    "password requisite pam_pwquality.so local_users_only",
                    "password required pam_pwhistory.so use_authtok",
                    "password sufficient pam_unix.so sha512 shadow use_authtok",
                    "session required pam_unix.so",
                })
            end
            return nil
        end,
    }, function()
        local result = authselect_probe.inspect_profile_modules({})

        assert(result.available == true, "Expected authselect evidence to be available")
        assert(result.profile == "custom/hardening", "Expected active profile to be reported")
        assert(result.features["with-faillock"] == true, "Expected authselect features to be reported")
        assert(result.missing_count == 0, "Expected all required modules to be present in both templates")
    end)
end

function test_inspect_profile_modules_reports_missing_modules_and_unreadable_profile()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/authselect/authselect.conf" then
                return make_reader({ "sssd" })
            end
            if path == "/usr/share/authselect/default/sssd/system-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so local_users_only",
                })
            end
            return nil
        end,
    }, function()
        local result = authselect_probe.inspect_profile_modules({
            modules = { "pwquality", "pwhistory" },
        })

        assert(result.available == true, "Expected readable authselect.conf to make profile evidence available")
        assert(result.profile_path == "/usr/share/authselect/default/sssd",
            "Expected built-in profiles to resolve under /usr/share/authselect/default")
        assert(result.missing_count == 2,
            "Expected one missing module plus one unreadable template to be reported")
    end)
end

function test_inspect_profile_modules_reports_missing_authselect_conf_in_band()
    with_dependencies({
        io_open = function()
            return nil
        end,
    }, function()
        local result = authselect_probe.inspect_profile_modules({})

        assert(result.available == false, "Expected missing authselect.conf to fail in-band")
        assert(result.missing_count > 0, "Expected missing profile evidence not to pass")
    end)
end
