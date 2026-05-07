local pam_probe = require('seharden.probes.pam')

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
    pam_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    pam_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_check_password_history_accepts_default_config_and_pam_unix()
    with_dependencies({
        expand_paths = function(paths)
            if paths[1] == "/etc/security/pwhistory.conf" then
                return { "/etc/security/pwhistory.conf" }
            end
            if paths[1] == "/etc/security/pwhistory.conf.d/*.conf" then
                return { "/etc/security/pwhistory.conf.d/50-hardening.conf" }
            end
            return {}
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "password required pam_pwhistory.so use_authtok"
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password sufficient pam_unix.so remember=30 use_authtok"
                })
            end
            if path == "/etc/security/pwhistory.conf" then
                return make_reader({
                    "remember = 20"
                })
            end
            if path == "/etc/security/pwhistory.conf.d/50-hardening.conf" then
                return make_reader({
                    "remember = 24"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.check_password_history({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            min_remember = 24,
            config_paths = {
                "/etc/security/pwhistory.conf",
                "/etc/security/pwhistory.conf.d/*.conf",
            },
        })

        assert(result.count == 0, "Expected both PAM stacks to satisfy password history requirements")
    end)
end

function test_check_password_history_reports_missing_and_small_values()
    with_dependencies({
        expand_paths = function()
            return {}
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "password required pam_pwhistory.so remember=10 use_authtok"
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password required pam_unix.so use_authtok"
                })
            end
            return nil
        end
    }, function()
        local result = pam_probe.check_password_history({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            min_remember = 24,
        })

        assert(result.count == 2, "Expected both PAM stacks to be reported as non-compliant")
        assert(result.details[1].reason ~= nil, "Expected violation reasons to be preserved")
    end)
end

function test_inspect_pwquality_accepts_default_minlen_and_config_overrides()
    with_dependencies({
        expand_paths = function(paths)
            if paths[1] == "/etc/security/pwquality.conf" then
                return { "/etc/security/pwquality.conf" }
            end
            if paths[1] == "/etc/security/pwquality.conf.d/*.conf" then
                return { "/etc/security/pwquality.conf.d/50-hardening.conf" }
            end
            return {}
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so retry=3"
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so minlen=10 retry=3"
                })
            end
            if path == "/etc/security/pwquality.conf" then
                return make_reader({
                    "minlen = 7"
                })
            end
            if path == "/etc/security/pwquality.conf.d/50-hardening.conf" then
                return make_reader({
                    "minlen = 8",
                    "minclass = 3"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_pwquality({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            config_paths = {
                "/etc/security/pwquality.conf",
                "/etc/security/pwquality.conf.d/*.conf",
            },
            min_minlen = 8,
            default_minlen = 8,
        })

        assert(result.missing_module_count == 0, "Expected pam_pwquality to be enabled in both PAM stacks")
        assert(result.weak_minlen_count == 0, "Expected effective minlen overrides to satisfy the policy")
        assert(result.weak_complexity_count == 0,
            "Expected effective pwquality class requirements to satisfy the policy")
    end)
end

function test_inspect_pwquality_reports_missing_module_weak_minlen_and_weak_complexity()
    with_dependencies({
        expand_paths = function(paths)
            return {}
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so minlen=6 retry=3"
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password sufficient pam_unix.so use_authtok"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_pwquality({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            config_paths = {
                "/etc/security/pwquality.conf",
                "/etc/security/pwquality.conf.d/*.conf",
            },
            min_minlen = 8,
            default_minlen = 8,
        })

        assert(result.missing_module_count == 1, "Expected missing pam_pwquality modules to be reported")
        assert(result.weak_minlen_count == 2, "Expected both missing module and weak minlen to be non-compliant")
        assert(result.weak_complexity_count == 1,
            "Expected enabled pwquality stacks without class complexity requirements to be reported")
        assert(result.details[1].reason == "minlen_too_small" or result.details[1].reason == "module_missing",
            "Expected pwquality failures to preserve meaningful reasons")
    end)
end

function test_inspect_pwquality_accepts_negative_credit_class_requirements()
    with_dependencies({
        expand_paths = function(paths)
            return {}
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so minlen=12 dcredit=-1 ucredit=-1 lcredit=-1 retry=3"
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so minlen=10 minclass=3 retry=3"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_pwquality({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            min_minlen = 8,
            min_minclass = 3,
            default_minlen = 8,
        })

        assert(result.missing_module_count == 0, "Expected pwquality to be enabled in both PAM stacks")
        assert(result.weak_minlen_count == 0, "Expected compliant minlen settings to pass")
        assert(result.weak_complexity_count == 0,
            "Expected negative class-credit requirements to satisfy the complexity baseline")
    end)
end

function test_inspect_pwquality_accepts_inline_comments_in_config()
    with_dependencies({
        expand_paths = function(paths)
            if paths[1] == "/etc/security/pwquality.conf" then
                return { "/etc/security/pwquality.conf" }
            end
            return {}
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so retry=3"
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so retry=3"
                })
            end
            if path == "/etc/security/pwquality.conf" then
                return make_reader({
                    "minlen = 8 # comment",
                    "minclass = 3 # comment"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_pwquality({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            config_paths = {
                "/etc/security/pwquality.conf",
            },
            min_minlen = 8,
            min_minclass = 3,
            default_minlen = 8,
        })

        assert(result.missing_module_count == 0, "Expected pwquality modules to be enabled")
        assert(result.weak_minlen_count == 0, "Expected inline-comment minlen settings to be parsed")
        assert(result.weak_complexity_count == 0, "Expected inline-comment minclass settings to be parsed")
    end)
end

function test_inspect_faillock_accepts_structured_stack_and_defaults()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth",
                    "auth [default=die] pam_faillock.so authfail",
                    "account required pam_faillock.so",
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "auth [success=1 default=bad] pam_unix.so",
                    "auth [default=die] pam_faillock.so authfail",
                    "auth sufficient pam_faillock.so authsucc",
                })
            end
            return nil
        end
    }, function()
        local result = pam_probe.inspect_faillock({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            config_path = "/etc/security/faillock.conf",
            default_deny = 3,
            default_unlock_time = 600,
        })

        assert(result.count == 0, "Expected valid pam_faillock stack layouts with default settings to pass")
    end)
end

function test_inspect_faillock_reports_incomplete_stack_and_invalid_unlock_time()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "auth required pam_faillock.so authfail unlock_time=bad"
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth",
                    "auth required pam_faillock.so authfail"
                })
            end
            return nil
        end
    }, function()
        local result = pam_probe.inspect_faillock({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            config_path = "/etc/security/faillock.conf",
            default_deny = 3,
            default_unlock_time = 600,
        })

        assert(result.count == 1, "Expected only the invalid stack to be reported")
        assert(result.details[1].reason == "unlock_time_invalid"
            or result.details[1].reason == "stack_incomplete",
            "Expected a meaningful faillock failure reason")
    end)
end

function test_inspect_faillock_rejects_weakened_thresholds()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth deny=5 unlock_time=600",
                    "auth [default=die] pam_faillock.so authfail deny=5 unlock_time=600",
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth deny=3 unlock_time=60",
                    "auth sufficient pam_faillock.so authsucc deny=3 unlock_time=60",
                    "auth [default=die] pam_faillock.so authfail deny=3 unlock_time=60",
                })
            end
            return nil
        end
    }, function()
        local result = pam_probe.inspect_faillock({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            config_path = "/etc/security/faillock.conf",
            default_deny = 3,
            default_unlock_time = 600,
        })

        assert(result.count == 2, "Expected weakened faillock thresholds to be reported")
        assert(result.details[1].reason == "deny_too_large"
            or result.details[2].reason == "deny_too_large",
            "Expected oversized deny thresholds to be rejected")
        assert(result.details[1].reason == "unlock_time_too_short"
            or result.details[2].reason == "unlock_time_too_short",
            "Expected too-short unlock_time values to be rejected")
    end)
end

function test_inspect_faillock_accepts_never_unlock_as_stricter_policy()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth deny=3 unlock_time=never",
                    "auth [default=die] pam_faillock.so authfail deny=3 unlock_time=never",
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth",
                    "auth sufficient pam_faillock.so authsucc",
                    "auth [default=die] pam_faillock.so authfail",
                })
            end
            return nil
        end
    }, function()
        local result = pam_probe.inspect_faillock({
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            config_path = "/etc/security/faillock.conf",
            default_deny = 3,
            default_unlock_time = 600,
        })

        assert(result.count == 0, "Expected never-unlock faillock policy to be accepted as stricter")
    end)
end

function test_inspect_module_accepts_cis_faillock_stack_in_both_files()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/system-auth" or path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "auth required pam_faillock.so preauth silent",
                    "auth required pam_faillock.so authfail",
                    "account required pam_faillock.so",
                })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_module({
            module = "faillock",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
        })

        assert(result.count == 0, "Expected complete faillock stacks in both PAM files to pass")
    end)
end

function test_inspect_module_reports_missing_required_pam_stack_entry()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/system-auth" then
                return make_reader({
                    "password requisite pam_pwquality.so local_users_only",
                })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password requisite pam_unix.so sha512 shadow",
                })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_module({
            module = "pwquality",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
        })

        assert(result.count == 1, "Expected missing pwquality in one PAM file to be reported")
        assert(result.details[1].reason == "requirement_missing",
            "Expected missing stack requirement to preserve a useful reason")
    end)
end

function test_inspect_faillock_setting_accepts_configured_deny_and_rejects_weak_module_override()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/security/faillock.conf" then
                return make_reader({ "deny = 5" })
            end
            if path == "/etc/pam.d/system-auth" then
                return make_reader({ "auth required pam_faillock.so authfail deny=6" })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({ "auth required pam_faillock.so authfail" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_faillock_setting({
            option = "deny",
            config_path = "/etc/security/faillock.conf",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            max_deny = 5,
        })

        assert(result.config_compliant == true, "Expected configured deny=5 to satisfy CIS")
        assert(result.compliant == false, "Expected weak PAM deny override to fail the setting")
        assert(result.module_argument_violation_count == 1, "Expected one weak module override")
    end)
end

function test_inspect_faillock_setting_accepts_root_lockout_with_minimum_root_unlock_time()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/security/faillock.conf" then
                return make_reader({ "root_unlock_time = 60" })
            end
            if path == "/etc/pam.d/system-auth" or path == "/etc/pam.d/password-auth" then
                return make_reader({ "auth required pam_faillock.so authfail" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_faillock_setting({
            option = "root_lockout",
            config_path = "/etc/security/faillock.conf",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            min_root_unlock_time = 60,
        })

        assert(result.compliant == true, "Expected root_unlock_time >= 60 to satisfy root lockout")
        assert(result.count == 0, "Expected no root lockout violations")
    end)
end

function test_inspect_pwquality_setting_observes_config_precedence_and_module_overrides()
    with_dependencies({
        expand_paths = function(paths)
            if paths[1] == "/etc/security/pwquality.conf.d/*.conf" then
                return { "/etc/security/pwquality.conf.d/50-length.conf" }
            end
            if paths[1] == "/etc/security/pwquality.conf" then
                return { "/etc/security/pwquality.conf" }
            end
            return {}
        end,
        io_open = function(path)
            if path == "/etc/security/pwquality.conf.d/50-length.conf" then
                return make_reader({ "minlen = 10" })
            end
            if path == "/etc/security/pwquality.conf" then
                return make_reader({ "minlen = 14" })
            end
            if path == "/etc/pam.d/system-auth" then
                return make_reader({ "password requisite pam_pwquality.so minlen=12" })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({ "password requisite pam_pwquality.so" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_pwquality_setting({
            option = "minlen",
            config_paths = {
                "/etc/security/pwquality.conf.d/*.conf",
                "/etc/security/pwquality.conf",
            },
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            min_value = 14,
        })

        assert(result.config_value == "14", "Expected main pwquality.conf to override .conf.d settings")
        assert(result.config_compliant == true, "Expected effective config minlen to pass")
        assert(result.compliant == false, "Expected weak module minlen override to fail")
    end)
end

function test_inspect_pwquality_setting_accepts_absent_dictcheck_default()
    with_dependencies({
        expand_paths = function()
            return {}
        end,
        io_open = function(path)
            if path == "/etc/pam.d/system-auth" or path == "/etc/pam.d/password-auth" then
                return make_reader({ "password requisite pam_pwquality.so" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_pwquality_setting({
            option = "dictcheck",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            default_value = 1,
            disallowed_values = { "0" },
        })

        assert(result.compliant == true, "Expected default dictcheck=1 to pass when not disabled")
    end)
end

function test_inspect_pwquality_setting_rejects_disabled_root_enforcement_flag()
    with_dependencies({
        expand_paths = function(paths)
            if paths[1] == "/etc/security/pwquality.conf" then
                return { "/etc/security/pwquality.conf" }
            end
            return {}
        end,
        io_open = function(path)
            if path == "/etc/security/pwquality.conf" then
                return make_reader({ "enforce_for_root = 0" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_pwquality_setting({
            option = "enforce_for_root",
            config_paths = { "/etc/security/pwquality.conf" },
            require_flag = true,
        })

        assert(result.compliant == false, "Expected enforce_for_root=0 not to satisfy root enforcement")
    end)
end

function test_inspect_pwhistory_setting_requires_configured_remember_and_rejects_weak_argument()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/security/pwhistory.conf" then
                return make_reader({ "remember = 24" })
            end
            if path == "/etc/pam.d/system-auth" then
                return make_reader({ "password required pam_pwhistory.so remember=20 use_authtok" })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({ "password required pam_pwhistory.so use_authtok" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_pwhistory_setting({
            option = "remember",
            config_path = "/etc/security/pwhistory.conf",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
            min_remember = 24,
        })

        assert(result.config_compliant == true, "Expected pwhistory.conf remember=24 to pass")
        assert(result.compliant == false, "Expected weak module remember override to fail")
    end)
end

function test_inspect_pwhistory_setting_accepts_bare_root_enforcement_flag_only()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/security/pwhistory.conf" then
                return make_reader({ "enforce_for_root" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_pwhistory_setting({
            option = "enforce_for_root",
            config_path = "/etc/security/pwhistory.conf",
        })

        assert(result.compliant == true, "Expected bare enforce_for_root flag to pass")
    end)

    with_dependencies({
        io_open = function(path)
            if path == "/etc/security/pwhistory.conf" then
                return make_reader({ "enforce_for_root = 0" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_pwhistory_setting({
            option = "enforce_for_root",
            config_path = "/etc/security/pwhistory.conf",
        })

        assert(result.compliant == false, "Expected disabled enforce_for_root value to fail")
    end)
end

function test_inspect_pwhistory_setting_requires_use_authtok_in_both_password_stacks()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/system-auth" then
                return make_reader({ "password required pam_pwhistory.so use_authtok" })
            end
            if path == "/etc/pam.d/password-auth" then
                return make_reader({ "password required pam_pwhistory.so" })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_pwhistory_setting({
            option = "use_authtok",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
        })

        assert(result.count == 1, "Expected missing pwhistory use_authtok in one file to fail")
        assert(result.details[1].reason == "use_authtok_missing",
            "Expected missing use_authtok reason")
    end)
end

function test_inspect_unix_accepts_enabled_stacks_and_strong_password_arguments()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/system-auth" or path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "auth sufficient pam_unix.so",
                    "account required pam_unix.so",
                    "password sufficient pam_unix.so sha512 shadow use_authtok",
                    "session required pam_unix.so",
                })
            end
            return nil
        end,
    }, function()
        local paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" }
        assert(pam_probe.inspect_unix({ check = "enabled", pam_paths = paths }).count == 0,
            "Expected all pam_unix stack kinds to be present")
        assert(pam_probe.inspect_unix({ check = "no_nullok", pam_paths = paths }).count == 0,
            "Expected pam_unix nullok absence to pass")
        assert(pam_probe.inspect_unix({ check = "strong_hash", pam_paths = paths }).count == 0,
            "Expected sha512 pam_unix password hash to pass")
        assert(pam_probe.inspect_unix({ check = "use_authtok", pam_paths = paths }).count == 0,
            "Expected pam_unix use_authtok to pass")
    end)
end

function test_inspect_unix_reports_nullok_remember_and_weak_hash()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/system-auth" or path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "auth sufficient pam_unix.so nullok",
                    "account required pam_unix.so",
                    "password sufficient pam_unix.so sha256 remember=5",
                    "session required pam_unix.so",
                })
            end
            return nil
        end,
    }, function()
        local paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" }
        assert(pam_probe.inspect_unix({ check = "no_nullok", pam_paths = paths }).count == 2,
            "Expected nullok in both files to fail")
        assert(pam_probe.inspect_unix({ check = "no_remember", pam_paths = paths }).count == 2,
            "Expected pam_unix remember in both files to fail")
        assert(pam_probe.inspect_unix({ check = "strong_hash", pam_paths = paths }).count == 4,
            "Expected weak hash and missing strong hash in both files to fail")
    end)
end

function test_inspect_unix_requires_every_password_line_to_have_strong_hash()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/system-auth" or path == "/etc/pam.d/password-auth" then
                return make_reader({
                    "password sufficient pam_unix.so sha512 shadow use_authtok",
                    "password required pam_unix.so shadow use_authtok",
                })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_unix({
            check = "strong_hash",
            pam_paths = { "/etc/pam.d/system-auth", "/etc/pam.d/password-auth" },
        })

        assert(result.count == 2, "Expected password pam_unix lines without a strong hash to fail")
    end)
end

function test_inspect_wheel_accepts_required_and_bracket_controls()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/su" then
                return make_reader({
                    "auth sufficient pam_rootok.so",
                    "auth [default=die] pam_wheel.so use_uid group=wheel",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_wheel({
            pam_paths = { "/etc/pam.d/su" },
        })

        assert(result.count == 0, "Expected su PAM stack to accept restrictive pam_wheel controls")
    end)
end

function test_inspect_wheel_requires_empty_group_when_requested()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/su" then
                return make_reader({
                    "auth required pam_wheel.so use_uid group=sugroup",
                })
            end
            if path == "/etc/group" then
                return make_reader({
                    "sugroup:x:4000:",
                })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_wheel({
            pam_paths = { "/etc/pam.d/su" },
            require_empty_group = true,
        })

        assert(result.count == 0, "Expected pam_wheel with use_uid and an empty group to pass")
    end)
end

function test_inspect_wheel_reports_missing_or_nonempty_group_when_required()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/su" then
                return make_reader({
                    "auth required pam_wheel.so use_uid",
                })
            end
            if path == "/etc/pam.d/su-l" then
                return make_reader({
                    "auth required pam_wheel.so use_uid group=sugroup",
                })
            end
            if path == "/etc/group" then
                return make_reader({
                    "sugroup:x:4000:alice",
                })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_wheel({
            pam_paths = { "/etc/pam.d/su", "/etc/pam.d/su-l" },
            require_empty_group = true,
        })

        assert(result.count == 2, "Expected missing and non-empty groups to be reported")
        assert(result.details[1].reason == "group_missing"
            or result.details[2].reason == "group_missing",
            "Expected missing group= argument to be reported")
        assert(result.details[1].reason == "group_not_empty"
            or result.details[2].reason == "group_not_empty",
            "Expected non-empty su group to be reported")
    end)
end

function test_inspect_wheel_reports_unreadable_group_file_when_group_required()
    with_dependencies({
        io_open = function(path)
            if path == "/etc/pam.d/su" then
                return make_reader({
                    "auth required pam_wheel.so use_uid group=sugroup",
                })
            end
            return nil
        end,
    }, function()
        local result = pam_probe.inspect_wheel({
            pam_paths = { "/etc/pam.d/su" },
            require_empty_group = true,
        })

        assert(result.count == 1, "Expected missing /etc/group evidence to fail")
        assert(result.details[1].reason == "group_file_unreadable",
            "Expected missing group evidence to be explicit")
    end)
end

function test_inspect_wheel_reports_missing_use_uid_and_weak_control()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/su" then
                return make_reader({
                    "auth optional pam_wheel.so use_uid",
                })
            end
            if path == "/etc/pam.d/su-l" then
                return make_reader({
                    "auth required pam_wheel.so",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_wheel({
            pam_paths = { "/etc/pam.d/su", "/etc/pam.d/su-l" },
        })

        assert(result.count == 2, "Expected both weak pam_wheel configurations to be reported")
        assert(result.details[1].reason == "control_not_restrictive"
            or result.details[2].reason == "control_not_restrictive",
            "Expected weak pam_wheel control to be reported")
        assert(result.details[1].reason == "use_uid_missing"
            or result.details[2].reason == "use_uid_missing",
            "Expected missing use_uid to be reported")
    end)
end

function test_inspect_wheel_reports_deny_and_trust_options()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/su" then
                return make_reader({
                    "auth required pam_wheel.so deny use_uid",
                })
            end
            if path == "/etc/pam.d/su-l" then
                return make_reader({
                    "auth required pam_wheel.so trust use_uid",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_wheel({
            pam_paths = { "/etc/pam.d/su", "/etc/pam.d/su-l" },
        })

        assert(result.count == 2, "Expected deny and trust pam_wheel options to be reported")
        assert(result.details[1].reason == "deny_enabled"
            or result.details[2].reason == "deny_enabled",
            "Expected deny-enabled pam_wheel to be reported")
        assert(result.details[1].reason == "trust_enabled"
            or result.details[2].reason == "trust_enabled",
            "Expected trust-enabled pam_wheel to be reported")
    end)
end

function test_inspect_wheel_rejects_dangerous_entries_even_when_safe_entry_exists()
    with_dependencies({
        io_open = function(path, mode)
            assert(mode == "r", "Expected PAM probe to open files read-only")
            if path == "/etc/pam.d/su" then
                return make_reader({
                    "auth required pam_wheel.so use_uid",
                    "auth required pam_wheel.so trust use_uid",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = pam_probe.inspect_wheel({
            pam_paths = { "/etc/pam.d/su" },
        })

        assert(result.count == 1, "Expected dangerous pam_wheel entries to override earlier safe ones")
        assert(result.details[1].reason == "trust_enabled",
            "Expected trust-enabled pam_wheel entry to keep the stack non-compliant")
    end)
end
