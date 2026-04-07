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
