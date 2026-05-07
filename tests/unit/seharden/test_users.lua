local users_probe = require('seharden.probes.users')

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

function test_get_shadow_entries_preserves_empty_fields()
    users_probe._test_set_dependencies({
        shadow_path = "/tmp/test-shadow",
        io_open = function(path, mode)
            assert(path == "/tmp/test-shadow", "Expected configured shadow path to be used")
            assert(mode == "r", "Expected shadow file to be opened read-only")
            return make_reader({
                "alice:$6$hash:20000:7:30:7:::",
                "locked:!:20000:7:30:7:::"
            })
        end
    })

    local result = users_probe.get_shadow_entries()
    users_probe._test_set_dependencies()

    assert(#result == 1, "Expected unlocked account with empty trailing fields to be preserved")
    assert(result[1].user == "alice", "Expected alice entry to be parsed")
    assert(result[1].pass_min_days == 7, "Expected PASS_MIN_DAYS to be parsed correctly")
    assert(result[1].pass_max_days == 30, "Expected PASS_MAX_DAYS to be parsed correctly")
    assert(result[1].pass_warn_age == 7, "Expected PASS_WARN_AGE to be parsed correctly")
    assert(result[1].inactive == nil, "Expected empty INACTIVE field to remain nil")
end

function test_get_defaults_surfaces_command_failure()
    users_probe._test_set_dependencies({
        useradd_defaults_path = "/tmp/test-useradd-defaults",
        io_popen = function()
            return {
                lines = function()
                    return function()
                        return nil
                    end
                end,
                close = function()
                    return nil, "exit", 1
                end
            }
        end,
        io_open = function(path, mode)
            assert(path == "/tmp/test-useradd-defaults", "Expected configured useradd defaults path to be used")
            assert(mode == "r", "Expected defaults file to be opened read-only")
            return nil
        end
    })

    local result, err = users_probe.get_defaults()
    users_probe._test_set_dependencies()

    assert(result == nil, "Expected defaults probe failure to return nil result")
    assert(err == "The 'useradd -D' command failed with exit code: 1",
        "Expected defaults probe to surface command failure details")
end

function test_get_defaults_falls_back_to_defaults_file_when_useradd_fails()
    users_probe._test_set_dependencies({
        useradd_defaults_path = "/tmp/test-useradd-defaults",
        io_popen = function(cmd, mode)
            assert(cmd == "useradd -D 2>/dev/null", "Expected stderr-silenced useradd invocation")
            assert(mode == "r", "Expected useradd output to be opened read-only")
            return {
                lines = function()
                    return function()
                        return nil
                    end
                end,
                close = function()
                    return nil, "exit", 1
                end
            }
        end,
        io_open = function(path, mode)
            assert(path == "/tmp/test-useradd-defaults", "Expected configured useradd defaults path to be used")
            assert(mode == "r", "Expected defaults file to be opened read-only")
            return make_reader({
                "# comment",
                "GROUP=100",
                "INACTIVE=30",
                "SHELL=/bin/bash",
            })
        end
    })

    local result, err = users_probe.get_defaults()
    users_probe._test_set_dependencies()

    assert(err == nil, "Expected fallback path to avoid surfacing an error")
    assert(result ~= nil, "Expected parsed defaults from fallback file")
    assert(result.INACTIVE == 30, "Expected INACTIVE to be parsed numerically from fallback file")
    assert(result.SHELL == "/bin/bash", "Expected other defaults to be preserved from fallback file")
end

function test_find_files_requires_filename_even_when_params_nil()
    local result, err = users_probe.find_files(nil)
    assert(result == nil, "Expected nil result when params are missing")
    assert(err:match("requires a 'filename' parameter"), "Expected missing filename error")
end

function test_find_files_surfaces_passwd_read_failures()
    users_probe._test_set_dependencies({
        passwd_path = "/tmp/test-passwd",
        io_open = function(path, mode)
            assert(path == "/tmp/test-passwd", "Expected configured passwd path to be used")
            assert(mode == "r", "Expected passwd file to be opened read-only")
            return nil
        end
    })

    local result, err = users_probe.find_files({ filename = ".forward" })
    users_probe._test_set_dependencies()

    assert(result == nil, "Expected passwd read failures to be surfaced")
    assert(err:find("/tmp/test%-passwd"), "Expected error to mention the unreadable passwd path")
end

function test_get_shadow_entries_surfaces_read_failures()
    users_probe._test_set_dependencies({
        shadow_path = "/tmp/test-shadow",
        io_open = function(path, mode)
            assert(path == "/tmp/test-shadow", "Expected configured shadow path to be used")
            assert(mode == "r", "Expected shadow file to be opened read-only")
            return nil
        end
    })

    local result, err = users_probe.get_shadow_entries()
    users_probe._test_set_dependencies()

    assert(result == nil, "Expected shadow read failures to be surfaced")
    assert(err:find("/tmp/test%-shadow"), "Expected error to mention the unreadable shadow path")
end

function test_get_login_shadow_entries_filters_non_login_and_locked_accounts()
    users_probe._test_set_dependencies({
        shadow_path = "/tmp/test-shadow",
        passwd_path = "/tmp/test-passwd",
        io_open = function(path, mode)
            assert(mode == "r", "Expected probe inputs to be opened read-only")
            if path == "/tmp/test-shadow" then
                return make_reader({
                    "root:$6$hash:20000:7:30:7:::",
                    "svc:$6$hash:20000:7:99999:7:::",
                    "svc2:$6$hash:20000:7:99999:7:::",
                    "locked:!:20000:7:30:7:::",
                    "alice:$6$hash:20000:7:60:7:::",
                })
            end
            if path == "/tmp/test-passwd" then
                return make_reader({
                    "root:x:0:0:root:/root:/bin/bash",
                    "svc:x:999:999:svc:/srv/svc:/usr/sbin/nologin",
                    "svc2:x:998:998:svc2:/srv/svc2:/bin/nologin",
                    "locked:x:1000:1000:locked:/home/locked:/bin/bash",
                    "alice:x:1001:1001:alice:/home/alice:/bin/bash",
                })
            end
            error("Unexpected path: " .. path)
        end
    })

    local result = users_probe.get_login_shadow_entries()
    users_probe._test_set_dependencies()

    assert(#result == 2, "Expected only unlocked login-capable accounts to be returned")
    assert(result[1].user == "root", "Expected root to be retained as a login-capable account")
    assert(result[2].user == "alice", "Expected alice to be retained as a login-capable account")
end

function test_find_interactive_system_accounts_reports_non_login_violations()
    users_probe._test_set_dependencies({
        passwd_path = "/tmp/test-passwd",
        io_open = function(path, mode)
            assert(path == "/tmp/test-passwd", "Expected configured passwd path to be used")
            assert(mode == "r", "Expected passwd file to be opened read-only")
            return make_reader({
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "backup:x:34:34:backup:/var/backups:/bin/nologin",
                "games:x:12:12:games:/usr/games:/bin/bash",
                "mysql:x:27:27:mysql:/var/lib/mysql:/bin/false",
                "app:x:1000:1000:app:/home/app:/bin/bash",
            })
        end
    })

    local result = users_probe.find_interactive_system_accounts({ uid_min = 1000 })
    users_probe._test_set_dependencies()

    assert(result.count == 1, "Expected one interactive system account to be reported")
    assert(result.details[1].user == "games", "Expected games to be flagged as interactive system account")
    assert(result.details[1].shell == "/bin/bash", "Expected flagged account shell to be preserved")
end

function test_find_interactive_system_accounts_requires_positive_uid_min()
    local result, err = users_probe.find_interactive_system_accounts({ uid_min = 0 })
    assert(result == nil, "Expected invalid uid_min to fail")
    assert(err:match("positive 'uid_min'"), "Expected error to mention positive uid_min")
end

function test_find_interactive_system_accounts_reads_uid_min_from_login_defs()
    users_probe._test_set_dependencies({
        passwd_path = "/tmp/test-passwd",
        login_defs_path = "/tmp/login.defs",
        io_open = function(path, mode)
            assert(mode == "r", "Expected probe inputs to be opened read-only")
            if path == "/tmp/login.defs" then
                return make_reader({
                    "UID_MIN 500"
                })
            end
            if path == "/tmp/test-passwd" then
                return make_reader({
                    "root:x:0:0:root:/root:/bin/bash",
                    "games:x:12:12:games:/usr/games:/bin/bash",
                    "app:x:1000:1000:app:/home/app:/bin/bash",
                })
            end
            error("Unexpected path: " .. path)
        end
    })

    local result = users_probe.find_interactive_system_accounts({})
    users_probe._test_set_dependencies()

    assert(result.count == 1, "Expected UID_MIN from login.defs to control system-account classification")
    assert(result.details[1].user == "games", "Expected UID_MIN-derived classification to flag games")
end

function test_get_existing_home_directories_filters_missing_and_non_directory_homes()
    users_probe._test_set_dependencies({
        passwd_path = "/tmp/test-passwd",
        io_open = function(path, mode)
            assert(path == "/tmp/test-passwd", "Expected configured passwd path to be used")
            assert(mode == "r", "Expected passwd file to be opened read-only")
            return make_reader({
                "root:x:0:0:root:/root:/bin/bash",
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
                "bob:x:1001:1001:Bob:/missing:/bin/bash",
                "carol:x:1002:1002:Carol:/home/carol:/bin/bash",
                "daemon:x:2:2:daemon:/sbin:/usr/sbin/nologin",
            })
        end,
        lfs_attributes = function(path)
            if path == "/root" or path == "/home/alice" then
                return { mode = "directory" }
            end
            if path == "/home/carol" then
                return { mode = "file" }
            end
            return nil
        end
    })

    local result = users_probe.get_existing_home_directories()
    users_probe._test_set_dependencies()

    assert(result.count == 2, "Expected only existing home directories to be returned")
    assert(result.details[1].user == "root", "Expected root home to be preserved when present")
    assert(result.details[2].path == "/home/alice", "Expected valid user home path to be preserved")
end

local function make_stat(uid, gid, mode)
    return {
        uid = function() return uid end,
        gid = function() return gid end,
        mode = function() return mode end,
    }
end

function test_inspect_future_password_changes_reports_hashed_users_with_future_dates()
    users_probe._test_set_dependencies({
        shadow_path = "/tmp/test-shadow",
        io_open = function(path, mode)
            assert(path == "/tmp/test-shadow", "Expected configured shadow path")
            assert(mode == "r", "Expected shadow file to be opened read-only")
            return make_reader({
                "alice:$6$salt$hash:20001:7:90:7:::",
                "bob:$6$salt$hash:19999:7:90:7:::",
                "locked:!$6$salt$hash:20005:7:90:7:::",
                "never:$6$salt$hash::7:90:7:::",
            })
        end,
    })

    local result = users_probe.inspect_future_password_changes({ now = 20000 * 86400 })
    users_probe._test_set_dependencies()

    assert(result.available == true, "Expected shadow evidence to be available")
    assert(result.count == 1, "Expected only the future hashed account to fail")
    assert(result.details[1].user == "alice", "Expected alice to be reported")
end

function test_inspect_identity_reports_uid_and_gid_zero_violations()
    users_probe._test_set_dependencies({
        passwd_path = "/tmp/test-passwd",
        group_path = "/tmp/test-group",
        io_open = function(path, mode)
            assert(mode == "r", "Expected account files to be opened read-only")
            if path == "/tmp/test-passwd" then
                return make_reader({
                    "root:x:0:0:root:/root:/bin/bash",
                    "toor:x:0:1000:toor:/root:/bin/bash",
                    "badgid:x:1001:0:badgid:/home/badgid:/bin/bash",
                    "sync:x:5:0:sync:/sbin:/bin/sync",
                })
            end
            if path == "/tmp/test-group" then
                return make_reader({
                    "root:x:0:",
                    "wheel:x:10:",
                    "badroot:x:0:",
                })
            end
            error("Unexpected path: " .. path)
        end,
    })

    local uid_result = users_probe.inspect_identity({ check = "uid_zero" })
    local gid_user_result = users_probe.inspect_identity({ check = "gid_zero_users" })
    local gid_group_result = users_probe.inspect_identity({ check = "gid_zero_groups" })
    users_probe._test_set_dependencies()

    assert(uid_result.root_uid_zero == true, "Expected root UID 0 to be recognized")
    assert(uid_result.non_root_uid_zero_count == 1, "Expected non-root UID 0 account to be reported")
    assert(gid_user_result.non_root_gid_zero_count == 1,
        "Expected sync to be excluded and badgid to be reported")
    assert(gid_group_result.non_root_gid_zero_group_count == 1,
        "Expected non-root GID 0 group to be reported")
end

function test_inspect_root_access_requires_password_set_or_locked()
    users_probe._test_set_dependencies({
        shadow_path = "/tmp/test-shadow",
        io_open = function(path)
            assert(path == "/tmp/test-shadow", "Expected configured shadow path")
            return make_reader({ "root::20000:0:99999:7:::" })
        end,
    })

    local empty_result = users_probe.inspect_root_access()

    users_probe._test_set_dependencies({
        shadow_path = "/tmp/test-shadow",
        io_open = function(path)
            assert(path == "/tmp/test-shadow", "Expected configured shadow path")
            return make_reader({ "root:!$6$salt$hash:20000:0:99999:7:::" })
        end,
    })

    local locked_result = users_probe.inspect_root_access()
    users_probe._test_set_dependencies()

    assert(empty_result.controlled == false, "Expected empty root password field to fail")
    assert(locked_result.controlled == true, "Expected locked root account to pass")
    assert(locked_result.locked == true, "Expected locked root status to be reported")
end

function test_inspect_root_path_reports_empty_dot_unowned_and_permissive_segments()
    local attrs = {
        ["/usr/bin"] = { mode = "directory" },
        ["/bad"] = { mode = "directory" },
        ["/missing"] = nil,
    }
    local stats = {
        ["/usr/bin"] = make_stat(0, 0, tonumber("755", 8)),
        ["/bad"] = make_stat(1000, 0, tonumber("777", 8)),
    }

    users_probe._test_set_dependencies({
        lfs_attributes = function(path)
            return attrs[path]
        end,
        fs_stat = function(path)
            return stats[path]
        end,
    })

    local result = users_probe.inspect_root_path({ path = "/usr/bin::.:/bad:/missing" })
    users_probe._test_set_dependencies()

    assert(result.count == 5, "Expected empty, dot, unowned, permissive, and missing path failures")
end

function test_inspect_shells_reports_nologin_and_system_login_shells_from_shells_file()
    users_probe._test_set_dependencies({
        shells_path = "/tmp/shells",
        passwd_path = "/tmp/passwd",
        login_defs_path = "/tmp/login.defs",
        io_open = function(path)
            if path == "/tmp/shells" then
                return make_reader({
                    "/bin/bash",
                    "/usr/sbin/nologin",
                })
            end
            if path == "/tmp/passwd" then
                return make_reader({
                    "root:x:0:0:root:/root:/bin/bash",
                    "daemon:x:2:2:daemon:/sbin:/usr/sbin/nologin",
                    "games:x:12:12:games:/usr/games:/bin/bash",
                    "app:x:1000:1000:app:/home/app:/bin/bash",
                    "nobody:x:65534:65534:nobody:/nonexistent:/bin/bash",
                })
            end
            if path == "/tmp/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            return nil
        end,
    })

    local nologin_result = users_probe.inspect_shells({ check = "nologin_absent" })
    local system_shell_result = users_probe.inspect_system_account_shells({})
    users_probe._test_set_dependencies()

    assert(nologin_result.count == 1, "Expected /usr/sbin/nologin in /etc/shells to be reported")
    assert(system_shell_result.count == 2, "Expected games and nobody valid shells to be reported")
end

function test_inspect_nonlogin_accounts_locked_uses_shells_inventory_and_shadow_state()
    users_probe._test_set_dependencies({
        shells_path = "/tmp/shells",
        passwd_path = "/tmp/passwd",
        shadow_path = "/tmp/shadow",
        io_open = function(path)
            if path == "/tmp/shells" then
                return make_reader({ "/bin/bash" })
            end
            if path == "/tmp/passwd" then
                return make_reader({
                    "root:x:0:0:root:/root:/bin/bash",
                    "daemon:x:2:2:daemon:/sbin:/usr/sbin/nologin",
                    "svc:x:1001:1001:svc:/srv/svc:/bin/false",
                    "alice:x:1000:1000:alice:/home/alice:/bin/bash",
                })
            end
            if path == "/tmp/shadow" then
                return make_reader({
                    "root:$6$hash:20000:0:99999:7:::",
                    "daemon:!:20000:0:99999:7:::",
                    "svc:$6$hash:20000:0:99999:7:::",
                    "alice:$6$hash:20000:0:99999:7:::",
                })
            end
            return nil
        end,
    })

    local result = users_probe.inspect_nonlogin_accounts_locked()
    users_probe._test_set_dependencies()

    assert(result.count == 1, "Expected only unlocked non-login-shell account to fail")
    assert(result.details[1].user == "svc", "Expected svc to be reported")
end

function test_inspect_dotfiles_checks_forbidden_files_modes_and_netrc_warnings()
    local attrs = {
        ["/home/alice"] = { mode = "directory", dev = 1 },
        ["/home/alice/.profile"] = { mode = "file", dev = 1 },
        ["/home/alice/.bash_history"] = { mode = "file", dev = 1 },
        ["/home/alice/.rhosts"] = { mode = "file", dev = 1 },
        ["/home/alice/.netrc"] = { mode = "file", dev = 1 },
    }
    local stats = {
        ["/home/alice/.profile"] = make_stat(1000, 1000, tonumber("644", 8)),
        ["/home/alice/.bash_history"] = make_stat(1000, 1000, tonumber("644", 8)),
        ["/home/alice/.rhosts"] = make_stat(1000, 1000, tonumber("600", 8)),
        ["/home/alice/.netrc"] = make_stat(1000, 1000, tonumber("600", 8)),
    }

    users_probe._test_set_dependencies({
        passwd_path = "/tmp/test-passwd",
        io_open = function(path, mode)
            assert(path == "/tmp/test-passwd", "Expected configured passwd path to be used")
            assert(mode == "r", "Expected passwd file to be opened read-only")
            return make_reader({
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
            })
        end,
        lfs_symlinkattributes = function(path)
            return attrs[path]
        end,
        lfs_dir = function(path)
            assert(path == "/home/alice", "Expected home directory to be scanned")
            local entries = { ".", "..", ".profile", ".bash_history", ".rhosts", ".netrc" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        fs_stat = function(path)
            return stats[path]
        end,
    })

    local result = users_probe.inspect_dotfiles({})
    users_probe._test_set_dependencies()

    assert(result.count == 2, "Expected .rhosts and permissive .bash_history to fail")
    assert(result.warning_count == 1, "Expected compliant .netrc files to produce a warning only")
end

function test_inspect_dotfiles_flags_forbidden_symlinks()
    local attrs = {
        ["/home/alice"] = { mode = "directory", dev = 1 },
        ["/home/alice/.forward"] = { mode = "link", dev = 1 },
        ["/home/alice/.rhosts"] = { mode = "link", dev = 1 },
    }

    users_probe._test_set_dependencies({
        passwd_path = "/tmp/test-passwd",
        io_open = function(path, mode)
            assert(path == "/tmp/test-passwd", "Expected configured passwd path to be used")
            assert(mode == "r", "Expected passwd file to be opened read-only")
            return make_reader({
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
            })
        end,
        lfs_symlinkattributes = function(path)
            return attrs[path]
        end,
        lfs_dir = function(path)
            assert(path == "/home/alice", "Expected home directory to be scanned")
            local entries = { ".", "..", ".forward", ".rhosts" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        fs_stat = function(path)
            error("Forbidden dotfile symlinks should fail without following " .. path)
        end,
    })

    local result = users_probe.inspect_dotfiles({})
    users_probe._test_set_dependencies()

    assert(result.count == 2, "Expected forbidden dotfile symlinks to fail on existence")
    assert(result.details[1].reason == "forbidden_file", "Expected .forward symlink to fail as forbidden")
    assert(result.details[2].reason == "forbidden_file", "Expected .rhosts symlink to fail as forbidden")
end
