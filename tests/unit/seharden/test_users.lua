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
