local file_probe = require('seharden.probes.file')

local function with_dependencies(deps, fn)
    file_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    file_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

local function handle_for(content)
    return {
        lines = function()
            local lines = {}
            for line in (content .. "\n"):gmatch("(.-)\n") do
                lines[#lines + 1] = line
            end
            local index = 0
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function() end,
    }
end

local function make_stat(uid, gid, mode)
    return {
        uid = function() return uid end,
        gid = function() return gid end,
        mode = function() return mode end,
    }
end

local function dir_iter(entries)
    local state = { entries = entries, index = 0 }
    return function(s)
        s.index = s.index + 1
        return s.entries[s.index]
    end, state
end

function test_find_pattern_surfaces_open_failures()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/tmp/unreadable.conf" then
                return { mode = "file" }
            end
            return nil
        end,
        io_open = function(path, mode)
            assert(path == "/tmp/unreadable.conf", "Expected find_pattern to open the target file")
            assert(mode == "r", "Expected find_pattern to open files read-only")
            return nil, "permission denied"
        end,
    }, function()
        local result, err = file_probe.find_pattern({
            paths = { "/tmp/unreadable.conf" },
            pattern = "needle"
        })

        assert(result == nil, "Expected unreadable file to fail the probe")
        assert(err:find("/tmp/unreadable.conf", 1, true), "Expected error to mention the unreadable path")
    end)
end

function test_find_pattern_surfaces_grep_failures()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/tmp/grep-target.conf" then
                return { mode = "file" }
            end
            return nil
        end,
        os_execute = function(cmd)
            return nil, "exit", 2
        end,
    }, function()
        local result, err = file_probe.find_pattern({
            paths = { "/tmp/grep-target.conf" },
            pattern = "(bad|pattern"
        })

        assert(result == nil, "Expected grep execution failure to fail the probe")
        assert(err:find("/tmp/grep%-target%.conf"), "Expected grep failure to mention the target path")
    end)
end

function test_find_pattern_reports_zero_checked_files_in_band()
    with_dependencies({
        lfs_attributes = function()
            return nil
        end,
    }, function()
        local result, err = file_probe.find_pattern({
            paths = { "/tmp/missing.conf" },
            pattern = "needle"
        })

        assert(err == nil, "Expected missing path expansion evidence not to raise a probe error")
        assert(result.found == false, "Expected missing files not to produce a match")
        assert(result.checked_count == 0, "Expected checked_count to reveal that no file was inspected")
    end)
end

function test_find_pattern_handles_luajit_raw_grep_exit_statuses()
    local calls = 0

    with_dependencies({
        lfs_attributes = function(path)
            if path == "/tmp/grep-target.conf" then
                return { mode = "file" }
            end
            return nil
        end,
        os_execute = function(cmd)
            assert(cmd:find("grep %-E %-q", 1, false), "Expected alternation pattern to use grep -E")
            calls = calls + 1
            if calls == 1 then
                return 256
            end
            return 0
        end,
    }, function()
        local missing, missing_err = file_probe.find_pattern({
            paths = { "/tmp/grep-target.conf" },
            pattern = "missing|absent"
        })
        local matched, matched_err = file_probe.find_pattern({
            paths = { "/tmp/grep-target.conf" },
            pattern = "present|found"
        })

        assert(missing_err == nil, "Expected grep no-match to return false, not an engine error")
        assert(missing.found == false, "Expected raw exit status 256 to mean grep no-match")
        assert(missing.checked_count == 1, "Expected checked_count to report inspected files")
        assert(matched_err == nil, "Expected grep success to return true")
        assert(matched.found == true, "Expected raw exit status 0 to mean grep matched")
        assert(matched.checked_count == 1, "Expected checked_count to report inspected files")
    end)
end

function test_list_paths_returns_expanded_matches()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/ssh" then
                return { mode = "directory" }
            end
            if path == "/etc/ssh/ssh_host_rsa_key"
                or path == "/etc/ssh/ssh_host_ed25519_key" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/ssh", "Expected list_paths to enumerate the target directory")
            local entries = {
                ".",
                "..",
                "ssh_host_rsa_key",
                "ssh_host_ed25519_key",
                "sshd_config",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
    }, function()
        local result = file_probe.list_paths({
            paths = { "/etc/ssh/ssh_host_*_key" }
        })

        assert(result.count == 2, "Expected two matching host key files")
        assert(result.details[1].path == "/etc/ssh/ssh_host_rsa_key"
            or result.details[2].path == "/etc/ssh/ssh_host_rsa_key",
            "Expected list_paths to include ssh_host_rsa_key")
    end)
end

function test_list_paths_matches_only_public_key_globs()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/ssh" then
                return { mode = "directory" }
            end
            if path == "/etc/ssh/ssh_host_rsa_key"
                or path == "/etc/ssh/ssh_host_rsa_key.pub"
                or path == "/etc/ssh/ssh_host_ed25519_key.pub" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/ssh", "Expected list_paths to enumerate the target directory")
            local entries = {
                ".",
                "..",
                "ssh_host_rsa_key",
                "ssh_host_rsa_key.pub",
                "ssh_host_ed25519_key.pub",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
    }, function()
        local result = file_probe.list_paths({
            paths = { "/etc/ssh/ssh_host_*_key.pub" }
        })

        assert(result.count == 2, "Expected only public host key files to match the .pub glob")
        for _, detail in ipairs(result.details) do
            assert(detail.path:match("%.pub$"), "Expected public key glob results to end with .pub")
        end
    end)
end

function test_inspect_bootloader_config_access_applies_path_specific_modes()
    local stats = {
        ["/boot/grub2/grub.cfg"] = make_stat(0, 0, tonumber("600", 8)),
        ["/boot/grub2/grubenv"] = make_stat(0, 0, tonumber("640", 8)),
        ["/boot/efi/EFI/alinux/grub.cfg"] = make_stat(0, 0, tonumber("700", 8)),
    }

    with_dependencies({
        fs_stat = function(path)
            return stats[path]
        end,
        lfs_attributes = function(path)
            if path == "/boot"
                or path == "/boot/grub2"
                or path == "/boot/efi"
                or path == "/boot/efi/EFI"
                or path == "/boot/efi/EFI/alinux" then
                return { mode = "directory" }
            end
            if stats[path] then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            local entries = {
                ["/boot"] = { ".", "..", "efi", "grub2" },
                ["/boot/grub2"] = { ".", "..", "grub.cfg", "grubenv", "notes.txt" },
                ["/boot/efi"] = { ".", "..", "EFI" },
                ["/boot/efi/EFI"] = { ".", "..", "alinux" },
                ["/boot/efi/EFI/alinux"] = { ".", "..", "grub.cfg" },
            }
            return dir_iter(entries[path] or { ".", ".." })
        end,
    }, function()
        local result = file_probe.inspect_bootloader_config_access({ base_path = "/boot" })

        assert(result.available == true, "Expected /boot traversal to be available")
        assert(result.checked_count == 3, "Expected grub* files under /boot to be checked recursively")
        assert(result.invalid_count == 1, "Expected overly permissive /boot/grub2 mode to fail")
        assert(result.all_configured == false, "Expected any invalid bootloader config file to fail the aggregate")
    end)
end

function test_inspect_bootloader_config_access_fails_when_boot_cannot_be_enumerated()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/boot" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/boot", "Expected probe to enumerate the configured boot path")
            return nil, "permission denied"
        end,
    }, function()
        local result = file_probe.inspect_bootloader_config_access({ base_path = "/boot" })

        assert(result.available == false, "Expected unavailable bootloader evidence to fail closed")
        assert(result.all_configured == false, "Expected unavailable bootloader evidence not to pass")
        assert(result.error:find("permission denied", 1, true), "Expected traversal error evidence to be retained")
    end)
end

function test_find_key_value_outside_allowed_flags_each_invalid_assignment()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/yum.repos.d" then
                return { mode = "directory" }
            end
            if path == "/etc/yum.repos.d/base.repo" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/yum.repos.d", "Expected repo directory expansion")
            local entries = { ".", "..", "base.repo" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only file access")
            assert(path == "/etc/yum.repos.d/base.repo", "Expected repo file to be opened")
            return handle_for([[
[baseos]
gpgcheck=true
[bad]
gpgcheck=10
[disabled]
gpgcheck=no
]])
        end,
    }, function()
        local result = file_probe.find_key_value_outside_allowed({
            paths = { "/etc/yum.repos.d/*" },
            key = "gpgcheck",
            allowed_values = { "1", "true", "yes" },
            normalize_values = "lower",
        })

        assert(result.found == true, "Expected invalid gpgcheck values to be found")
        assert(result.count == 2, "Expected each invalid gpgcheck assignment to be reported")
    end)
end

function test_find_key_value_matches_only_requested_section()
    local files = {
        ["/etc/dconf/db/local.d/00-login-screen"] = table.concat({
            "[org/gnome/desktop/interface]",
            "banner-message-enable=true",
            "[org/gnome/login-screen]",
            "banner-message-enable=true",
        }, "\n"),
        ["/etc/dconf/db/local.d/10-other"] = table.concat({
            "[org/gnome/desktop/interface]",
            "disable-user-list=true",
        }, "\n"),
    }

    with_dependencies({
        lfs_attributes = function(path, attr)
            local mode
            if path == "/etc/dconf/db/local.d" then
                mode = "directory"
            elseif files[path] then
                mode = "file"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/dconf/db/local.d", "Expected dconf local database directory")
            local entries = { ".", "..", "00-login-screen", "10-other" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only file access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local enabled = file_probe.find_key_value({
            paths = { "/etc/dconf/db/local.d/*" },
            section = "org/gnome/login-screen",
            key = "banner-message-enable",
            expected_value = "true",
            normalize_values = "lower",
        })
        local disabled_user_list = file_probe.find_key_value({
            paths = { "/etc/dconf/db/local.d/*" },
            section = "org/gnome/login-screen",
            key = "disable-user-list",
            expected_value = "true",
            normalize_values = "lower",
        })

        assert(enabled.found == true, "Expected key in requested section to match")
        assert(enabled.count == 1, "Expected only requested-section assignments to be reported")
        assert(disabled_user_list.found == false,
            "Expected same key value in a different section not to match")
    end)
end

function test_find_key_value_can_require_non_empty_quoted_values()
    local files = {
        ["/etc/dconf/db/local.d/00-login-screen"] = table.concat({
            "[org/gnome/login-screen]",
            "banner-message-text=''",
        }, "\n"),
        ["/etc/dconf/db/local.d/01-login-screen"] = table.concat({
            "[org/gnome/login-screen]",
            "banner-message-text='Authorized use only'",
        }, "\n"),
    }

    with_dependencies({
        lfs_attributes = function(path, attr)
            local mode
            if path == "/etc/dconf/db/local.d" then
                mode = "directory"
            elseif files[path] then
                mode = "file"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/dconf/db/local.d", "Expected dconf local database directory")
            local entries = { ".", "..", "00-login-screen", "01-login-screen" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only file access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local result = file_probe.find_key_value({
            paths = { "/etc/dconf/db/local.d/*" },
            section = "org/gnome/login-screen",
            key = "banner-message-text",
            require_non_empty_value = true,
        })

        assert(result.found == true, "Expected non-empty quoted values to match")
        assert(result.count == 1, "Expected empty quoted values not to match")
        assert(result.details[1].path == "/etc/dconf/db/local.d/01-login-screen",
            "Expected the non-empty assignment to be reported")
    end)
end

function test_find_key_value_can_match_numeric_suffix_ranges()
    local files = {
        ["/etc/dconf/db/local.d/00-screensaver"] = table.concat({
            "[org/gnome/desktop/session]",
            "idle-delay=uint32 900",
            "[org/gnome/desktop/screensaver]",
            "lock-delay=uint32 10",
        }, "\n"),
    }

    with_dependencies({
        lfs_attributes = function(path, attr)
            local mode
            if files[path] then
                mode = "file"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only file access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local idle = file_probe.find_key_value({
            paths = { "/etc/dconf/db/local.d/00-screensaver" },
            section = "org/gnome/desktop/session",
            key = "idle-delay",
            numeric_min = 1,
            numeric_max = 900,
        })
        local lock = file_probe.find_key_value({
            paths = { "/etc/dconf/db/local.d/00-screensaver" },
            section = "org/gnome/desktop/screensaver",
            key = "lock-delay",
            numeric_max = 5,
        })

        assert(idle.found == true, "Expected uint32 values inside the numeric range to match")
        assert(lock.found == false, "Expected uint32 values above the numeric range not to match")
    end)
end

function test_get_effective_key_value_uses_last_sorted_assignment()
    local files = {
        ["/etc/dconf/db/local.d/00-login-screen"] = table.concat({
            "[org/gnome/login-screen]",
            "banner-message-enable=true",
        }, "\n"),
        ["/etc/dconf/db/local.d/99-login-screen"] = table.concat({
            "[org/gnome/login-screen]",
            "banner-message-enable=false",
        }, "\n"),
    }

    with_dependencies({
        lfs_attributes = function(path, attr)
            local mode
            if path == "/etc/dconf/db/local.d" then
                mode = "directory"
            elseif files[path] then
                mode = "file"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/dconf/db/local.d", "Expected dconf local database directory")
            local entries = { ".", "..", "99-login-screen", "00-login-screen" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only file access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local result = file_probe.get_effective_key_value({
            paths = { "/etc/dconf/db/local.d/*" },
            section = "org/gnome/login-screen",
            key = "banner-message-enable",
            expected_value = "true",
            normalize_values = "lower",
        })

        assert(result.found == true, "Expected the effective key to be found")
        assert(result.matched == false, "Expected the later false assignment to override the earlier compliant line")
        assert(result.value == "false", "Expected the effective value to be reported")
        assert(result.path == "/etc/dconf/db/local.d/99-login-screen",
            "Expected effective files to be evaluated in sorted path order")
    end)
end

function test_parse_systemd_key_values_effective_merges_section_aware_dropins()
    local files = {
        ["/usr/lib/systemd/journald.conf"] = "[Journal]\nStorage=volatile\n[Other]\nCompress=no\n",
        ["/usr/lib/systemd/journald.conf.d/20-default.conf"] = "[Journal]\nStorage=volatile\n",
        ["/etc/systemd/journald.conf.d/20-default.conf"] = "[Journal]\nStorage=persistent\n",
        ["/run/systemd/journald.conf.d/30-runtime.conf"] = "[Journal]\nCompress=yes\n",
    }
    local dirs = {
        ["/etc/systemd/journald.conf.d"] = { ".", "..", "20-default.conf" },
        ["/run/systemd/journald.conf.d"] = { ".", "..", "30-runtime.conf" },
        ["/usr/lib/systemd/journald.conf.d"] = { ".", "..", "20-default.conf" },
    }

    with_dependencies({
        lfs_attributes = function(path, attr)
            local mode
            if files[path] then
                mode = "file"
            elseif dirs[path] then
                mode = "directory"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function(path)
            local entries = assert(dirs[path], "Unexpected directory: " .. tostring(path))
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only file access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local result = file_probe.parse_systemd_key_values({
            path = "/etc/systemd/journald.conf",
            config_dirs = { "/etc/systemd", "/run/systemd", "/usr/lib/systemd" },
            section = "Journal",
            effective = true,
            allow_missing = true,
        })

        assert(result.Storage == "persistent",
            "Expected higher-priority same-name drop-ins to mask lower-priority drop-ins")
        assert(result.Compress == "yes", "Expected later lexicographic drop-ins to override main config")
    end)
end
