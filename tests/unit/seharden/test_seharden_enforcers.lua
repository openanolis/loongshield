-- Unit tests for seharden enforcer modules
-- Each enforcer uses _test_set_dependencies for isolation.

--------------------------------------------------------------------------------
-- kmod enforcer
--------------------------------------------------------------------------------

local kmod_enforcer = require('seharden.enforcers.kmod')

function test_kmod_unload_calls_modprobe()
    local called_with = nil
    kmod_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            called_with = cmd
            return true, nil, 0
        end,
        io_open  = function() return nil, "not needed" end,
        io_lines = function()
            local lines = { "cramfs 16384 0 - Live 0x00000000" }
            local i = 0
            return function()
                i = i + 1
                return lines[i]
            end
        end,
        lfs_dir  = function() return nil end,
    })
    local ok = kmod_enforcer.unload({ name = "cramfs" })
    assert(ok == true, "Expected unload to succeed")
    assert(called_with ~= nil, "Expected os.execute to be called")
    assert(called_with:find("cramfs"), "Expected command to mention cramfs")
end

function test_kmod_unload_rejects_invalid_name()
    kmod_enforcer._test_set_dependencies({
        os_execute = function() return true end,
        io_open    = function() return nil end,
        io_lines   = function() return function() return nil end end,
        lfs_dir    = function() return nil end,
    })
    local ok, err = kmod_enforcer.unload({ name = "bad name!" })
    assert(ok == nil, "Expected error for invalid name")
    assert(err ~= nil, "Expected error message")
end

function test_kmod_unload_skips_when_module_already_unloaded()
    local called = false
    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            called = true
            return true, nil, 0
        end,
        io_open = function() return nil end,
        io_lines = function()
            return function()
                return nil
            end
        end,
        lfs_dir = function() return nil end,
    })

    local ok = kmod_enforcer.unload({ name = "cramfs" })
    assert(ok == true, "Expected already-unloaded module to be treated as success")
    assert(called == false, "Expected modprobe not to run when the module is already absent")
end

function test_kmod_unload_surfaces_modprobe_failure_for_loaded_module()
    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, "exit", 1
        end,
        io_open = function() return nil end,
        io_lines = function()
            local lines = { "cramfs 16384 0 - Live 0x00000000" }
            local i = 0
            return function()
                i = i + 1
                return lines[i]
            end
        end,
        lfs_dir = function() return nil end,
    })

    local ok, err = kmod_enforcer.unload({ name = "cramfs" })
    assert(ok == nil, "Expected loaded-module unload failures to be surfaced")
    assert(err:find("failed to unload 'cramfs'", 1, true),
        "Expected error to include the module name and unload failure")
end

function test_kmod_blacklist_writes_file_when_not_present()
    local written = {}
    local buf = {}

    local fake_file = {
        write = function(_, s) table.insert(buf, s) end,
        close = function() return true end,
    }

    kmod_enforcer._test_set_dependencies({
        os_execute = function() return true end,
        io_open    = function(path, mode)
            if mode == "w" then
                written.path = path
                return fake_file
            end
            return nil
        end,
        lfs_dir    = function() return function() return nil end end, -- empty dir
        io_lines   = function() return function() return nil end end,
        os_rename  = function()
            return true
        end,
        os_remove  = function()
            return true
        end,
    })

    local ok = kmod_enforcer.blacklist({ name = "cramfs" })
    assert(ok == true, "Expected blacklist to succeed")
    assert(written.path ~= nil, "Expected a file to be written")
    assert(table.concat(buf):find("blacklist cramfs"), "Expected blacklist line to be written")
end

function test_kmod_blacklist_skips_when_already_present()
    local written = false
    kmod_enforcer._test_set_dependencies({
        os_execute = function() return true end,
        io_open    = function()
            written = true
            return nil
        end,
        lfs_dir = function()
            local items = { "cramfs.conf" }
            local i = 0
            return function()
                i = i + 1
                return items[i]
            end
        end,
        io_lines = function()
            local lines = { "blacklist cramfs" }
            local i = 0
            return function()
                i = i + 1
                return lines[i]
            end
        end,
    })
    local ok = kmod_enforcer.blacklist({ name = "cramfs" })
    assert(ok == true, "Expected skip to return true")
    assert(written == false, "Expected no file write when already blacklisted")
end

function test_kmod_set_install_command_writes_file()
    local buf = {}
    local fake_file = {
        write = function(_, s) table.insert(buf, s) end,
        close = function() return true end,
    }
    kmod_enforcer._test_set_dependencies({
        os_execute = function() return true end,
        io_open    = function(_, mode)
            if mode == "w" then return fake_file end
            return nil
        end,
        lfs_dir    = function() return function() return nil end end,
        io_lines   = function() return function() return nil end end,
        os_rename  = function()
            return true
        end,
        os_remove  = function()
            return true
        end,
    })
    local ok = kmod_enforcer.set_install_command({ name = "cramfs" })
    assert(ok == true, "Expected set_install_command to succeed")
    assert(table.concat(buf):find("install cramfs /bin/true"),
        "Expected install line to be written")
end

--------------------------------------------------------------------------------
-- sysctl enforcer
--------------------------------------------------------------------------------

local sysctl_enforcer = require('seharden.enforcers.sysctl')

function test_sysctl_set_value_writes_live_and_persists()
    local live_written = nil
    local conf_written = {}

    local function fake_open(path, mode)
        if mode == "w" and path:find("proc") then
            return {
                write = function(_, s) live_written = s end,
                close = function() return true end,
            }
        elseif mode == "r" then
            return nil  -- no existing conf
        elseif mode == "w" then
            return {
                write = function(_, s) table.insert(conf_written, s) end,
                close = function() return true end,
            }
        end
        return nil
    end

    sysctl_enforcer._test_set_dependencies({
        io_open  = fake_open,
        io_lines = function() return function() return nil end end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        sysctl_conf = "/tmp/test-loongshield.conf",
        procfs_root = "/tmp/test-proc-sys",
    })

    local ok = sysctl_enforcer.set_value({ key = "kernel.randomize_va_space", value = "2" })
    assert(ok == true, "Expected set_value to succeed")
    assert(#conf_written > 0, "Expected conf file to be written")
    local conf_content = table.concat(conf_written)
    assert(conf_content:find("kernel.randomize_va_space"), "Expected key in conf file")
    assert(conf_content:find("2"), "Expected value in conf file")
end

function test_sysctl_set_value_rejects_invalid_key()
    sysctl_enforcer._test_set_dependencies({
        io_open  = function() return nil end,
        io_lines = function() return function() return nil end end,
    })
    local ok, err = sysctl_enforcer.set_value({ key = "../../etc/passwd", value = "1" })
    assert(ok == nil, "Expected error for path-traversal key")
    assert(err ~= nil, "Expected error message")
end

function test_sysctl_set_value_requires_both_params()
    sysctl_enforcer._test_set_dependencies({
        io_open  = function() return nil end,
        io_lines = function() return function() return nil end end,
    })
    local ok, err = sysctl_enforcer.set_value({ key = "some.key" })
    assert(ok == nil, "Expected error when value missing")
    assert(err ~= nil, "Expected error message")
end

function test_sysctl_set_value_updates_existing_key()
    local conf_written = {}
    local existing_lines = { "kernel.randomize_va_space = 0", "net.ipv4.ip_forward = 0" }
    local line_iter_pos = 0

    sysctl_enforcer._test_set_dependencies({
        sysctl_conf = "/tmp/test-loongshield.conf",
        procfs_root = "/tmp/test-proc-sys",
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        io_open = function(_, mode)
            if mode == "r" then
                line_iter_pos = 0
                return {
                    lines = function()
                        return function()
                            line_iter_pos = line_iter_pos + 1
                            return existing_lines[line_iter_pos]
                        end
                    end,
                    close = function() return true end,
                }
            elseif mode == "w" then
                return {
                    write = function(_, s) table.insert(conf_written, s) end,
                    close = function() return true end,
                }
            end
            return nil
        end,
        io_lines = function()
            local i = 0
            return function()
                i = i + 1
                return existing_lines[i]
            end
        end,
    })

    local ok = sysctl_enforcer.set_value({ key = "kernel.randomize_va_space", value = "2" })
    assert(ok == true, "Expected update to succeed")
    local content = table.concat(conf_written)
    assert(content:find("kernel.randomize_va_space = 2"), "Expected updated value in conf")
    assert(content:find("net.ipv4.ip_forward"), "Expected other keys preserved")
end

function test_sysctl_set_value_surfaces_live_write_failure_after_persisting()
    local conf_written = {}

    sysctl_enforcer._test_set_dependencies({
        sysctl_conf = "/tmp/test-loongshield.conf",
        procfs_root = "/tmp/test-proc-sys",
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        io_open = function(path, mode)
            if mode == "w" and path:find("proc") then
                return nil, "permission denied"
            elseif mode == "r" then
                return nil
            elseif mode == "w" then
                return {
                    write = function(_, s) table.insert(conf_written, s) end,
                    close = function() return true end,
                }
            end
            return nil
        end,
    })

    local ok, err = sysctl_enforcer.set_value({ key = "kernel.randomize_va_space", value = "2" })
    assert(ok == nil, "Expected live sysctl write failures to be surfaced")
    assert(err:find("live apply failed", 1, true),
        "Expected error to explain that the runtime sysctl write failed")
    assert(table.concat(conf_written):find("kernel.randomize_va_space = 2", 1, true),
        "Expected persistent sysctl config to still be written")
end

--------------------------------------------------------------------------------
-- permissions enforcer
--------------------------------------------------------------------------------

local permissions_enforcer = require('seharden.enforcers.permissions')

local function make_fs_attr(uid, gid, mode)
    return {
        uid = function() return uid end,
        gid = function() return gid end,
        mode = function() return mode end,
    }
end

function test_permissions_set_attributes_updates_owner_and_mode()
    local chown_called = nil
    local chmod_called = nil

    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(1000, 1000, 0644)
        end,
        fs_chown = function(path, uid, gid)
            chown_called = { path = path, uid = uid, gid = gid }
            return true
        end,
        fs_chmod = function(path, mode)
            chmod_called = { path = path, mode = mode }
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
    })

    local ok = permissions_enforcer.set_attributes({
        path = "/etc/shadow",
        uid = 0,
        gid = 0,
        mode = 0,
    })
    assert(ok == true, "Expected attribute update to succeed")
    assert(chown_called ~= nil, "Expected chown to be invoked")
    assert(chmod_called ~= nil, "Expected chmod to be invoked")
end

function test_permissions_set_attributes_rejects_symlink()
    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, 0)
        end,
        fs_chown = function()
            error("fs_chown should not be called for symlink paths")
        end,
        fs_chmod = function()
            error("fs_chmod should not be called for symlink paths")
        end,
        lfs_symlinkattributes = function()
            return { mode = "link" }
        end,
    })

    local ok, err = permissions_enforcer.set_attributes({
        path = "/etc/shadow",
        uid = 0,
        gid = 0,
        mode = 0,
    })
    assert(ok == nil, "Expected symlink paths to be rejected")
    assert(err:find("symlink"), "Expected error to mention symlink refusal")
end

function test_permissions_set_attributes_rejects_invalid_uid_and_gid()
    local chown_called = false
    local chmod_called = false

    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(1000, 1000, 0644)
        end,
        fs_chown = function()
            chown_called = true
            return true
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
    })

    local ok, err = permissions_enforcer.set_attributes({
        path = "/etc/shadow",
        uid = "root",
    })
    assert(ok == nil, "Expected invalid uid to be rejected")
    assert(err:find("invalid uid", 1, true), "Expected uid validation error")

    ok, err = permissions_enforcer.set_attributes({
        path = "/etc/shadow",
        gid = -1,
    })
    assert(ok == nil, "Expected invalid gid to be rejected")
    assert(err:find("invalid gid", 1, true), "Expected gid validation error")

    assert(chown_called == false, "Expected chown not to run on invalid input")
    assert(chmod_called == false, "Expected chmod not to run on invalid input")
end

function test_permissions_set_attributes_for_all_chmods_each_entry()
    local chmod_calls = {}
    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber("644", 8))
        end,
        fs_chmod = function(path, mode)
            chmod_calls[#chmod_calls + 1] = { path = path, mode = mode }
            return true
        end,
        fs_chown = function() return true end,
        lfs_symlinkattributes = function() return nil end,
    })
    local ok = permissions_enforcer.set_attributes_for_all({
        list = { details = {
            { path = "/home/alice/.ssh" },
            { path = "/home/bob/.ssh" },
        }},
        mode = tonumber("700", 8),
    })
    assert(ok == true, "Expected set_attributes_for_all to succeed")
    assert(#chmod_calls == 2, "Expected chmod called for each entry, got " .. #chmod_calls)
end

function test_permissions_set_attributes_for_all_skips_compliant()
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber("700", 8))
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        fs_chown = function() return true end,
        lfs_symlinkattributes = function() return nil end,
    })
    local ok = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = "/home/alice/.ssh" } } },
        mode = tonumber("700", 8),
    })
    assert(ok == true, "Expected success for already-compliant entries")
    assert(chmod_called == false, "Expected no chmod when mode already correct")
end

function test_permissions_set_attributes_for_all_requires_list()
    permissions_enforcer._test_set_dependencies({})
    local ok, err = permissions_enforcer.set_attributes_for_all({ mode = tonumber("700", 8) })
    assert(ok == nil, "Expected error when list is missing")
    assert(err ~= nil, "Expected error message")
end

function test_permissions_set_attributes_for_all_requires_mode()
    permissions_enforcer._test_set_dependencies({})
    local ok, err = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = "/tmp/test" } } },
    })
    assert(ok == nil, "Expected error when mode is missing")
    assert(err ~= nil, "Expected error message")
end

function test_permissions_set_attributes_for_all_skips_symlinks()
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        fs_stat = function() return make_fs_attr(0, 0, tonumber("644", 8)) end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        fs_chown = function() return true end,
        lfs_symlinkattributes = function() return { mode = "link" } end,
    })
    local ok = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = "/tmp/link" } } },
        mode = tonumber("700", 8),
    })
    assert(ok == true, "Expected success when symlink is skipped")
    assert(chmod_called == false, "Expected no chmod on symlink")
end

function test_permissions_fix_bootloader_config_fixes_permissions()
    local chown_called = false
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if path == "/boot" then return { mode = "directory" } end
            if path == "/boot/grub.cfg" then return { mode = "file" } end
            return nil
        end,
        lfs_dir = function(path)
            if path == "/boot" then
                local items = { "grub.cfg" }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function() return make_fs_attr(1000, 1000, tonumber("644", 8)) end,
        fs_chown = function() chown_called = true; return true end,
        fs_chmod = function() chmod_called = true; return true end,
    })
    local ok = permissions_enforcer.fix_bootloader_config({ base_path = "/boot" })
    assert(ok == true, "Expected fix_bootloader_config to succeed")
    assert(chown_called, "Expected chown to be called for non-root-owned file")
    assert(chmod_called, "Expected chmod to be called for wrong-mode file")
end

function test_permissions_fix_bootloader_config_idempotent()
    local chown_called = false
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if path == "/boot" then return { mode = "directory" } end
            if path == "/boot/grub.cfg" then return { mode = "file" } end
            return nil
        end,
        lfs_dir = function()
            local items = { "grub.cfg" }
            local i = 0
            return function()
                i = i + 1
                return items[i]
            end
        end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function() return make_fs_attr(0, 0, tonumber("600", 8)) end,
        fs_chown = function() chown_called = true; return true end,
        fs_chmod = function() chmod_called = true; return true end,
    })
    local ok = permissions_enforcer.fix_bootloader_config({ base_path = "/boot" })
    assert(ok == true, "Expected idempotent skip to succeed")
    assert(chown_called == false, "Expected no chown when already root-owned")
    assert(chmod_called == false, "Expected no chmod when mode already 0600")
end

function test_permissions_fix_bootloader_config_returns_true_when_no_files()
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if path == "/boot" then return { mode = "directory" } end
            return nil
        end,
        lfs_dir = function()
            local items = {}
            local i = 0
            return function()
                i = i + 1
                return items[i]
            end
        end,
    })
    local ok = permissions_enforcer.fix_bootloader_config({ base_path = "/boot" })
    assert(ok == true, "Expected success when no config files found")
end

function test_permissions_fix_sshd_config_access_fixes_permissions()
    local chown_called = false
    local chmod_called = false
    local fake_files = {
        ["/etc/ssh/sshd_config"] = true,
    }
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if fake_files[path] then return { mode = "file" } end
            return nil
        end,
        lfs_dir = function()
            local items = {}
            local i = 0
            return function()
                i = i + 1
                return items[i]
            end
        end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function() return make_fs_attr(1000, 1000, tonumber("644", 8)) end,
        fs_chown = function() chown_called = true; return true end,
        fs_chmod = function() chmod_called = true; return true end,
        io_open = function(path)
            if path == "/etc/ssh/sshd_config" then
                return {
                    lines = function() return function() return nil end end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = permissions_enforcer.fix_sshd_config_access({
        path = "/etc/ssh/sshd_config",
        include_dir = "/nonexistent",
    })
    assert(ok == true, "Expected fix_sshd_config_access to succeed")
    assert(chown_called, "Expected chown for non-root-owned sshd config")
    assert(chmod_called, "Expected chmod for wrong-mode sshd config")
end

function test_permissions_fix_sshd_config_access_returns_true_when_no_files()
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function() return nil end,
        lfs_dir = function() return nil end,
        lfs_symlinkattributes = function() return nil end,
        io_open = function() return nil end,
    })
    local ok = permissions_enforcer.fix_sshd_config_access({
        path = "/nonexistent/sshd_config",
        include_dir = "/nonexistent",
    })
    assert(ok == true, "Expected success when no config files found")
end

--------------------------------------------------------------------------------
-- file enforcer
--------------------------------------------------------------------------------

local file_enforcer = require('seharden.enforcers.file')

function test_file_append_line_adds_new_line()
    local written = {}
    local fake_file = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_file
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = file_enforcer.append_line({ path = "/etc/test.conf", line = "TESTKEY=1" })
    assert(ok == true, "Expected append to succeed")
    assert(table.concat(written):find("TESTKEY=1"), "Expected line to be written")
end

function test_file_append_line_idempotent()
    local written = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "TESTKEY=1" }
                local i = 0
                return {
                    lines  = function() return function() i = i + 1; return lines[i] end end,
                    close  = function() return true end,
                }
            end
            written = true
            return nil
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    -- Provide line reader via io.lines style
    local real_open = file_enforcer._test_set_dependencies
    file_enforcer._test_set_dependencies({
        io_open = function(path, mode)
            if mode == "r" then
                local lines = { "TESTKEY=1" }
                local i = 0
                -- simulate file:lines() by returning nil
                return {
                    lines = function(self)
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            written = true
            return nil
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    -- The enforcer uses io_open in "r" mode and iterates with :lines()
    local ok = file_enforcer.append_line({ path = "/etc/test.conf", line = "TESTKEY=1" })
    assert(ok == true, "Expected idempotent append to return true")
    assert(written == false, "Expected no write when line already present")
end

function test_file_remove_line_matching_removes_lines()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "keep this", "remove me", "keep this too" }
                local i = 0
                return {
                    lines = function()
                        return function() i = i + 1; return lines[i] end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = file_enforcer.remove_line_matching({ path = "/etc/test.conf", pattern = "remove" })
    assert(ok == true, "Expected removal to succeed")
    local content = table.concat(written)
    assert(not content:find("remove me"), "Expected matching line removed")
    assert(content:find("keep this"), "Expected non-matching lines preserved")
end

function test_file_set_key_value_appends_new_key()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = file_enforcer.set_key_value({ path = "/etc/test.conf", key = "MaxAuthTries", value = "4" })
    assert(ok == true, "Expected set to succeed")
    local content = table.concat(written)
    assert(content:find("MaxAuthTries=4"), "Expected key=value line appended")
end

function test_file_set_key_value_replaces_duplicate_keys_with_single_line()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = {
                    "MaxAuthTries=1",
                    "OtherKey=yes",
                    "MaxAuthTries=2",
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    local ok = file_enforcer.set_key_value({ path = "/etc/test.conf", key = "MaxAuthTries", value = "4" })
    assert(ok == true, "Expected duplicate key update to succeed")

    local content = table.concat(written)
    local _, count = content:gsub("MaxAuthTries=4", "")
    assert(count == 1, "Expected duplicate keys to collapse into one line")
    assert(content:find("OtherKey=yes"), "Expected unrelated keys to be preserved")
end

function test_file_set_key_value_rewrites_duplicate_identical_keys()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = {
                    "MaxAuthTries=4",
                    "MaxAuthTries=4",
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    local ok = file_enforcer.set_key_value({ path = "/etc/test.conf", key = "MaxAuthTries", value = "4" })
    assert(ok == true, "Expected duplicate identical key update to succeed")

    local content = table.concat(written)
    local _, count = content:gsub("MaxAuthTries=4", "")
    assert(count == 1, "Expected duplicate identical keys to be normalized")
end

function test_file_set_key_value_supports_whitespace_separators()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = {
                    "MAIL_DIR /var/spool/mail",
                    "UMASK    022",
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    local ok = file_enforcer.set_key_value({
        path = "/etc/login.defs",
        key = "UMASK",
        value = "027",
        separator = " ",
    })
    assert(ok == true, "Expected whitespace-separated key update to succeed")

    local content = table.concat(written)
    assert(content:find("MAIL_DIR /var/spool/mail", 1, true),
        "Expected unrelated login.defs settings to be preserved")
    assert(content:find("UMASK 027", 1, true),
        "Expected whitespace-separated key to be rewritten with the requested value")
end

function test_file_test_dependencies_reset_symlink_override()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        lfs_symlinkattributes = function()
            return { mode = "link" }
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    local ok, err = file_enforcer.append_line({ path = "/etc/test.conf", line = "TESTKEY=1" })
    assert(ok == nil, "Expected symlink override to block writes")
    assert(err:find("symlink"), "Expected symlink error")

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    ok, err = file_enforcer.append_line({ path = "/etc/test.conf", line = "TESTKEY=1" })
    assert(ok == true, "Expected dependency reset to restore default symlink handling")
end

function test_file_write_content_writes_new_file()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.write_content({ path = "/etc/test.conf", content = "line1\nline2\nline3" })
    assert(ok == true, "Expected write_content to succeed")
    local content = table.concat(written)
    assert(content:find("line1"), "Expected line1 in output")
    assert(content:find("line2"), "Expected line2 in output")
    assert(content:find("line3"), "Expected line3 in output")
end

function test_file_write_content_idempotent_when_content_matches()
    local write_called = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "line1", "line2" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            write_called = true
            return { write = function() end, close = function() end }
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.write_content({ path = "/etc/test.conf", content = "line1\nline2" })
    assert(ok == true, "Expected idempotent skip to return true")
    assert(write_called == false, "Expected no write when content already matches")
end

function test_file_write_content_rejects_missing_params()
    file_enforcer._test_set_dependencies({})
    local ok, err = file_enforcer.write_content({ path = "/etc/test.conf" })
    assert(ok == nil, "Expected error when content is nil")
    assert(err ~= nil, "Expected error message")

    ok, err = file_enforcer.write_content(nil)
    assert(ok == nil, "Expected error when params is nil")
end

function test_file_write_content_rejects_symlink()
    file_enforcer._test_set_dependencies({
        lfs_symlinkattributes = function() return { mode = "link" } end,
    })
    local ok, err = file_enforcer.write_content({ path = "/etc/link", content = "data" })
    assert(ok == nil, "Expected symlink rejection")
    assert(err:find("symlink"), "Expected symlink error message")
end

function test_file_set_ini_key_value_updates_existing_key_in_section()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "[daemon]", "log_level=info", "log_file=/var/log/test.log", "", "[security]", "enabled=true" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.set_ini_key_value({ path = "/etc/test.ini", section = "daemon", key = "log_level", value = "debug" })
    assert(ok == true, "Expected set_ini_key_value to succeed")
    local content = table.concat(written, "\n")
    assert(content:find("log_level=debug"), "Expected key value to be updated")
    assert(content:find("%[security%]"), "Expected other sections preserved")
end

function test_file_set_ini_key_value_appends_key_to_existing_section()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "[daemon]", "log_level=info", "", "[security]", "enabled=true" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.set_ini_key_value({ path = "/etc/test.ini", section = "daemon", key = "max_workers", value = "4" })
    assert(ok == true, "Expected set_ini_key_value to succeed")
    local content = table.concat(written, "\n")
    assert(content:find("max_workers=4"), "Expected new key to be appended to section")
end

function test_file_set_ini_key_value_creates_section_if_missing()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "[existing]", "key=val" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.set_ini_key_value({ path = "/etc/test.ini", section = "new_section", key = "key", value = "val" })
    assert(ok == true, "Expected set_ini_key_value to succeed")
    local content = table.concat(written, "\n")
    assert(content:find("%[new_section%]"), "Expected new section header")
    assert(content:find("key=val"), "Expected key=value in new section")
end

function test_file_set_ini_key_value_idempotent()
    local write_called = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "[daemon]", "log_level=info" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            write_called = true
            return { write = function() end, close = function() end }
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.set_ini_key_value({ path = "/etc/test.ini", section = "daemon", key = "log_level", value = "info" })
    assert(ok == true, "Expected idempotent skip to return true")
    assert(write_called == false, "Expected no write when value already correct")
end

function test_file_set_ini_key_value_rejects_missing_params()
    file_enforcer._test_set_dependencies({})
    local ok, err = file_enforcer.set_ini_key_value({ path = "/etc/test.ini", section = "daemon", key = "k" })
    assert(ok == nil, "Expected error when value is nil")
    assert(err ~= nil, "Expected error message")
end

function test_file_comment_line_matching_comments_matching_lines()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "allow_tcp_forwarding yes", "PermitRootLogin yes", "# already commented" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.comment_line_matching({ path = "/etc/ssh/sshd_config", pattern = "PermitRootLogin" })
    assert(ok == true, "Expected comment_line_matching to succeed")
    local content = table.concat(written, "\n")
    assert(content:find("# PermitRootLogin yes"), "Expected matching line to be commented")
    assert(content:find("allow_tcp_forwarding yes"), "Expected non-matching line to be preserved")
    assert(content:find("# already commented"), "Expected already-commented line to be preserved as-is")
end

function test_file_comment_line_matching_idempotent_when_all_commented()
    local write_called = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "# PermitRootLogin yes" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            write_called = true
            return { write = function() end, close = function() end }
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = file_enforcer.comment_line_matching({ path = "/etc/test.conf", pattern = "PermitRootLogin" })
    assert(ok == true, "Expected idempotent skip to return true")
    assert(write_called == false, "Expected no write when all lines already commented")
end

function test_file_comment_line_matching_returns_true_for_missing_file()
    file_enforcer._test_set_dependencies({
        io_open = function() return nil end,
    })
    local ok = file_enforcer.comment_line_matching({ path = "/nonexistent", pattern = "anything" })
    assert(ok == true, "Expected true when file doesn't exist")
end

function test_file_comment_line_matching_rejects_missing_params()
    file_enforcer._test_set_dependencies({})
    local ok, err = file_enforcer.comment_line_matching({ path = "/etc/test.conf" })
    assert(ok == nil, "Expected error when pattern is missing")
    assert(err ~= nil, "Expected error message")
end

--------------------------------------------------------------------------------
-- mounts enforcer
--------------------------------------------------------------------------------

local mounts_enforcer = require('seharden.enforcers.mounts')

function test_mounts_remount_returns_error_when_live_remount_fails()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }

    mounts_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, "exit", 32
        end,
        io_open = function(_, mode)
            if mode == "r" then
                local lines = {
                    "tmpfs /dev/shm tmpfs defaults 0 0",
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() return true end,
                }
            end
            return fake_out
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    local ok, err = mounts_enforcer.remount({ path = "/dev/shm", add_options = { "noexec" } })
    assert(ok == nil, "Expected live remount failure to be surfaced")
    assert(err:find("live remount failed", 1, true),
        "Expected error to explain that runtime remount did not succeed")
    assert(table.concat(written):find("defaults,noexec", 1, true),
        "Expected fstab update to still persist the requested option")
end

function test_mounts_remount_rejects_invalid_option_tokens()
    local ok, err = mounts_enforcer.remount({
        path = "/dev/shm",
        add_options = { "noexec,nosuid" }
    })

    assert(ok == nil, "Expected invalid mount option token to be rejected")
    assert(err:find("add_options%[1%]"), "Expected error to identify the bad option index")
end

--------------------------------------------------------------------------------
-- services enforcer
--------------------------------------------------------------------------------

local services_enforcer = require('seharden.enforcers.services')

function test_services_set_filestate_calls_systemctl()
    local cmd_run = nil
    services_enforcer._test_set_dependencies({
        io_popen = function(cmd)
            cmd_run = cmd
            return {
                read  = function() return "" end,
                close = function() return true end,
            }
        end,
    })
    local ok = services_enforcer.set_filestate({ name = "sshd.service", state = "disable" })
    assert(ok == true, "Expected set_filestate to succeed")
    assert(cmd_run ~= nil, "Expected systemctl to be called")
    assert(cmd_run:find("disable") and cmd_run:find("sshd"), "Expected correct systemctl command")
end

function test_services_set_filestate_uses_resolved_systemctl_path()
    local cmd_run = nil
    services_enforcer._test_set_dependencies({
        io_popen = function(cmd)
            cmd_run = cmd
            return {
                read = function() return "" end,
                close = function() return true end,
            }
        end,
        lfs_attributes = function(path)
            if path == "/usr/bin/systemctl" then
                return { mode = "file" }
            end
            return nil
        end,
    })

    local ok = services_enforcer.set_filestate({ name = "sshd.service", state = "disable" })

    assert(ok == true, "Expected set_filestate to succeed with resolved systemctl path")
    assert(cmd_run:match("^/usr/bin/systemctl disable sshd%.service 2>&1$"),
        "Expected systemctl command to use the resolved absolute path")
end

function test_services_set_filestate_rejects_invalid_unit()
    services_enforcer._test_set_dependencies({
        io_popen = function() return nil end,
    })
    local ok, err = services_enforcer.set_filestate({ name = "bad;name", state = "disable" })
    assert(ok == nil, "Expected error for invalid unit name")
    assert(err ~= nil, "Expected error message")
end

function test_services_set_filestate_rejects_invalid_state()
    services_enforcer._test_set_dependencies({
        io_popen = function() return nil end,
    })
    local ok, err = services_enforcer.set_filestate({ name = "sshd.service", state = "explode" })
    assert(ok == nil, "Expected error for invalid state")
    assert(err ~= nil, "Expected error message")
end

function test_services_set_active_state_calls_systemctl()
    local cmd_run = nil
    services_enforcer._test_set_dependencies({
        io_popen = function(cmd)
            cmd_run = cmd
            return {
                read  = function() return "" end,
                close = function() return true end,
            }
        end,
    })
    local ok = services_enforcer.set_active_state({ name = "sshd.service", state = "stop" })
    assert(ok == true, "Expected set_active_state to succeed")
    assert(cmd_run:find("stop") and cmd_run:find("sshd"), "Expected correct systemctl stop command")
end

function test_services_set_filestate_reports_systemctl_failures()
    services_enforcer._test_set_dependencies({
        io_popen = function()
            return {
                read = function() return "Unit demo.service not found.\n" end,
                close = function() return nil, "exit", 1 end,
            }
        end,
    })

    local ok, err = services_enforcer.set_filestate({ name = "demo.service", state = "disable" })
    assert(ok == nil, "Expected service enforcer to report systemctl failure")
    assert(err:find("not found"), "Expected stderr/stdout from failed systemctl to be surfaced")
end

--------------------------------------------------------------------------------
-- packages enforcer
--------------------------------------------------------------------------------

local packages_enforcer = require('seharden.enforcers.packages')

function test_packages_install_calls_dnf()
    local cmd_run = nil
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
    })
    local ok = packages_enforcer.install({ name = "aide" })
    assert(ok == true, "Expected install to succeed")
    assert(cmd_run:find("dnf install") and cmd_run:find("aide"), "Expected dnf install command")
end

function test_packages_install_rejects_wildcard()
    packages_enforcer._test_set_dependencies({
        os_execute = function() return true end,
    })
    local ok, err = packages_enforcer.install({ name = "aide*" })
    assert(ok == nil, "Expected error for wildcard package name")
    assert(err ~= nil, "Expected error message")
end

function test_packages_remove_calls_dnf()
    local cmd_run = nil
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_popen = function()
            return {
                lines = function()
                    local done = false
                    return function()
                        if done then
                            return nil
                        end
                        done = true
                        return "telnet"
                    end
                end,
                close = function() return true, nil, 0 end,
            }
        end,
    })
    local ok = packages_enforcer.remove({ name = "telnet" })
    assert(ok == true, "Expected remove to succeed")
    assert(cmd_run:find("dnf remove") and cmd_run:find("telnet"), "Expected dnf remove command")
end

function test_packages_remove_matching_calls_dnf_with_sorted_matches()
    local cmd_run = nil
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_popen = function(cmd)
            assert(cmd:find("rpm %-qa", 1) ~= nil, "Expected remove_matching to inspect installed packages")
            local packages = { "bluez-libs", "telnet-server", "bluez" }
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return packages[i]
                    end
                end,
                close = function() return true, nil, 0 end,
            }
        end,
    })

    local ok = packages_enforcer.remove_matching({ pattern = "bluez*" })
    assert(ok == true, "Expected remove_matching to succeed")
    assert(cmd_run ~= nil, "Expected dnf remove command to be issued")
    assert(cmd_run:find("dnf remove %-y bluez bluez%-libs", 1) ~= nil,
        "Expected matched packages to be removed in deterministic order")
end

function test_packages_remove_matching_skips_when_nothing_matches()
    local cmd_run = nil
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_popen = function()
            return {
                lines = function()
                    return function() return nil end
                end,
                close = function() return true, nil, 0 end,
            }
        end,
    })

    local ok = packages_enforcer.remove_matching({ pattern = "wdaemon*" })
    assert(ok == true, "Expected remove_matching to no-op when nothing matches")
    assert(cmd_run == nil, "Expected dnf not to run when no packages match the pattern")
end

function test_packages_remove_matching_rejects_unsafe_pattern()
    packages_enforcer._test_set_dependencies({
        os_execute = function() return true end,
        io_popen = function() return nil end,
    })

    local ok, err = packages_enforcer.remove_matching({ pattern = "bluez*;rm" })
    assert(ok == nil, "Expected unsafe glob pattern to be rejected")
    assert(err ~= nil, "Expected error message for unsafe glob pattern")
end

function test_packages_remove_matching_rejects_malformed_glob_without_querying_rpm()
    local popen_called = false
    packages_enforcer._test_set_dependencies({
        os_execute = function() return true end,
        io_popen = function()
            popen_called = true
            return nil
        end,
    })

    local ok, err = packages_enforcer.remove_matching({ pattern = "[]" })
    assert(ok == nil, "Expected malformed glob pattern to be rejected")
    assert(err ~= nil, "Expected error message for malformed glob pattern")
    assert(popen_called == false, "Expected malformed glob validation to fail before querying installed packages")
end

function test_packages_update_calls_dnf_update()
    local cmds = {}
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = packages_enforcer.update({ name = "aide" })
    assert(ok == true, "Expected update to succeed")
    assert(cmds[1]:find("dnf update") and cmds[1]:find("aide"), "Expected dnf update command")
end

function test_packages_update_falls_back_to_install_when_not_installed()
    local cmds = {}
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            if cmd:find("dnf update") then
                return true, nil, 0
            end
            if cmd:find("rpm %-q") then
                return nil, "not installed", 1
            end
            if cmd:find("dnf install") then
                return true, nil, 0
            end
            return true, nil, 0
        end,
    })
    local ok = packages_enforcer.update({ name = "aide" })
    assert(ok == true, "Expected fallback install to succeed")
    local found_install = false
    for _, cmd in ipairs(cmds) do
        if cmd:find("dnf install") and cmd:find("aide") then
            found_install = true
        end
    end
    assert(found_install, "Expected dnf install fallback when package not installed")
end

function test_packages_update_rejects_wildcard()
    packages_enforcer._test_set_dependencies({
        os_execute = function() return true end,
    })
    local ok, err = packages_enforcer.update({ name = "aide*" })
    assert(ok == nil, "Expected error for wildcard package name")
    assert(err ~= nil, "Expected error message")
end

function test_packages_update_requires_name()
    packages_enforcer._test_set_dependencies({})
    local ok, err = packages_enforcer.update({})
    assert(ok == nil, "Expected error when name is missing")
    assert(err ~= nil, "Expected error message")
end

function test_packages_update_propagates_dnf_update_failure()
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            if cmd:find("dnf update") then
                return nil, "dnf update failed", 1
            end
            if cmd:find("rpm %-q") then
                return true, nil, 0
            end
            return true, nil, 0
        end,
    })
    local ok, err = packages_enforcer.update({ name = "aide" })
    assert(ok == nil, "Expected error when dnf update fails")
    assert(err ~= nil, "Expected error message")
end

--------------------------------------------------------------------------------
-- audit / pam / sudo enforcers
--------------------------------------------------------------------------------

local audit_enforcer = require('seharden.enforcers.audit')
local pam_enforcer = require('seharden.enforcers.pam')
local sudo_enforcer = require('seharden.enforcers.sudo')

local function merge_tables(...)
    local result = {}
    for index = 1, select('#', ...) do
        local tbl = select(index, ...)
        for key, value in pairs(tbl or {}) do
            result[key] = value
        end
    end
    return result
end

local function split_content_lines(content)
    local lines = {}
    content = tostring(content or "")
    if content == "" then
        return lines
    end

    if content:sub(-1) ~= "\n" then
        content = content .. "\n"
    end

    for line in content:gmatch("(.-)\n") do
        lines[#lines + 1] = line
    end

    return lines
end

local function make_fake_text_fs(initial_files, initial_attrs, directory_entries)
    local files = {}
    for path, content in pairs(initial_files or {}) do
        files[path] = content
    end

    local attrs = {}
    for path, attr in pairs(initial_attrs or {}) do
        attrs[path] = {
            type = attr.type,
            uid = attr.uid,
            gid = attr.gid,
            mode = attr.mode,
        }
    end

    local pending = {}
    local writes = {}

    local function ensure_attr(path)
        if not attrs[path] then
            attrs[path] = {}
        end
        return attrs[path]
    end

    local deps = {}

    deps.io_open = function(path, mode)
        if mode == "r" then
            local content = files[path]
            if content == nil then
                return nil, "not found"
            end

            local lines = split_content_lines(content)
            local index = 0
            return {
                lines = function()
                    return function()
                        index = index + 1
                        return lines[index]
                    end
                end,
                read = function(_, fmt)
                    if fmt == "*a" then
                        return content
                    end
                    return nil
                end,
                close = function() return true end,
            }
        end

        if mode == "w" then
            local buffer = {}
            return {
                write = function(_, chunk)
                    buffer[#buffer + 1] = chunk
                end,
                close = function()
                    pending[path] = table.concat(buffer)
                    return true
                end,
            }
        end

        return nil, "unsupported mode"
    end

    deps.os_rename = function(src, dst)
        if pending[src] == nil then
            return nil, "missing temp file"
        end

        files[dst] = pending[src]
        pending[src] = nil
        writes[#writes + 1] = {
            src = src,
            dst = dst,
            content = files[dst],
        }

        local attr = ensure_attr(dst)
        attr.type = attr.type or "file"
        return true
    end

    deps.os_remove = function(path)
        pending[path] = nil
        return true
    end

    deps.lfs_attributes = function(path)
        local attr = attrs[path]
        if attr then
            return { mode = attr.type or "file" }
        end
        if files[path] ~= nil then
            return { mode = "file" }
        end
        return nil
    end

    deps.lfs_symlinkattributes = function(path)
        local attr = attrs[path]
        if attr and attr.type == "link" then
            return { mode = "link" }
        end
        return deps.lfs_attributes(path)
    end

    deps.lfs_dir = function(path)
        local entries = directory_entries and directory_entries[path] or {}
        local index = 0
        return function()
            index = index + 1
            return entries[index]
        end
    end

    deps.fs_stat = function(path)
        if files[path] == nil and attrs[path] == nil then
            return nil
        end
        local attr = attrs[path] or {}
        return make_fs_attr(attr.uid or 0, attr.gid or 0, attr.mode or 420)
    end

    deps.fs_chown = function(path, uid, gid)
        local attr = ensure_attr(path)
        attr.uid = uid
        attr.gid = gid
        attr.type = attr.type or "file"
        return true
    end

    deps.fs_chmod = function(path, mode)
        local attr = ensure_attr(path)
        attr.mode = mode
        attr.type = attr.type or "file"
        return true
    end

    return deps, files, attrs, writes
end

function test_audit_ensure_watch_rule_appends_canonical_line_idempotently_and_preserves_attrs()
    local rule_file = "/etc/audit/rules.d/99-loongshield-seharden.rules"
    local deps, files, attrs = make_fake_text_fs(
        {
            [rule_file] = "# managed by test\n",
        },
        {
            ["/etc/audit/rules.d"] = { type = "directory" },
            [rule_file] = { type = "file", uid = 0, gid = 0, mode = 384 },
        },
        {
            ["/etc/audit/rules.d"] = {},
        }
    )

    audit_enforcer._test_set_dependencies(merge_tables(deps, {
        rules_dir = "/etc/audit/rules.d",
        fallback_rules_path = "/etc/audit/audit.rules",
    }))

    local ok = audit_enforcer.ensure_watch_rule({ path = "/etc/passwd", permissions = "aw" })
    assert(ok == true, "Expected audit watch rule creation to succeed")

    ok = audit_enforcer.ensure_watch_rule({ path = "/etc/passwd", permissions = "aw" })
    assert(ok == true, "Expected audit watch rule creation to be idempotent")

    local content = files[rule_file]
    assert(content:find("-w /etc/passwd -p wa", 1, true),
        "Expected watch rule permissions to be canonicalized in stable order")
    local _, count = content:gsub("%-w /etc/passwd %-p wa", "")
    assert(count == 1, "Expected duplicate audit watch rules to be avoided")
    assert(attrs[rule_file].uid == 0 and attrs[rule_file].gid == 0,
        "Expected audit rule file ownership to be preserved when rewriting")
    assert(attrs[rule_file].mode == 384,
        "Expected audit rule file mode to be preserved when rewriting")
end

function test_audit_ensure_syscall_rule_writes_each_arch_once()
    local rule_file = "/etc/audit/rules.d/99-loongshield-seharden.rules"
    local deps, files = make_fake_text_fs(
        {
            [rule_file] = "",
        },
        {
            ["/etc/audit/rules.d"] = { type = "directory" },
            [rule_file] = { type = "file", uid = 0, gid = 0, mode = 384 },
        },
        {
            ["/etc/audit/rules.d"] = {},
        }
    )

    audit_enforcer._test_set_dependencies(merge_tables(deps, {
        rules_dir = "/etc/audit/rules.d",
        fallback_rules_path = "/etc/audit/audit.rules",
    }))

    local ok = audit_enforcer.ensure_syscall_rule({
        syscalls = { "unlinkat", "unlink" },
        required_arches = { "b64", "b32" },
        auid_min = 1000,
    })
    assert(ok == true, "Expected syscall audit rule creation to succeed")

    ok = audit_enforcer.ensure_syscall_rule({
        syscalls = { "unlinkat", "unlink" },
        required_arches = { "b64", "b32" },
        auid_min = 1000,
    })
    assert(ok == true, "Expected syscall audit rule creation to be idempotent")

    local content = files[rule_file]
    assert(content:find("-F arch=b32 -S unlink -S unlinkat -F auid>=1000 -F auid!=unset", 1, true),
        "Expected syscall audit rule for b32 to be written with sorted syscalls")
    assert(content:find("-F arch=b64 -S unlink -S unlinkat -F auid>=1000 -F auid!=unset", 1, true),
        "Expected syscall audit rule for b64 to be written with sorted syscalls")
    local _, count = content:gsub("%-a always,exit", "")
    assert(count == 2, "Expected exactly one syscall audit rule per architecture")
end

function test_pam_ensure_entry_inserts_before_anchor_and_preserves_attrs()
    local path = "/etc/pam.d/system-auth"
    local deps, files, attrs = make_fake_text_fs(
        {
            [path] = table.concat({
                "auth required pam_env.so",
                "auth sufficient pam_unix.so",
            }, "\n") .. "\n",
        },
        {
            [path] = { type = "file", uid = 0, gid = 0, mode = 416 },
        }
    )

    pam_enforcer._test_set_dependencies(deps)

    local ok = pam_enforcer.ensure_entry({
        path = path,
        kind = "auth",
        module = "pam_faillock.so",
        control = "required",
        args = { "preauth" },
        match_args = { "preauth" },
        anchor_kind = "auth",
        anchor_module = "pam_unix.so",
    })
    assert(ok == true, "Expected PAM entry insertion to succeed")

    local content = files[path]
    local env_pos = content:find("auth required pam_env.so", 1, true)
    local faillock_pos = content:find("auth required pam_faillock.so preauth", 1, true)
    local unix_pos = content:find("auth sufficient pam_unix.so", 1, true)
    assert(env_pos and faillock_pos and unix_pos and env_pos < faillock_pos and faillock_pos < unix_pos,
        "Expected PAM entry to be inserted immediately before the anchor module")
    assert(attrs[path].uid == 0 and attrs[path].gid == 0,
        "Expected PAM file ownership to be preserved when rewriting")
    assert(attrs[path].mode == 416,
        "Expected PAM file mode to be preserved when rewriting")
end

function test_pam_ensure_entry_normalizes_duplicate_entries()
    local path = "/etc/pam.d/su"
    local deps, files = make_fake_text_fs(
        {
            [path] = table.concat({
                "auth required pam_wheel.so trust",
                "auth sufficient pam_unix.so",
                "auth required pam_wheel.so use_uid",
            }, "\n") .. "\n",
        },
        {
            [path] = { type = "file", uid = 0, gid = 0, mode = 420 },
        }
    )

    pam_enforcer._test_set_dependencies(deps)

    local ok = pam_enforcer.ensure_entry({
        path = path,
        kind = "auth",
        module = "pam_wheel.so",
        control = "required",
        args = { "use_uid" },
    })
    assert(ok == true, "Expected duplicate PAM entry normalization to succeed")

    local content = files[path]
    local _, count = content:gsub("auth required pam_wheel.so use_uid", "")
    assert(count == 1, "Expected duplicate PAM entries to collapse into one desired line")
    assert(not content:find("pam_wheel.so trust", 1, true),
        "Expected non-compliant duplicate PAM entries to be removed")
end

function test_sudo_set_use_pty_strips_negated_entries_and_preserves_attrs()
    local root_path = "/etc/sudoers"
    local include_dir = "/etc/sudoers.d"
    local include_file = include_dir .. "/custom"
    local deps, files, attrs = make_fake_text_fs(
        {
            [root_path] = table.concat({
                "Defaults !use_pty",
                "#includedir /etc/sudoers.d",
            }, "\n") .. "\n",
            [include_file] = table.concat({
                "Defaults !use_pty",
                "Defaults !authenticate",
            }, "\n") .. "\n",
        },
        {
            [root_path] = { type = "file", uid = 0, gid = 0, mode = 288 },
            [include_dir] = { type = "directory" },
            [include_file] = { type = "file", uid = 0, gid = 0, mode = 288 },
        },
        {
            [include_dir] = { "custom" },
        }
    )

    sudo_enforcer._test_set_dependencies(merge_tables(deps, {
        root_path = root_path,
    }))

    local ok = sudo_enforcer.set_use_pty({ root_path = root_path })
    assert(ok == true, "Expected sudo use_pty enforcement to succeed")

    assert(files[root_path]:find("Defaults use_pty", 1, true),
        "Expected the root sudoers file to gain a global Defaults use_pty line")
    assert(not files[root_path]:find("!use_pty", 1, true),
        "Expected negated use_pty directives to be removed from the root sudoers file")
    assert(not files[include_file]:find("!use_pty", 1, true),
        "Expected negated use_pty directives to be removed from included sudoers files")
    assert(files[include_file]:find("Defaults !authenticate", 1, true),
        "Expected unrelated Defaults directives in included sudoers files to be preserved")
    assert(attrs[root_path].mode == 288 and attrs[include_file].mode == 288,
        "Expected sudoers file modes to be preserved when rewriting")

    ok = sudo_enforcer.set_use_pty({ root_path = root_path })
    assert(ok == true, "Expected sudo use_pty enforcement to be idempotent")
    local _, count = files[root_path]:gsub("Defaults use_pty", "")
    assert(count == 1, "Expected only one global Defaults use_pty line after repeated runs")
end

function test_sudo_ensure_audit_watches_resolves_dynamic_sudoers_paths()
    local root_path = "/etc/sudoers"
    local include_file = "/etc/sudoers.local"
    local include_dir = "/etc/sudoers.d"
    local included_member = include_dir .. "/custom"
    local captured = {}
    local deps = make_fake_text_fs(
        {
            [root_path] = table.concat({
                "#include /etc/sudoers.local",
                "#includedir /etc/sudoers.d",
            }, "\n") .. "\n",
            [include_file] = "Defaults env_reset\n",
            [included_member] = "Defaults secure_path=/usr/sbin\n",
        },
        {
            [root_path] = { type = "file", uid = 0, gid = 0, mode = 288 },
            [include_file] = { type = "file", uid = 0, gid = 0, mode = 288 },
            [include_dir] = { type = "directory" },
            [included_member] = { type = "file", uid = 0, gid = 0, mode = 288 },
        },
        {
            [include_dir] = { "custom" },
        }
    )

    sudo_enforcer._test_set_dependencies(merge_tables(deps, {
        root_path = root_path,
        ensure_watch_rule = function(params)
            captured[#captured + 1] = {
                path = params.path,
                permissions = params.permissions,
            }
            return true
        end,
    }))

    local ok = sudo_enforcer.ensure_audit_watches({ root_path = root_path, permissions = "wa" })
    assert(ok == true, "Expected sudo audit-watch enforcement to succeed")
    assert(#captured == 3, "Expected sudo audit-watch enforcement to cover the root file, explicit include, and includedir")
    assert(captured[1].path == root_path,
        "Expected the root sudoers file to be watched")
    assert(captured[2].path == include_file,
        "Expected explicit include files to be watched individually")
    assert(captured[3].path == include_dir,
        "Expected includedir paths to be watched at the directory level")
    assert(captured[1].permissions == "wa" and captured[2].permissions == "wa" and captured[3].permissions == "wa",
        "Expected sudo audit-watch enforcement to pass through the requested permissions")
end

--------------------------------------------------------------------------------
-- users enforcer: username injection hardening
--------------------------------------------------------------------------------

local users_enforcer = require('seharden.enforcers.users')

function test_users_set_password_max_days_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error("os_execute must NOT be called for unsafe usernames")
        end,
    })

    local ok, err = users_enforcer.set_password_max_days_for_root({
        max_days = 90,
        entries = {
            { user = "alice;touch /tmp/x", pass_max_days = 999 },
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, "Expected unsafe username to be rejected")
    assert(err:find("unsafe username", 1, true),
        "Expected error to mention unsafe username")
end

function test_users_set_password_min_days_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error("os_execute must NOT be called for unsafe usernames")
        end,
    })

    local ok, err = users_enforcer.set_password_min_days_for_root({
        min_days = 7,
        entries = {
            { user = "bob$(rm -rf /)", pass_min_days = 0 },
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, "Expected unsafe username to be rejected")
    assert(err:find("unsafe username", 1, true),
        "Expected error to mention unsafe username")
end

function test_users_set_password_max_days_accepts_safe_usernames()
    local commands = {}
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            commands[#commands + 1] = cmd
            return true, nil, 0
        end,
    })

    local ok = users_enforcer.set_password_max_days_for_root({
        max_days = 90,
        entries = {
            { user = "alice", pass_max_days = 999 },
            { user = "bob_smith", pass_max_days = 100 },
            { user = "carol.admin", pass_max_days = 50 },  -- already compliant, skipped
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == true, "Expected safe usernames to succeed")
    assert(#commands == 2, "Expected two chage commands (carol.admin already compliant)")
    assert(commands[1]:find("alice"), "Expected alice command to be built")
    assert(commands[2]:find("bob_smith"), "Expected bob_smith command to be built")
end

function test_users_lock_empty_password_accounts_locks_empty()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    users_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "root:$6$hash:19000:0:99999:7:::", "emptyuser::19000:0:99999:7:::", "locked:!$6$hash:19000:0:99999:7:::" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return fake_out
        end,
        lfs_symlinkattributes = function() return nil end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = users_enforcer.lock_empty_password_accounts({ shadow_path = "/etc/shadow" })
    assert(ok == true, "Expected lock to succeed")
    local content = table.concat(written, "\n")
    assert(content:find("emptyuser:!"), "Expected empty password to be locked with ! prefix")
    assert(content:find("root:%$6%$"), "Expected non-empty password to be preserved")
end

function test_users_lock_empty_password_accounts_idempotent()
    local write_called = false
    users_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "root:$6$hash:19000:0:99999:7:::", "emptyuser:!locked:19000:0:99999:7:::" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            write_called = true
            return { write = function() end, close = function() return true end }
        end,
        lfs_symlinkattributes = function() return nil end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = users_enforcer.lock_empty_password_accounts({ shadow_path = "/etc/shadow" })
    assert(ok == true, "Expected idempotent skip to return true")
    assert(write_called == false, "Expected no write when no empty passwords found")
end

function test_users_lock_empty_password_accounts_rejects_symlink()
    users_enforcer._test_set_dependencies({
        lfs_symlinkattributes = function() return { mode = "link" } end,
    })
    local ok, err = users_enforcer.lock_empty_password_accounts({ shadow_path = "/etc/shadow" })
    assert(ok == nil, "Expected symlink rejection")
    assert(err:find("symlink"), "Expected symlink error message")
end

function test_users_lock_shutdown_and_halt_accounts_locks_existing()
    local cmds = {}
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            if cmd:find("getent passwd") then
                return true, nil, 0
            end
            if cmd:find("passwd %-l") then
                return true, nil, 0
            end
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.lock_shutdown_and_halt_accounts()
    assert(ok == true, "Expected lock to succeed")
    local found_shutdown = false
    local found_halt = false
    for _, cmd in ipairs(cmds) do
        if cmd:find("passwd %-l shutdown") then found_shutdown = true end
        if cmd:find("passwd %-l halt") then found_halt = true end
    end
    assert(found_shutdown, "Expected shutdown account to be locked")
    assert(found_halt, "Expected halt account to be locked")
end

function test_users_lock_shutdown_and_halt_accounts_skips_missing()
    local lock_called = false
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            if cmd:find("getent passwd") then
                return nil, "not found", 2
            end
            if cmd:find("passwd %-l") then
                lock_called = true
                return true, nil, 0
            end
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.lock_shutdown_and_halt_accounts()
    assert(ok == true, "Expected success when accounts don't exist")
    assert(lock_called == false, "Expected no passwd -l when accounts don't exist")
end

function test_users_set_password_defaults_applies_chage()
    local cmds = {}
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.set_password_defaults({
        max_days = 90,
        warn_days = 7,
        inactive = 30,
        entries = {
            { user = "alice", pass_max_days = 99999, pass_warn_age = 0, inactive = -1 },
        },
    })
    assert(ok == true, "Expected set_password_defaults to succeed")
    assert(#cmds > 0, "Expected at least one chage command")
    local cmd = cmds[1]
    assert(cmd:find("%-%-maxdays 90"), "Expected --maxdays in command")
    assert(cmd:find("%-%-warndays 7"), "Expected --warndays in command")
    assert(cmd:find("%-%-inactive 30"), "Expected --inactive in command")
    assert(cmd:find("alice"), "Expected username in command")
end

function test_users_set_password_defaults_skips_compliant()
    local cmd_called = false
    users_enforcer._test_set_dependencies({
        os_execute = function()
            cmd_called = true
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.set_password_defaults({
        max_days = 90,
        entries = {
            { user = "alice", pass_max_days = 60 },
        },
    })
    assert(ok == true, "Expected success for compliant user")
    assert(cmd_called == false, "Expected no chage when already compliant")
end

function test_users_set_password_defaults_requires_entries()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.set_password_defaults({ max_days = 90 })
    assert(ok == nil, "Expected error when entries missing")
    assert(err ~= nil, "Expected error message")
end

function test_users_set_password_defaults_requires_at_least_one_policy()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.set_password_defaults({ entries = { { user = "alice" } } })
    assert(ok == nil, "Expected error when no policy params given")
    assert(err ~= nil, "Expected error message")
end

function test_users_fix_future_password_changes_calls_chage()
    local cmds = {}
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.fix_future_password_changes({
        details = { { user = "alice" }, { user = "bob" } },
    })
    assert(ok == true, "Expected fix_future_password_changes to succeed")
    assert(#cmds == 2, "Expected two chage commands")
    assert(cmds[1]:find("chage %-%-lastday"), "Expected chage --lastday command")
    assert(cmds[1]:find("alice"), "Expected username in command")
end

function test_users_fix_future_password_changes_requires_details()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.fix_future_password_changes({})
    assert(ok == nil, "Expected error when details missing")
    assert(err ~= nil, "Expected error message")
end

function test_users_fix_future_password_changes_propagates_failure()
    users_enforcer._test_set_dependencies({
        os_execute = function() return nil, "failed", 1 end,
    })
    local ok, err = users_enforcer.fix_future_password_changes({
        details = { { user = "alice" } },
    })
    assert(ok == nil, "Expected error when chage fails")
    assert(err ~= nil, "Expected error message")
end

function test_users_lock_nologin_accounts_calls_passwd_lock()
    local cmds = {}
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.lock_nologin_accounts({
        details = { { user = "daemon" }, { user = "bin" } },
    })
    assert(ok == true, "Expected lock_nologin_accounts to succeed")
    assert(#cmds == 2, "Expected two passwd -l commands")
    assert(cmds[1]:find("passwd %-l daemon"), "Expected passwd -l for daemon")
end

function test_users_lock_nologin_accounts_requires_details()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.lock_nologin_accounts({})
    assert(ok == nil, "Expected error when details missing")
    assert(err ~= nil, "Expected error message")
end

function test_users_lock_root_account_calls_passwd_lock()
    local cmd_run = nil
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.lock_root_account()
    assert(ok == true, "Expected lock_root_account to succeed")
    assert(cmd_run:find("passwd %-l root"), "Expected passwd -l root command")
end

function test_users_lock_root_account_propagates_failure()
    users_enforcer._test_set_dependencies({
        os_execute = function() return nil, "failed", 1 end,
    })
    local ok, err = users_enforcer.lock_root_account()
    assert(ok == nil, "Expected error when passwd -l fails")
    assert(err ~= nil, "Expected error message")
end

function test_users_disable_system_account_shells_calls_usermod()
    local cmds = {}
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.disable_system_account_shells({
        details = { { user = "daemon" }, { user = "lp" } },
    })
    assert(ok == true, "Expected disable_system_account_shells to succeed")
    assert(#cmds == 2, "Expected two usermod commands")
    assert(cmds[1]:find("usermod %-s /usr/sbin/nologin daemon"), "Expected usermod with nologin")
end

function test_users_disable_system_account_shells_requires_details()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.disable_system_account_shells({})
    assert(ok == nil, "Expected error when details missing")
    assert(err ~= nil, "Expected error message")
end

function test_users_disable_system_account_shells_propagates_failure()
    users_enforcer._test_set_dependencies({
        os_execute = function() return nil, "failed", 1 end,
    })
    local ok, err = users_enforcer.disable_system_account_shells({
        details = { { user = "daemon" } },
    })
    assert(ok == nil, "Expected error when usermod fails")
    assert(err ~= nil, "Expected error message")
end

function test_users_set_password_defaults_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error("os_execute must NOT be called for unsafe usernames")
        end,
    })

    local ok, err = users_enforcer.set_password_defaults({
        max_days = 90,
        entries = {
            { user = "alice;touch /tmp/x", pass_max_days = 999, pass_warn_age = 7, inactive = 30 },
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, "Expected unsafe username to be rejected")
    assert(err:find("unsafe username", 1, true),
        "Expected error to mention unsafe username")
end

function test_users_fix_future_password_changes_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error("os_execute must NOT be called for unsafe usernames")
        end,
    })

    local ok, err = users_enforcer.fix_future_password_changes({
        details = { { user = "bob$(whoami)" } },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, "Expected unsafe username to be rejected")
    assert(err:find("unsafe username", 1, true),
        "Expected error to mention unsafe username")
end

function test_users_lock_nologin_accounts_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error("os_execute must NOT be called for unsafe usernames")
        end,
    })

    local ok, err = users_enforcer.lock_nologin_accounts({
        details = { { user = "`touch /tmp/pwned`" } },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, "Expected unsafe username to be rejected")
    assert(err:find("unsafe username", 1, true),
        "Expected error to mention unsafe username")
end

function test_users_disable_system_account_shells_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error("os_execute must NOT be called for unsafe usernames")
        end,
    })

    local ok, err = users_enforcer.disable_system_account_shells({
        details = { { user = "nobody|cat /etc/shadow" } },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, "Expected unsafe username to be rejected")
    assert(err:find("unsafe username", 1, true),
        "Expected error to mention unsafe username")
end

function test_users_fix_dotfiles_removes_forbidden_files()
    local removed = {}
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == "/etc/passwd" then
                local lines = { "testuser:x:1000:1000::/home/testuser:/bin/bash" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        lfs_symlinkattributes = function(path)
            if path == "/home/testuser" then return { mode = "directory", dev = 1 } end
            if path == "/home/testuser/.forward" then return { mode = "file", dev = 1 } end
            return nil
        end,
        lfs_dir = function(path)
            if path == "/home/testuser" then
                local items = { ".forward" }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        os_remove = function(path)
            removed[#removed + 1] = path
            return true
        end,
        fs_stat = function() return nil end,
        fs_chmod = function() return true end,
        fs_chown = function() return true end,
        passwd_path = "/etc/passwd",
    })
    local ok = users_enforcer.fix_dotfiles()
    assert(ok == true, "Expected fix_dotfiles to succeed")
    assert(#removed > 0, "Expected .forward to be removed")
    assert(removed[1]:find("%.forward"), "Expected .forward path in removals")
end

function test_users_fix_dotfiles_fixes_permissions()
    local chmod_called = false
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == "/etc/passwd" then
                local lines = { "testuser:x:1000:1000::/home/testuser:/bin/bash" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        lfs_symlinkattributes = function(path)
            if path == "/home/testuser" then return { mode = "directory", dev = 1 } end
            if path == "/home/testuser/.bashrc" then return { mode = "file", dev = 1 } end
            return nil
        end,
        lfs_dir = function(path)
            if path == "/home/testuser" then
                local items = { ".bashrc" }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        fs_stat = function()
            return {
                mode = function() return tonumber("777", 8) end,
                uid = function() return 1000 end,
                gid = function() return 1000 end,
            }
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        fs_chown = function() return true end,
        os_remove = function() return true end,
        passwd_path = "/etc/passwd",
    })
    local ok = users_enforcer.fix_dotfiles()
    assert(ok == true, "Expected fix_dotfiles to succeed")
    assert(chmod_called, "Expected chmod for overly permissive dotfile")
end

function test_users_fix_dotfiles_idempotent()
    local chmod_called = false
    local chown_called = false
    local remove_called = false
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == "/etc/passwd" then
                local lines = { "testuser:x:1000:1000::/home/testuser:/bin/bash" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        lfs_symlinkattributes = function(path)
            if path == "/home/testuser" then return { mode = "directory", dev = 1 } end
            if path == "/home/testuser/.bashrc" then return { mode = "file", dev = 1 } end
            return nil
        end,
        lfs_dir = function(path)
            if path == "/home/testuser" then
                local items = { ".bashrc" }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        fs_stat = function()
            return {
                mode = function() return tonumber("644", 8) end,
                uid = function() return 1000 end,
                gid = function() return 1000 end,
            }
        end,
        fs_chmod = function() chmod_called = true; return true end,
        fs_chown = function() chown_called = true; return true end,
        os_remove = function() remove_called = true; return true end,
        passwd_path = "/etc/passwd",
    })
    local ok = users_enforcer.fix_dotfiles()
    assert(ok == true, "Expected idempotent run to succeed")
    assert(chmod_called == false, "Expected no chmod for compliant dotfile")
    assert(chown_called == false, "Expected no chown for compliant dotfile")
    assert(remove_called == false, "Expected no removal for non-forbidden dotfile")
end

function test_users_fix_dotfiles_reports_os_remove_failure()
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == "/etc/passwd" then
                local lines = { "testuser:x:1000:1000::/home/testuser:/bin/bash" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        lfs_symlinkattributes = function(path)
            if path == "/home/testuser" then return { mode = "directory", dev = 1 } end
            if path == "/home/testuser/.forward" then return { mode = "file", dev = 1 } end
            return nil
        end,
        lfs_dir = function(path)
            if path == "/home/testuser" then
                local items = { ".forward" }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        os_remove = function() return nil, "Permission denied" end,
        fs_stat = function() return nil end,
        fs_chmod = function() return true end,
        fs_chown = function() return true end,
        passwd_path = "/etc/passwd",
    })
    local ok, err = users_enforcer.fix_dotfiles()
    assert(ok == nil, "Expected fix_dotfiles to report failure when os_remove fails")
    assert(err and err:find("remove"), "Expected error message mentioning remove, got: " .. tostring(err))
end

function test_users_fix_dotfiles_reports_fs_chmod_failure()
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == "/etc/passwd" then
                local lines = { "testuser:x:1000:1000::/home/testuser:/bin/bash" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        lfs_symlinkattributes = function(path)
            if path == "/home/testuser" then return { mode = "directory", dev = 1 } end
            if path == "/home/testuser/.bashrc" then return { mode = "file", dev = 1 } end
            return nil
        end,
        lfs_dir = function(path)
            if path == "/home/testuser" then
                local items = { ".bashrc" }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        fs_stat = function()
            return {
                mode = function() return tonumber("777", 8) end,
                uid = function() return 1000 end,
                gid = function() return 1000 end,
            }
        end,
        fs_chmod = function() return nil, "Operation not permitted" end,
        fs_chown = function() return true end,
        os_remove = function() return true end,
        passwd_path = "/etc/passwd",
    })
    local ok, err = users_enforcer.fix_dotfiles()
    assert(ok == nil, "Expected fix_dotfiles to report failure when fs_chmod fails")
    assert(err and err:find("chmod"), "Expected error message mentioning chmod, got: " .. tostring(err))
end

function test_users_fix_dotfiles_reports_fs_chown_failure()
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == "/etc/passwd" then
                local lines = { "testuser:x:1000:1000::/home/testuser:/bin/bash" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        lfs_symlinkattributes = function(path)
            if path == "/home/testuser" then return { mode = "directory", dev = 1 } end
            if path == "/home/testuser/.bashrc" then return { mode = "file", dev = 1 } end
            return nil
        end,
        lfs_dir = function(path)
            if path == "/home/testuser" then
                local items = { ".bashrc" }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        fs_stat = function()
            return {
                mode = function() return tonumber("644", 8) end,
                uid = function() return 0 end,
                gid = function() return 0 end,
            }
        end,
        fs_chmod = function() return true end,
        fs_chown = function() return nil, "Operation not permitted" end,
        os_remove = function() return true end,
        passwd_path = "/etc/passwd",
    })
    local ok, err = users_enforcer.fix_dotfiles()
    assert(ok == nil, "Expected fix_dotfiles to report failure when fs_chown fails")
    assert(err and err:find("chown"), "Expected error message mentioning chown, got: " .. tostring(err))
end

--------------------------------------------------------------------------------
-- sudo enforcer: !authenticate Defaults handling
--------------------------------------------------------------------------------

function test_sudo_remove_nopasswd_strips_authenticate_disabled_defaults()
    local root_path = "/etc/sudoers"
    local include_dir = "/etc/sudoers.d"
    local include_file = include_dir .. "/custom"
    local deps, files, attrs = make_fake_text_fs(
        {
            [root_path] = table.concat({
                "Defaults !authenticate",
                "#includedir /etc/sudoers.d",
            }, "\n") .. "\n",
            [include_file] = table.concat({
                "Defaults:deploy !authenticate",
                "deploy ALL=(ALL) NOPASSWD: ALL",
            }, "\n") .. "\n",
        },
        {
            [root_path] = { type = "file", uid = 0, gid = 0, mode = 288 },
            [include_dir] = { type = "directory" },
            [include_file] = { type = "file", uid = 0, gid = 0, mode = 288 },
        },
        {
            [include_dir] = { "custom" },
        }
    )

    sudo_enforcer._test_set_dependencies(deps)
    local ok = sudo_enforcer.remove_nopasswd({ root_path = root_path })
    sudo_enforcer._test_set_dependencies()

    assert(ok == true, "Expected remove_nopasswd to succeed")
    assert(not files[root_path]:find("!authenticate", 1, true),
        "Expected global !authenticate Defaults line to be dropped")
    assert(not files[include_file]:find("!authenticate", 1, true),
        "Expected scoped !authenticate Defaults line to be dropped")
    assert(not files[include_file]:find("NOPASSWD:", 1, true),
        "Expected NOPASSWD tag to be removed from rule line")
end

function test_sudo_remove_nopasswd_preserves_other_tokens_when_stripping_authenticate()
    local root_path = "/etc/sudoers"
    local deps, files, attrs = make_fake_text_fs(
        {
            [root_path] = table.concat({
                "Defaults authenticate, !authenticate, use_pty",
            }, "\n") .. "\n",
        },
        {
            [root_path] = { type = "file", uid = 0, gid = 0, mode = 288 },
        },
        {}
    )

    sudo_enforcer._test_set_dependencies(deps)
    local ok = sudo_enforcer.remove_nopasswd({ root_path = root_path })
    sudo_enforcer._test_set_dependencies()

    assert(ok == true, "Expected remove_nopasswd to succeed")
    assert(not files[root_path]:find("!authenticate", 1, true),
        "Expected !authenticate token to be removed")
    assert(files[root_path]:find("authenticate", 1, true),
        "Expected positive authenticate token to be preserved")
    assert(files[root_path]:find("use_pty", 1, true),
        "Expected other tokens like use_pty to be preserved")
end

--------------------------------------------------------------------------------
-- audit enforcer (new functions)
--------------------------------------------------------------------------------

function test_audit_ensure_path_exec_rule_writes_rule()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    audit_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_attributes = function() return { mode = "directory" } end,
        rules_dir = "/etc/audit/rules.d",
    })
    local ok = audit_enforcer.ensure_path_exec_rule({ path = "/usr/bin/sudo", key = "privileged", arches = { "b64" } })
    assert(ok == true, "Expected ensure_path_exec_rule to succeed")
    local content = table.concat(written)
    assert(content:find("path=/usr/bin/sudo"), "Expected path in rule")
    assert(content:find("arch=b64"), "Expected arch in rule")
    assert(content:find("%-k privileged"), "Expected key in rule")
end

function test_audit_ensure_path_exec_rule_rejects_unsafe_path()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_path_exec_rule({ path = "" })
    assert(ok == nil, "Expected error for empty path")
    assert(err ~= nil, "Expected error message")
end

function test_audit_ensure_path_exec_rule_rejects_invalid_key()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_path_exec_rule({ path = "/usr/bin/sudo", key = "bad key!" })
    assert(ok == nil, "Expected error for invalid key")
    assert(err ~= nil, "Expected error message")
end

function test_audit_ensure_privileged_command_rules_scans_and_writes()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    local popen_calls = {}
    audit_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        io_popen = function(cmd)
            popen_calls[#popen_calls + 1] = cmd
            local lines
            if cmd:find("findmnt") then
                lines = { "/" }
            else
                lines = { "/usr/bin/sudo", "/usr/bin/passwd" }
            end
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function() return true, nil, 0 end,
            }
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_attributes = function() return { mode = "directory" } end,
        rules_dir = "/etc/audit/rules.d",
    })
    local ok = audit_enforcer.ensure_privileged_command_rules({ key = "privileged" })
    assert(ok == true, "Expected ensure_privileged_command_rules to succeed")
    local content = table.concat(written)
    assert(content:find("path=/usr/bin/sudo"), "Expected sudo path in rules")
    assert(content:find("path=/usr/bin/passwd"), "Expected passwd path in rules")
    assert(#popen_calls >= 1 and popen_calls[1]:find("findmnt"), "Expected findmnt call for mount-point scanning")
end

function test_audit_ensure_privileged_command_rules_scans_multiple_mounts()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    local popen_calls = {}
    audit_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        io_popen = function(cmd)
            popen_calls[#popen_calls + 1] = cmd
            local lines
            if cmd:find("findmnt") then
                lines = { "/", "/usr" }
            elseif cmd:find("find '/'") then
                lines = { "/usr/bin/sudo" }
            elseif cmd:find("find '/usr'") then
                lines = { "/usr/libexec/dbus-daemon-launch-helper" }
            else
                lines = {}
            end
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function() return true, nil, 0 end,
            }
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_attributes = function() return { mode = "directory" } end,
        rules_dir = "/etc/audit/rules.d",
    })
    local ok = audit_enforcer.ensure_privileged_command_rules({ key = "privileged" })
    assert(ok == true, "Expected ensure_privileged_command_rules to succeed")
    local content = table.concat(written)
    assert(content:find("path=/usr/bin/sudo"), "Expected sudo from / filesystem")
    assert(content:find("path=/usr/libexec/dbus%-daemon%-launch%-helper"),
        "Expected binary from /usr filesystem (cross-mount scanning)")
end

function test_audit_ensure_privileged_command_rules_rejects_invalid_key()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_privileged_command_rules({ key = "bad key!" })
    assert(ok == nil, "Expected error for invalid key")
    assert(err ~= nil, "Expected error message")
end

function test_audit_reload_rules_calls_augenrules()
    local cmd_run = nil
    audit_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
    })
    local ok = audit_enforcer.reload_rules()
    assert(ok == true, "Expected reload_rules to succeed")
    assert(cmd_run:find("augenrules"), "Expected augenrules command")
    assert(cmd_run:find("%-%-load"), "Expected --load flag")
end

function test_audit_reload_rules_propagates_failure()
    audit_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, "failed", 1
        end,
    })
    local ok, err = audit_enforcer.reload_rules()
    assert(ok == nil, "Expected error when augenrules fails")
    assert(err ~= nil, "Expected error message")
end

function test_audit_ensure_directive_appends_line()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    audit_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_attributes = function() return { mode = "directory" } end,
        rules_dir = "/etc/audit/rules.d",
    })
    local ok = audit_enforcer.ensure_directive({ directive = "-e", value = "2" })
    assert(ok == true, "Expected ensure_directive to succeed")
    local content = table.concat(written)
    assert(content:find("%-e 2"), "Expected directive with value in output")
end

function test_audit_ensure_directive_rejects_missing_directive()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_directive({})
    assert(ok == nil, "Expected error when directive is missing")
    assert(err ~= nil, "Expected error message")
end

function test_audit_ensure_directive_rejects_directive_without_dash()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_directive({ directive = "badvalue" })
    assert(ok == nil, "Expected error for directive without leading dash")
    assert(err:find("must start with '-'"), "Expected specific error message")
end

--------------------------------------------------------------------------------
-- crypto_policy enforcer
--------------------------------------------------------------------------------

local crypto_policy_enforcer = require('seharden.enforcers.crypto_policy')

function test_crypto_policy_set_policy_calls_update_crypto_policies()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function() return nil end,
    })
    local ok = crypto_policy_enforcer.set_policy({ policy = "DEFAULT" })
    assert(ok == true, "Expected set_policy to succeed")
    assert(cmd_run:find("update%-crypto%-policies"), "Expected update-crypto-policies command")
    assert(cmd_run:find("DEFAULT"), "Expected policy name in command")
end

function test_crypto_policy_set_policy_writes_module_file()
    local written = {}
    local written_content = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function() return true, nil, 0 end,
        io_open = function(path, mode)
            if mode == "r" then return nil end
            if mode == "w" then
                written[#written + 1] = path
                return {
                    write = function(_, s) written_content = s end,
                    close = function() return true end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = "DEFAULT",
        modules = { { name = "NO-SHA1", content = "hash = SHA256\nsign = RSA-SHA256" } },
    })
    assert(ok == true, "Expected set_policy with modules to succeed")
    assert(#written > 0, "Expected module file to be written")
    assert(written[1]:find("NO%-SHA1%.pmod"), "Expected .pmod filename")
    assert(written_content:find("SHA256"), "Expected module content to be written")
end

function test_crypto_policy_set_policy_idempotent_module()
    local write_called = false
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function() return true, nil, 0 end,
        io_open = function(path, mode)
            if mode == "r" then
                return {
                    read = function() return "hash = SHA256\nsign = RSA-SHA256" end,
                    close = function() end,
                }
            end
            write_called = true
            return { write = function() end, close = function() return true end }
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = "DEFAULT",
        modules = { { name = "NO-SHA1", content = "hash = SHA256\nsign = RSA-SHA256" } },
    })
    assert(ok == true, "Expected idempotent skip to succeed")
    assert(write_called == false, "Expected no write when module content already matches")
end

function test_crypto_policy_set_policy_rejects_missing_policy()
    crypto_policy_enforcer._test_set_dependencies({})
    local ok, err = crypto_policy_enforcer.set_policy({})
    assert(ok == nil, "Expected error when policy is missing")
    assert(err ~= nil, "Expected error message")
end

function test_crypto_policy_set_policy_rejects_invalid_characters()
    crypto_policy_enforcer._test_set_dependencies({})
    local ok, err = crypto_policy_enforcer.set_policy({ policy = "DEFAULT; rm -rf /" })
    assert(ok == nil, "Expected error for policy with shell metacharacters")
    assert(err ~= nil, "Expected error message")
end

function test_crypto_policy_set_policy_rejects_invalid_module_content()
    crypto_policy_enforcer._test_set_dependencies({
        io_open = function() return nil end,
    })
    local ok, err = crypto_policy_enforcer.set_policy({
        policy = "DEFAULT",
        modules = { { name = "MOD", content = "hash = SHA256; evil" } },
    })
    assert(ok == nil, "Expected error for module content with shell metacharacters")
    assert(err ~= nil, "Expected error message")
end

function test_crypto_policy_set_policy_preserves_current_base_policy()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == "r" and path:find("config") then
                return {
                    read = function() return "FIPS" end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = "DEFAULT:NO-SHA1",
        current_policy_path = "/etc/crypto-policies/config",
    })
    assert(ok == true, "Expected set_policy to succeed")
    assert(cmd_run:find("FIPS:NO%-SHA1"), "Expected FIPS base preserved with NO-SHA1 appended, got: " .. tostring(cmd_run))
end

function test_crypto_policy_set_policy_deduplicates_subpolicies()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == "r" and path:find("config") then
                return {
                    read = function() return "DEFAULT:NO-SHA1" end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = "DEFAULT:NO-SHA1",
        current_policy_path = "/etc/crypto-policies/config",
    })
    assert(ok == true, "Expected set_policy to succeed")
    assert(cmd_run:find("DEFAULT:NO%-SHA1%s"), "Expected no duplicate NO-SHA1, got: " .. tostring(cmd_run))
    assert(not cmd_run:find("NO%-SHA1:NO%-SHA1"), "Expected no duplicate subpolicies, got: " .. tostring(cmd_run))
end

function test_crypto_policy_set_policy_merges_multiple_subpolicies()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == "r" and path:find("config") then
                return {
                    read = function() return "DEFAULT:NO-SHA1" end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = "DEFAULT:NO-WEAK-MACS",
        current_policy_path = "/etc/crypto-policies/config",
    })
    assert(ok == true, "Expected set_policy to succeed")
    assert(cmd_run:find("DEFAULT:NO%-SHA1:NO%-WEAK%-MACS"),
        "Expected both subpolicies present, got: " .. tostring(cmd_run))
end

function test_crypto_policy_set_policy_falls_back_when_config_unreadable()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function() return nil end,
    })
    local ok = crypto_policy_enforcer.set_policy({ policy = "DEFAULT:NO-SHA1" })
    assert(ok == true, "Expected set_policy to succeed")
    assert(cmd_run:find("DEFAULT:NO%-SHA1"), "Expected requested policy used as-is, got: " .. tostring(cmd_run))
end

--------------------------------------------------------------------------------
-- logging enforcer
--------------------------------------------------------------------------------

local logging_enforcer = require('seharden.enforcers.logging')

function test_logging_fix_logfile_access_chmods_non_compliant_files()
    local cmds = {}
    logging_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = logging_enforcer.fix_logfile_access({
        details = {
            { path = "/var/log/secure", exists = true, configured = false, mode_ok = false, expected_mode = tonumber("600", 8), owner_ok = true, group_ok = true },
        },
    })
    assert(ok == true, "Expected fix_logfile_access to succeed")
    local found_chmod = false
    for _, cmd in ipairs(cmds) do
        if cmd:find("chmod") and cmd:find("0600") then
            found_chmod = true
        end
    end
    assert(found_chmod, "Expected chmod command with correct mode")
end

function test_logging_fix_logfile_access_chowns_non_compliant_files()
    local cmds = {}
    logging_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = logging_enforcer.fix_logfile_access({
        details = {
            { path = "/var/log/messages", exists = true, configured = false, mode_ok = true, owner_ok = false, group_ok = true, allowed_owners = { "root" }, allowed_groups = { "root" } },
        },
    })
    assert(ok == true, "Expected fix_logfile_access to succeed")
    local found_chown = false
    for _, cmd in ipairs(cmds) do
        if cmd:find("chown") and cmd:find("root:root") then
            found_chown = true
        end
    end
    assert(found_chown, "Expected chown command with correct owner")
end

function test_logging_fix_logfile_access_skips_configured_entries()
    local cmd_called = false
    logging_enforcer._test_set_dependencies({
        os_execute = function()
            cmd_called = true
            return true, nil, 0
        end,
    })
    local ok = logging_enforcer.fix_logfile_access({
        details = {
            { path = "/var/log/secure", exists = true, configured = true },
        },
    })
    assert(ok == true, "Expected success when all entries are already configured")
    assert(cmd_called == false, "Expected no os_execute calls for configured entries")
end

function test_logging_fix_logfile_access_skips_missing_files()
    local cmd_called = false
    logging_enforcer._test_set_dependencies({
        os_execute = function()
            cmd_called = true
            return true, nil, 0
        end,
    })
    local ok = logging_enforcer.fix_logfile_access({
        details = {
            { path = "/var/log/nonexistent", exists = false, configured = false },
        },
    })
    assert(ok == true, "Expected success when files don't exist")
    assert(cmd_called == false, "Expected no os_execute calls for missing files")
end

function test_logging_fix_logfile_access_requires_details()
    logging_enforcer._test_set_dependencies({})
    local ok, err = logging_enforcer.fix_logfile_access({})
    assert(ok == nil, "Expected error when details is missing")
    assert(err ~= nil, "Expected error message")
end

function test_logging_fix_logfile_access_propagates_chmod_failure()
    logging_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, "failed", 1
        end,
    })
    local ok, err = logging_enforcer.fix_logfile_access({
        details = {
            { path = "/var/log/secure", exists = true, configured = false, mode_ok = false, expected_mode = tonumber("600", 8), owner_ok = true, group_ok = true },
        },
    })
    assert(ok == nil, "Expected error when chmod fails")
    assert(err ~= nil, "Expected error message")
end

--------------------------------------------------------------------------------
-- ssh enforcer
--------------------------------------------------------------------------------

local ssh_enforcer = require('seharden.enforcers.ssh')

function test_ssh_remove_disallowed_algorithms_removes_algos()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    ssh_enforcer._test_set_dependencies({
        io_open = function(path, mode)
            if path == "/usr/sbin/sshd" and mode == "r" then
                return { close = function() end }
            end
            if path == "/proc/sys/kernel/hostname" and mode == "r" then
                return { read = function() return "testhost" end, close = function() end }
            end
            if path == "/etc/hosts" and mode == "r" then
                return {
                    lines = function()
                        local lines = { "127.0.0.1 localhost" }
                        local i = 0
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            if mode == "r" then return nil end
            return fake_out
        end,
        io_popen = function()
            local lines = { "ciphers aes128-ctr,aes256-ctr,3des-cbc" }
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function() return true, nil, 0 end,
            }
        end,
        lfs_symlinkattributes = function() return nil end,
        lfs_attributes = function() return nil end,
        lfs_dir = function() return function() return nil end end,
        os_rename = function() return true end,
        os_remove = function() return true end,
    })
    local ok = ssh_enforcer.remove_disallowed_algorithms({
        key = "ciphers",
        conditions = { user = "root" },
        disallowed_algorithms = { "3des-cbc" },
    })
    assert(ok == true, "Expected remove_disallowed_algorithms to succeed")
    local content = table.concat(written, "\n")
    assert(content:find("Ciphers"), "Expected Ciphers directive in output")
    assert(content:find("aes128%-ctr"), "Expected safe algorithm preserved")
    assert(not content:find("3des%-cbc"), "Expected disallowed algorithm removed")
end

function test_ssh_remove_disallowed_algorithms_comments_out_conflicting_sshd_config()
    local written_files = {}
    local fake_filesystem = {
        ["/usr/sbin/sshd"] = "",
        ["/proc/sys/kernel/hostname"] = "testhost",
        ["/etc/hosts"] = "127.0.0.1 localhost",
        ["/etc/ssh/sshd_config"] = "Include /etc/ssh/sshd_config.d/*.conf\nCiphers 3des-cbc,aes128-ctr,aes256-ctr\nPort 22\n",
        ["/etc/ssh/sshd_config.d/00-cis-hardening.conf"] = nil,
    }
    ssh_enforcer._test_set_dependencies({
        io_open = function(path, mode)
            if mode == "r" then
                local content = fake_filesystem[path]
                if content == nil then return nil end
                local lines = {}
                for line in (content .. "\n"):gmatch("(.-)\n") do
                    lines[#lines + 1] = line
                end
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    read = function() return lines[1] end,
                    close = function() end,
                }
            end
            -- write mode
            local buf = {}
            written_files[path] = buf
            return {
                write = function(_, s) table.insert(buf, s) end,
                close = function() return true end,
            }
        end,
        io_popen = function()
            local lines = { "ciphers aes128-ctr,aes256-ctr,3des-cbc" }
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function() return true, nil, 0 end,
            }
        end,
        lfs_symlinkattributes = function() return nil end,
        lfs_attributes = function() return nil end,
        lfs_dir = function() return function() return nil end end,
        os_rename = function(src, dst)
            -- simulate rename by copying buf reference
            written_files[dst] = written_files[src]
            return true
        end,
        os_remove = function() return true end,
    })
    local ok = ssh_enforcer.remove_disallowed_algorithms({
        key = "ciphers",
        conditions = { user = "root" },
        disallowed_algorithms = { "3des-cbc" },
        sshd_config_path = "/etc/ssh/sshd_config",
    })
    assert(ok == true, "Expected remove_disallowed_algorithms to succeed")
    -- Verify sshd_config had the Ciphers line commented out
    local sshd_config_buf = written_files["/etc/ssh/sshd_config"]
    assert(sshd_config_buf ~= nil, "Expected sshd_config to be rewritten")
    local sshd_content = table.concat(sshd_config_buf)
    assert(sshd_content:find("# Ciphers"), "Expected Ciphers directive to be commented out in sshd_config, got: " .. sshd_content)
    assert(sshd_content:find("Port 22"), "Expected non-conflicting directives preserved")
end

function test_ssh_remove_disallowed_algorithms_rejects_missing_params()
    ssh_enforcer._test_set_dependencies({})
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({})
    assert(ok == nil, "Expected error when params are missing")
    assert(err ~= nil, "Expected error message")
end

function test_ssh_remove_disallowed_algorithms_rejects_unsupported_key()
    ssh_enforcer._test_set_dependencies({})
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({
        key = "unsupported",
        conditions = {},
        disallowed_algorithms = {},
    })
    assert(ok == nil, "Expected error for unsupported key")
    assert(err:find("unsupported"), "Expected 'unsupported' in error message")
end

function test_ssh_remove_disallowed_algorithms_rejects_symlink()
    ssh_enforcer._test_set_dependencies({
        lfs_symlinkattributes = function() return { mode = "link" } end,
    })
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({
        key = "ciphers",
        conditions = {},
        disallowed_algorithms = {},
        path = "/etc/ssh/link.conf",
    })
    assert(ok == nil, "Expected symlink rejection")
    assert(err:find("symlink"), "Expected symlink error message")
end

--------------------------------------------------------------------------------
-- sudo.fix_permission_paths
--------------------------------------------------------------------------------

function test_sudo_fix_permission_paths_chmods_files_and_dirs()
    local chmod_calls = {}
    sudo_enforcer._test_set_dependencies({
        fs_stat = function(path)
            if path:find("sudoers%.d") then
                return make_fs_attr(0, 0, tonumber("755", 8))
            end
            return make_fs_attr(0, 0, tonumber("644", 8))
        end,
        fs_chmod = function(path, mode)
            chmod_calls[#chmod_calls + 1] = { path = path, mode = mode }
            return true
        end,
        fs_chown = function() return true end,
        lfs_symlinkattributes = function() return nil end,
    })
    local ok = sudo_enforcer.fix_permission_paths({
        list = { details = {
            { path = "/etc/sudoers", path_type = "file" },
            { path = "/etc/sudoers.d", path_type = "directory" },
        }},
    })
    assert(ok == true, "Expected fix_permission_paths to succeed")
    assert(#chmod_calls == 2, "Expected chmod for both entries, got " .. #chmod_calls)
    assert(chmod_calls[1].mode == tonumber("0440", 8), "Expected 0440 for file")
    assert(chmod_calls[2].mode == tonumber("0750", 8), "Expected 0750 for directory")
end

function test_sudo_fix_permission_paths_skips_compliant()
    local chmod_called = false
    sudo_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber("0440", 8))
        end,
        fs_chmod = function() chmod_called = true; return true end,
        fs_chown = function() return true end,
        lfs_symlinkattributes = function() return nil end,
    })
    local ok = sudo_enforcer.fix_permission_paths({
        list = { details = {
            { path = "/etc/sudoers", path_type = "file" },
        }},
    })
    assert(ok == true, "Expected success for compliant entry")
    assert(chmod_called == false, "Expected no chmod when already correct")
end

function test_sudo_fix_permission_paths_skips_symlinks()
    local chmod_called = false
    sudo_enforcer._test_set_dependencies({
        fs_stat = function() return make_fs_attr(0, 0, tonumber("644", 8)) end,
        fs_chmod = function() chmod_called = true; return true end,
        fs_chown = function() return true end,
        lfs_symlinkattributes = function() return { mode = "link" } end,
    })
    local ok = sudo_enforcer.fix_permission_paths({
        list = { details = { { path = "/etc/sudoers", path_type = "file" } } },
    })
    assert(ok == true, "Expected success when symlink is skipped")
    assert(chmod_called == false, "Expected no chmod on symlink")
end

function test_sudo_fix_permission_paths_requires_list()
    sudo_enforcer._test_set_dependencies({})
    local ok, err = sudo_enforcer.fix_permission_paths({})
    assert(ok == nil, "Expected error when list is missing")
    assert(err ~= nil, "Expected error message")
end

function test_sudo_fix_permission_paths_propagates_chown_failure()
    sudo_enforcer._test_set_dependencies({
        fs_stat = function() return make_fs_attr(1000, 1000, tonumber("644", 8)) end,
        fs_chmod = function() return true end,
        fs_chown = function() return nil, "chown failed" end,
        lfs_symlinkattributes = function() return nil end,
    })
    local ok, err = sudo_enforcer.fix_permission_paths({
        list = { details = { { path = "/etc/sudoers", path_type = "file" } } },
    })
    assert(ok == nil, "Expected error when chown fails")
    assert(err:find("chown failed"), "Expected chown error in message")
end

--------------------------------------------------------------------------------
-- fsutil.write_lines_atomically_preserving_attrs
--------------------------------------------------------------------------------

local fsutil = require('seharden.enforcers.fsutil')

function test_fsutil_write_lines_preserving_attrs_restores_owner_and_mode()
    local chown_called = nil
    local chmod_called = nil
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    local deps = {
        io_open = function(_, mode)
            if mode == "w" then return fake_out end
            return nil
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function()
            return make_fs_attr(0, 640, tonumber("640", 8))
        end,
        fs_chown = function(path, uid, gid)
            chown_called = { path = path, uid = uid, gid = gid }
            return true
        end,
        fs_chmod = function(path, mode)
            chmod_called = { path = path, mode = mode }
            return true
        end,
    }
    local ok = fsutil.write_lines_atomically_preserving_attrs("/etc/shadow", {"line1", "line2"}, "test", deps)
    assert(ok == true, "Expected write to succeed")
    assert(chown_called ~= nil, "Expected chown to restore owner")
    assert(chown_called.uid == 0, "Expected uid 0 to be restored")
    assert(chown_called.gid == 640, "Expected gid 640 to be restored")
    assert(chmod_called ~= nil, "Expected chmod to restore mode")
    assert(chmod_called.mode == tonumber("640", 8), "Expected mode 0640 to be restored")
end

function test_fsutil_write_lines_preserving_attrs_writes_content()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    local deps = {
        io_open = function(_, mode)
            if mode == "w" then return fake_out end
            return nil
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function() return nil end,
        fs_chown = function() return true end,
        fs_chmod = function() return true end,
    }
    local ok = fsutil.write_lines_atomically_preserving_attrs("/etc/test", {"alpha", "beta"}, "test", deps)
    assert(ok == true, "Expected write to succeed")
    local content = table.concat(written)
    assert(content:find("alpha"), "Expected alpha in output")
    assert(content:find("beta"), "Expected beta in output")
end

--------------------------------------------------------------------------------
-- fsutil.append_unique_line
--------------------------------------------------------------------------------

function test_fsutil_append_unique_line_appends_when_missing()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    local deps = {
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "existing_line" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function() return nil end,
        fs_chown = function() return true end,
        fs_chmod = function() return true end,
    }
    local ok = fsutil.append_unique_line("/etc/test.rules", "new_rule_line", "test", deps)
    assert(ok == true, "Expected append to succeed")
    local content = table.concat(written)
    assert(content:find("existing_line"), "Expected existing line preserved")
    assert(content:find("new_rule_line"), "Expected new line appended")
end

function test_fsutil_append_unique_line_idempotent()
    local write_called = false
    local deps = {
        io_open = function(_, mode)
            if mode == "r" then
                local lines = { "existing_line", "target_line" }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            write_called = true
            return { write = function() end, close = function() return true end }
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function() return nil end,
        fs_chown = function() return true end,
        fs_chmod = function() return true end,
    }
    local ok = fsutil.append_unique_line("/etc/test.rules", "target_line", "test", deps)
    assert(ok == true, "Expected idempotent skip to succeed")
    assert(write_called == false, "Expected no write when line already present")
end

function test_fsutil_append_unique_line_rejects_symlink()
    local deps = {
        lfs_symlinkattributes = function() return { mode = "link" } end,
    }
    local ok, err = fsutil.append_unique_line("/etc/link", "line", "test", deps)
    assert(ok == nil, "Expected symlink rejection")
    assert(err:find("symlink"), "Expected symlink error message")
end

function test_fsutil_append_unique_line_creates_new_file()
    local written = {}
    local fake_out = {
        write = function(_, s) table.insert(written, s) end,
        close = function() return true end,
    }
    local deps = {
        io_open = function(_, mode)
            if mode == "r" then return nil end
            return fake_out
        end,
        os_rename = function() return true end,
        os_remove = function() return true end,
        lfs_symlinkattributes = function() return nil end,
        fs_stat = function() return nil end,
        fs_chown = function() return true end,
        fs_chmod = function() return true end,
    }
    local ok = fsutil.append_unique_line("/etc/new.rules", "first_line", "test", deps)
    assert(ok == true, "Expected creation to succeed")
    local content = table.concat(written)
    assert(content:find("first_line"), "Expected first line written to new file")
end
