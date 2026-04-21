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
