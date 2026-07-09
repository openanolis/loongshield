-- Unit tests for seharden enforcer modules
-- Each enforcer uses _test_set_dependencies for isolation.

local helpers = require('seharden_enforcer_helpers')
local make_fs_attr = helpers.make_fs_attr

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
        io_open = function()
            return nil, 'not needed'
        end,
        io_lines = function()
            local lines = { 'cramfs 16384 0 - Live 0x00000000' }
            local i = 0
            return function()
                i = i + 1
                return lines[i]
            end
        end,
        lfs_dir = function()
            return nil
        end,
    })
    local ok = kmod_enforcer.unload({ name = 'cramfs' })
    assert(ok == true, 'Expected unload to succeed')
    assert(called_with ~= nil, 'Expected os.execute to be called')
    assert(called_with:find('cramfs'), 'Expected command to mention cramfs')
end

function test_kmod_unload_rejects_invalid_name()
    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
        io_open = function()
            return nil
        end,
        io_lines = function()
            return function()
                return nil
            end
        end,
        lfs_dir = function()
            return nil
        end,
    })
    local ok, err = kmod_enforcer.unload({ name = 'bad name!' })
    assert(ok == nil, 'Expected error for invalid name')
    assert(err ~= nil, 'Expected error message')
end

function test_kmod_unload_skips_when_module_already_unloaded()
    local called = false
    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            called = true
            return true, nil, 0
        end,
        io_open = function()
            return nil
        end,
        io_lines = function()
            return function()
                return nil
            end
        end,
        lfs_dir = function()
            return nil
        end,
    })

    local ok = kmod_enforcer.unload({ name = 'cramfs' })
    assert(ok == true, 'Expected already-unloaded module to be treated as success')
    assert(called == false, 'Expected modprobe not to run when the module is already absent')
end

function test_kmod_unload_surfaces_modprobe_failure_for_loaded_module()
    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, 'exit', 1
        end,
        io_open = function()
            return nil
        end,
        io_lines = function()
            local lines = { 'cramfs 16384 0 - Live 0x00000000' }
            local i = 0
            return function()
                i = i + 1
                return lines[i]
            end
        end,
        lfs_dir = function()
            return nil
        end,
    })

    local ok, err = kmod_enforcer.unload({ name = 'cramfs' })
    assert(ok == nil, 'Expected loaded-module unload failures to be surfaced')
    assert(
        err:find("failed to unload 'cramfs'", 1, true),
        'Expected error to include the module name and unload failure'
    )
end

function test_kmod_blacklist_writes_file_when_not_present()
    local written = {}
    local buf = {}

    local fake_file = {
        write = function(_, s)
            table.insert(buf, s)
        end,
        close = function()
            return true
        end,
    }

    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
        io_open = function(path, mode)
            if mode == 'w' then
                written.path = path
                return fake_file
            end
            return nil
        end,
        lfs_dir = function()
            return function()
                return nil
            end
        end, -- empty dir
        io_lines = function()
            return function()
                return nil
            end
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    local ok = kmod_enforcer.blacklist({ name = 'cramfs' })
    assert(ok == true, 'Expected blacklist to succeed')
    assert(written.path ~= nil, 'Expected a file to be written')
    assert(table.concat(buf):find('blacklist cramfs'), 'Expected blacklist line to be written')
end

function test_kmod_blacklist_skips_when_already_present()
    local written = false
    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
        io_open = function()
            written = true
            return nil
        end,
        lfs_dir = function()
            local items = { 'cramfs.conf' }
            local i = 0
            return function()
                i = i + 1
                return items[i]
            end
        end,
        io_lines = function()
            local lines = { 'blacklist cramfs' }
            local i = 0
            return function()
                i = i + 1
                return lines[i]
            end
        end,
    })
    local ok = kmod_enforcer.blacklist({ name = 'cramfs' })
    assert(ok == true, 'Expected skip to return true')
    assert(written == false, 'Expected no file write when already blacklisted')
end

function test_kmod_set_install_command_writes_file()
    local buf = {}
    local fake_file = {
        write = function(_, s)
            table.insert(buf, s)
        end,
        close = function()
            return true
        end,
    }
    kmod_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
        io_open = function(_, mode)
            if mode == 'w' then
                return fake_file
            end
            return nil
        end,
        lfs_dir = function()
            return function()
                return nil
            end
        end,
        io_lines = function()
            return function()
                return nil
            end
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = kmod_enforcer.set_install_command({ name = 'cramfs' })
    assert(ok == true, 'Expected set_install_command to succeed')
    assert(table.concat(buf):find('install cramfs /bin/true'), 'Expected install line to be written')
end

--------------------------------------------------------------------------------
-- sysctl enforcer
--------------------------------------------------------------------------------

local sysctl_enforcer = require('seharden.enforcers.sysctl')

function test_sysctl_set_value_writes_live_and_persists()
    local live_written = nil
    local conf_written = {}

    local function fake_open(path, mode)
        if mode == 'w' and path:find('proc') then
            return {
                write = function(_, s)
                    live_written = s
                end,
                close = function()
                    return true
                end,
            }
        elseif mode == 'r' then
            return nil -- no existing conf
        elseif mode == 'w' then
            return {
                write = function(_, s)
                    table.insert(conf_written, s)
                end,
                close = function()
                    return true
                end,
            }
        end
        return nil
    end

    sysctl_enforcer._test_set_dependencies({
        io_open = fake_open,
        io_lines = function()
            return function()
                return nil
            end
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        sysctl_conf = '/tmp/test-loongshield.conf',
        procfs_root = '/tmp/test-proc-sys',
    })

    local ok = sysctl_enforcer.set_value({ key = 'kernel.randomize_va_space', value = '2' })
    assert(ok == true, 'Expected set_value to succeed')
    assert(#conf_written > 0, 'Expected conf file to be written')
    local conf_content = table.concat(conf_written)
    assert(conf_content:find('kernel.randomize_va_space'), 'Expected key in conf file')
    assert(conf_content:find('2'), 'Expected value in conf file')
end

function test_sysctl_set_value_rejects_invalid_key()
    sysctl_enforcer._test_set_dependencies({
        io_open = function()
            return nil
        end,
        io_lines = function()
            return function()
                return nil
            end
        end,
    })
    local ok, err = sysctl_enforcer.set_value({ key = '../../etc/passwd', value = '1' })
    assert(ok == nil, 'Expected error for path-traversal key')
    assert(err ~= nil, 'Expected error message')
end

function test_sysctl_set_value_requires_both_params()
    sysctl_enforcer._test_set_dependencies({
        io_open = function()
            return nil
        end,
        io_lines = function()
            return function()
                return nil
            end
        end,
    })
    local ok, err = sysctl_enforcer.set_value({ key = 'some.key' })
    assert(ok == nil, 'Expected error when value missing')
    assert(err ~= nil, 'Expected error message')
end

function test_sysctl_set_value_updates_existing_key()
    local conf_written = {}
    local existing_lines = { 'kernel.randomize_va_space = 0', 'net.ipv4.ip_forward = 0' }
    local line_iter_pos = 0

    sysctl_enforcer._test_set_dependencies({
        sysctl_conf = '/tmp/test-loongshield.conf',
        procfs_root = '/tmp/test-proc-sys',
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        io_open = function(_, mode)
            if mode == 'r' then
                line_iter_pos = 0
                return {
                    lines = function()
                        return function()
                            line_iter_pos = line_iter_pos + 1
                            return existing_lines[line_iter_pos]
                        end
                    end,
                    close = function()
                        return true
                    end,
                }
            elseif mode == 'w' then
                return {
                    write = function(_, s)
                        table.insert(conf_written, s)
                    end,
                    close = function()
                        return true
                    end,
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

    local ok = sysctl_enforcer.set_value({ key = 'kernel.randomize_va_space', value = '2' })
    assert(ok == true, 'Expected update to succeed')
    local content = table.concat(conf_written)
    assert(content:find('kernel.randomize_va_space = 2'), 'Expected updated value in conf')
    assert(content:find('net.ipv4.ip_forward'), 'Expected other keys preserved')
end

function test_sysctl_set_value_surfaces_live_write_failure_after_persisting()
    local conf_written = {}

    sysctl_enforcer._test_set_dependencies({
        sysctl_conf = '/tmp/test-loongshield.conf',
        procfs_root = '/tmp/test-proc-sys',
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        io_open = function(path, mode)
            if mode == 'w' and path:find('proc') then
                return nil, 'permission denied'
            elseif mode == 'r' then
                return nil
            elseif mode == 'w' then
                return {
                    write = function(_, s)
                        table.insert(conf_written, s)
                    end,
                    close = function()
                        return true
                    end,
                }
            end
            return nil
        end,
    })

    local ok, err = sysctl_enforcer.set_value({ key = 'kernel.randomize_va_space', value = '2' })
    assert(ok == nil, 'Expected live sysctl write failures to be surfaced')
    assert(err:find('live apply failed', 1, true), 'Expected error to explain that the runtime sysctl write failed')
    assert(
        table.concat(conf_written):find('kernel.randomize_va_space = 2', 1, true),
        'Expected persistent sysctl config to still be written'
    )
end

--------------------------------------------------------------------------------
-- permissions enforcer
--------------------------------------------------------------------------------

local permissions_enforcer = require('seharden.enforcers.permissions')

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
        path = '/etc/shadow',
        uid = 0,
        gid = 0,
        mode = 0,
    })
    assert(ok == true, 'Expected attribute update to succeed')
    assert(chown_called ~= nil, 'Expected chown to be invoked')
    assert(chmod_called ~= nil, 'Expected chmod to be invoked')
end

function test_permissions_set_attributes_rejects_symlink()
    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, 0)
        end,
        fs_chown = function()
            error('fs_chown should not be called for symlink paths')
        end,
        fs_chmod = function()
            error('fs_chmod should not be called for symlink paths')
        end,
        lfs_symlinkattributes = function()
            return { mode = 'link' }
        end,
    })

    local ok, err = permissions_enforcer.set_attributes({
        path = '/etc/shadow',
        uid = 0,
        gid = 0,
        mode = 0,
    })
    assert(ok == nil, 'Expected symlink paths to be rejected')
    assert(err:find('symlink'), 'Expected error to mention symlink refusal')
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
        path = '/etc/shadow',
        uid = 'root',
    })
    assert(ok == nil, 'Expected invalid uid to be rejected')
    assert(err:find('invalid uid', 1, true), 'Expected uid validation error')

    ok, err = permissions_enforcer.set_attributes({
        path = '/etc/shadow',
        gid = -1,
    })
    assert(ok == nil, 'Expected invalid gid to be rejected')
    assert(err:find('invalid gid', 1, true), 'Expected gid validation error')

    assert(chown_called == false, 'Expected chown not to run on invalid input')
    assert(chmod_called == false, 'Expected chmod not to run on invalid input')
end

function test_permissions_set_attributes_for_all_chmods_each_entry()
    local chmod_calls = {}
    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber('644', 8))
        end,
        fs_chmod = function(path, mode)
            chmod_calls[#chmod_calls + 1] = { path = path, mode = mode }
            return true
        end,
        fs_chown = function()
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
    })
    local ok = permissions_enforcer.set_attributes_for_all({
        list = {
            details = {
                { path = '/home/alice/.ssh' },
                { path = '/home/bob/.ssh' },
            },
        },
        mode = tonumber('700', 8),
    })
    assert(ok == true, 'Expected set_attributes_for_all to succeed')
    assert(#chmod_calls == 2, 'Expected chmod called for each entry, got ' .. #chmod_calls)
end

function test_permissions_set_attributes_for_all_skips_compliant()
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber('700', 8))
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        fs_chown = function()
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
    })
    local ok = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = '/home/alice/.ssh' } } },
        mode = tonumber('700', 8),
    })
    assert(ok == true, 'Expected success for already-compliant entries')
    assert(chmod_called == false, 'Expected no chmod when mode already correct')
end

function test_permissions_set_attributes_for_all_requires_list()
    permissions_enforcer._test_set_dependencies({})
    local ok, err = permissions_enforcer.set_attributes_for_all({ mode = tonumber('700', 8) })
    assert(ok == nil, 'Expected error when list is missing')
    assert(err ~= nil, 'Expected error message')
end

function test_permissions_set_attributes_for_all_requires_mode()
    permissions_enforcer._test_set_dependencies({})
    local ok, err = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = '/tmp/test' } } },
    })
    assert(ok == nil, 'Expected error when mode is missing')
    assert(err ~= nil, 'Expected error message')
end

function test_permissions_set_attributes_for_all_rejects_invalid_uid_and_gid()
    local chown_called = false
    local chmod_called = false

    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(1000, 1000, tonumber('644', 8))
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

    local ok, err = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = '/tmp/test' } } },
        mode = tonumber('700', 8),
        uid = 'root',
    })
    assert(ok == nil, 'Expected invalid uid to be rejected')
    assert(err:find('invalid uid', 1, true), 'Expected uid validation error')

    ok, err = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = '/tmp/test' } } },
        mode = tonumber('700', 8),
        gid = -1,
    })
    assert(ok == nil, 'Expected invalid gid to be rejected')
    assert(err:find('invalid gid', 1, true), 'Expected gid validation error')

    assert(chown_called == false, 'Expected chown not to run on invalid input')
    assert(chmod_called == false, 'Expected chmod not to run on invalid input')
end

function test_permissions_set_attributes_for_all_skips_symlinks()
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber('644', 8))
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        fs_chown = function()
            return true
        end,
        lfs_symlinkattributes = function()
            return { mode = 'link' }
        end,
    })
    local ok = permissions_enforcer.set_attributes_for_all({
        list = { details = { { path = '/tmp/link' } } },
        mode = tonumber('700', 8),
    })
    assert(ok == true, 'Expected success when symlink is skipped')
    assert(chmod_called == false, 'Expected no chmod on symlink')
end

function test_permissions_fix_bootloader_config_fixes_permissions()
    local chown_called = false
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if path == '/boot' then
                return { mode = 'directory' }
            end
            if path == '/boot/grub.cfg' then
                return { mode = 'file' }
            end
            return nil
        end,
        lfs_dir = function(path)
            if path == '/boot' then
                local items = { 'grub.cfg' }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return make_fs_attr(1000, 1000, tonumber('644', 8))
        end,
        fs_chown = function()
            chown_called = true
            return true
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
    })
    local ok = permissions_enforcer.fix_bootloader_config({ base_path = '/boot' })
    assert(ok == true, 'Expected fix_bootloader_config to succeed')
    assert(chown_called, 'Expected chown to be called for non-root-owned file')
    assert(chmod_called, 'Expected chmod to be called for wrong-mode file')
end

function test_permissions_fix_bootloader_config_idempotent()
    local chown_called = false
    local chmod_called = false
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if path == '/boot' then
                return { mode = 'directory' }
            end
            if path == '/boot/grub.cfg' then
                return { mode = 'file' }
            end
            return nil
        end,
        lfs_dir = function()
            local items = { 'grub.cfg' }
            local i = 0
            return function()
                i = i + 1
                return items[i]
            end
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber('600', 8))
        end,
        fs_chown = function()
            chown_called = true
            return true
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
    })
    local ok = permissions_enforcer.fix_bootloader_config({ base_path = '/boot' })
    assert(ok == true, 'Expected idempotent skip to succeed')
    assert(chown_called == false, 'Expected no chown when already root-owned')
    assert(chmod_called == false, 'Expected no chmod when mode already 0600')
end

function test_permissions_fix_bootloader_config_returns_true_when_no_files()
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if path == '/boot' then
                return { mode = 'directory' }
            end
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
    local ok = permissions_enforcer.fix_bootloader_config({ base_path = '/boot' })
    assert(ok == true, 'Expected success when no config files found')
end

function test_permissions_fix_sshd_config_access_fixes_permissions()
    local chown_called = false
    local chmod_called = false
    local fake_files = {
        ['/etc/ssh/sshd_config'] = true,
    }
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function(path)
            if fake_files[path] then
                return { mode = 'file' }
            end
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
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return make_fs_attr(1000, 1000, tonumber('644', 8))
        end,
        fs_chown = function()
            chown_called = true
            return true
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        io_open = function(path)
            if path == '/etc/ssh/sshd_config' then
                return {
                    lines = function()
                        return function()
                            return nil
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = permissions_enforcer.fix_sshd_config_access({
        path = '/etc/ssh/sshd_config',
        include_dir = '/nonexistent',
    })
    assert(ok == true, 'Expected fix_sshd_config_access to succeed')
    assert(chown_called, 'Expected chown for non-root-owned sshd config')
    assert(chmod_called, 'Expected chmod for wrong-mode sshd config')
end

function test_permissions_fix_sshd_config_access_returns_true_when_no_files()
    permissions_enforcer._test_set_dependencies({
        lfs_attributes = function()
            return nil
        end,
        lfs_dir = function()
            return nil
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        io_open = function()
            return nil
        end,
    })
    local ok = permissions_enforcer.fix_sshd_config_access({
        path = '/nonexistent/sshd_config',
        include_dir = '/nonexistent',
    })
    assert(ok == true, 'Expected success when no config files found')
end

--------------------------------------------------------------------------------
-- file enforcer
--------------------------------------------------------------------------------

local file_enforcer = require('seharden.enforcers.file')

function test_file_append_line_adds_new_line()
    local written = {}
    local fake_file = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
            end
            return fake_file
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = file_enforcer.append_line({ path = '/etc/test.conf', line = 'TESTKEY=1' })
    assert(ok == true, 'Expected append to succeed')
    assert(table.concat(written):find('TESTKEY=1'), 'Expected line to be written')
end

function test_file_append_line_idempotent()
    local written = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { 'TESTKEY=1' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
            if mode == 'r' then
                local lines = { 'TESTKEY=1' }
                local i = 0
                -- simulate file:lines() by returning nil
                return {
                    lines = function(self)
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
    local ok = file_enforcer.append_line({ path = '/etc/test.conf', line = 'TESTKEY=1' })
    assert(ok == true, 'Expected idempotent append to return true')
    assert(written == false, 'Expected no write when line already present')
end

function test_file_remove_line_matching_removes_lines()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { 'keep this', 'remove me', 'keep this too' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
    local ok = file_enforcer.remove_line_matching({ path = '/etc/test.conf', pattern = 'remove' })
    assert(ok == true, 'Expected removal to succeed')
    local content = table.concat(written)
    assert(not content:find('remove me'), 'Expected matching line removed')
    assert(content:find('keep this'), 'Expected non-matching lines preserved')
end

function test_file_set_key_value_appends_new_key()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
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
    local ok = file_enforcer.set_key_value({ path = '/etc/test.conf', key = 'MaxAuthTries', value = '4' })
    assert(ok == true, 'Expected set to succeed')
    local content = table.concat(written)
    assert(content:find('MaxAuthTries=4'), 'Expected key=value line appended')
end

function test_file_set_key_value_replaces_duplicate_keys_with_single_line()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = {
                    'MaxAuthTries=1',
                    'OtherKey=yes',
                    'MaxAuthTries=2',
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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

    local ok = file_enforcer.set_key_value({ path = '/etc/test.conf', key = 'MaxAuthTries', value = '4' })
    assert(ok == true, 'Expected duplicate key update to succeed')

    local content = table.concat(written)
    local _, count = content:gsub('MaxAuthTries=4', '')
    assert(count == 1, 'Expected duplicate keys to collapse into one line')
    assert(content:find('OtherKey=yes'), 'Expected unrelated keys to be preserved')
end

function test_file_set_key_value_rewrites_duplicate_identical_keys()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = {
                    'MaxAuthTries=4',
                    'MaxAuthTries=4',
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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

    local ok = file_enforcer.set_key_value({ path = '/etc/test.conf', key = 'MaxAuthTries', value = '4' })
    assert(ok == true, 'Expected duplicate identical key update to succeed')

    local content = table.concat(written)
    local _, count = content:gsub('MaxAuthTries=4', '')
    assert(count == 1, 'Expected duplicate identical keys to be normalized')
end

function test_file_set_key_value_supports_whitespace_separators()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = {
                    'MAIL_DIR /var/spool/mail',
                    'UMASK    022',
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
        path = '/etc/login.defs',
        key = 'UMASK',
        value = '027',
        separator = ' ',
    })
    assert(ok == true, 'Expected whitespace-separated key update to succeed')

    local content = table.concat(written)
    assert(content:find('MAIL_DIR /var/spool/mail', 1, true), 'Expected unrelated login.defs settings to be preserved')
    assert(
        content:find('UMASK 027', 1, true),
        'Expected whitespace-separated key to be rewritten with the requested value'
    )
end

function test_file_test_dependencies_reset_symlink_override()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
            end
            return fake_out
        end,
        lfs_symlinkattributes = function()
            return { mode = 'link' }
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })

    local ok, err = file_enforcer.append_line({ path = '/etc/test.conf', line = 'TESTKEY=1' })
    assert(ok == nil, 'Expected symlink override to block writes')
    assert(err:find('symlink'), 'Expected symlink error')

    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
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

    ok, err = file_enforcer.append_line({ path = '/etc/test.conf', line = 'TESTKEY=1' })
    assert(ok == true, 'Expected dependency reset to restore default symlink handling')
end

function test_file_write_content_writes_new_file()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
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
    local ok = file_enforcer.write_content({ path = '/etc/test.conf', content = 'line1\nline2\nline3' })
    assert(ok == true, 'Expected write_content to succeed')
    local content = table.concat(written)
    assert(content:find('line1'), 'Expected line1 in output')
    assert(content:find('line2'), 'Expected line2 in output')
    assert(content:find('line3'), 'Expected line3 in output')
end

function test_file_write_content_idempotent_when_content_matches()
    local write_called = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { 'line1', 'line2' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
                }
            end
            write_called = true
            return { write = function() end, close = function() end }
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = file_enforcer.write_content({ path = '/etc/test.conf', content = 'line1\nline2' })
    assert(ok == true, 'Expected idempotent skip to return true')
    assert(write_called == false, 'Expected no write when content already matches')
end

function test_file_write_content_rejects_missing_params()
    file_enforcer._test_set_dependencies({})
    local ok, err = file_enforcer.write_content({ path = '/etc/test.conf' })
    assert(ok == nil, 'Expected error when content is nil')
    assert(err ~= nil, 'Expected error message')

    ok, err = file_enforcer.write_content(nil)
    assert(ok == nil, 'Expected error when params is nil')
end

function test_file_write_content_rejects_symlink()
    file_enforcer._test_set_dependencies({
        lfs_symlinkattributes = function()
            return { mode = 'link' }
        end,
    })
    local ok, err = file_enforcer.write_content({ path = '/etc/link', content = 'data' })
    assert(ok == nil, 'Expected symlink rejection')
    assert(err:find('symlink'), 'Expected symlink error message')
end

function test_file_set_ini_key_value_updates_existing_key_in_section()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines =
                    { '[daemon]', 'log_level=info', 'log_file=/var/log/test.log', '', '[security]', 'enabled=true' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
    local ok = file_enforcer.set_ini_key_value({
        path = '/etc/test.ini',
        section = 'daemon',
        key = 'log_level',
        value = 'debug',
    })
    assert(ok == true, 'Expected set_ini_key_value to succeed')
    local content = table.concat(written, '\n')
    assert(content:find('log_level=debug'), 'Expected key value to be updated')
    assert(content:find('%[security%]'), 'Expected other sections preserved')
end

function test_file_set_ini_key_value_appends_key_to_existing_section()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { '[daemon]', 'log_level=info', '', '[security]', 'enabled=true' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
    local ok = file_enforcer.set_ini_key_value({
        path = '/etc/test.ini',
        section = 'daemon',
        key = 'max_workers',
        value = '4',
    })
    assert(ok == true, 'Expected set_ini_key_value to succeed')
    local content = table.concat(written, '\n')
    assert(content:find('max_workers=4'), 'Expected new key to be appended to section')
end

function test_file_set_ini_key_value_creates_section_if_missing()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { '[existing]', 'key=val' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
    local ok =
        file_enforcer.set_ini_key_value({ path = '/etc/test.ini', section = 'new_section', key = 'key', value = 'val' })
    assert(ok == true, 'Expected set_ini_key_value to succeed')
    local content = table.concat(written, '\n')
    assert(content:find('%[new_section%]'), 'Expected new section header')
    assert(content:find('key=val'), 'Expected key=value in new section')
end

function test_file_set_ini_key_value_idempotent()
    local write_called = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { '[daemon]', 'log_level=info' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
                }
            end
            write_called = true
            return { write = function() end, close = function() end }
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = file_enforcer.set_ini_key_value({
        path = '/etc/test.ini',
        section = 'daemon',
        key = 'log_level',
        value = 'info',
    })
    assert(ok == true, 'Expected idempotent skip to return true')
    assert(write_called == false, 'Expected no write when value already correct')
end

function test_file_set_ini_key_value_rejects_missing_params()
    file_enforcer._test_set_dependencies({})
    local ok, err = file_enforcer.set_ini_key_value({ path = '/etc/test.ini', section = 'daemon', key = 'k' })
    assert(ok == nil, 'Expected error when value is nil')
    assert(err ~= nil, 'Expected error message')
end

function test_file_comment_line_matching_comments_matching_lines()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { 'allow_tcp_forwarding yes', 'PermitRootLogin yes', '# already commented' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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
    local ok = file_enforcer.comment_line_matching({ path = '/etc/ssh/sshd_config', pattern = 'PermitRootLogin' })
    assert(ok == true, 'Expected comment_line_matching to succeed')
    local content = table.concat(written, '\n')
    assert(content:find('# PermitRootLogin yes'), 'Expected matching line to be commented')
    assert(content:find('allow_tcp_forwarding yes'), 'Expected non-matching line to be preserved')
    assert(content:find('# already commented'), 'Expected already-commented line to be preserved as-is')
end

function test_file_comment_line_matching_idempotent_when_all_commented()
    local write_called = false
    file_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { '# PermitRootLogin yes' }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
                }
            end
            write_called = true
            return { write = function() end, close = function() end }
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = file_enforcer.comment_line_matching({ path = '/etc/test.conf', pattern = 'PermitRootLogin' })
    assert(ok == true, 'Expected idempotent skip to return true')
    assert(write_called == false, 'Expected no write when all lines already commented')
end

function test_file_comment_line_matching_returns_true_for_missing_file()
    file_enforcer._test_set_dependencies({
        io_open = function()
            return nil
        end,
    })
    local ok = file_enforcer.comment_line_matching({ path = '/nonexistent', pattern = 'anything' })
    assert(ok == true, "Expected true when file doesn't exist")
end

function test_file_comment_line_matching_rejects_missing_params()
    file_enforcer._test_set_dependencies({})
    local ok, err = file_enforcer.comment_line_matching({ path = '/etc/test.conf' })
    assert(ok == nil, 'Expected error when pattern is missing')
    assert(err ~= nil, 'Expected error message')
end

--------------------------------------------------------------------------------
-- mounts enforcer
--------------------------------------------------------------------------------

local mounts_enforcer = require('seharden.enforcers.mounts')

local function mount_remount_with_fstab_line(line, add_options)
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }

    mounts_enforcer._test_set_dependencies({
        os_execute = function()
            return true, 'exit', 0
        end,
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { line }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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

    local ok, err = mounts_enforcer.remount({ path = '/dev/shm', add_options = add_options })
    return ok, err, table.concat(written)
end

function test_mounts_remount_returns_error_when_live_remount_fails()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }

    mounts_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, 'exit', 32
        end,
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = {
                    'tmpfs /dev/shm tmpfs defaults 0 0',
                }
                local i = 0
                return {
                    lines = function()
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function()
                        return true
                    end,
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

    local ok, err = mounts_enforcer.remount({ path = '/dev/shm', add_options = { 'noexec' } })
    assert(ok == nil, 'Expected live remount failure to be surfaced')
    assert(err:find('live remount failed', 1, true), 'Expected error to explain that runtime remount did not succeed')
    assert(
        table.concat(written):find('defaults,noexec', 1, true),
        'Expected fstab update to still persist the requested option'
    )
end

function test_mounts_remount_appends_missing_options_without_duplicates()
    local ok, err, content =
        mount_remount_with_fstab_line('tmpfs /dev/shm tmpfs defaults,noexec 0 0', { 'noexec', 'nodev' })

    assert(ok == true, 'Expected remount to succeed, got: ' .. tostring(err))
    assert(content:find('defaults,noexec,nodev', 1, true), 'Expected missing option to be appended once')
    assert(not content:find('defaults,noexec,noexec', 1, true), 'Expected existing option not to be duplicated')
end

function test_mounts_remount_rejects_invalid_option_tokens()
    local ok, err = mounts_enforcer.remount({
        path = '/dev/shm',
        add_options = { 'noexec,nosuid' },
    })

    assert(ok == nil, 'Expected invalid mount option token to be rejected')
    assert(err:find('add_options%[1%]'), 'Expected error to identify the bad option index')
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
                read = function()
                    return ''
                end,
                close = function()
                    return true
                end,
            }
        end,
    })
    local ok = services_enforcer.set_filestate({ name = 'sshd.service', state = 'disable' })
    assert(ok == true, 'Expected set_filestate to succeed')
    assert(cmd_run ~= nil, 'Expected systemctl to be called')
    assert(cmd_run:find('disable') and cmd_run:find('sshd'), 'Expected correct systemctl command')
end

function test_services_set_filestate_uses_resolved_systemctl_path()
    local cmd_run = nil
    services_enforcer._test_set_dependencies({
        io_popen = function(cmd)
            cmd_run = cmd
            return {
                read = function()
                    return ''
                end,
                close = function()
                    return true
                end,
            }
        end,
        lfs_attributes = function(path)
            if path == '/usr/bin/systemctl' then
                return { mode = 'file' }
            end
            return nil
        end,
    })

    local ok = services_enforcer.set_filestate({ name = 'sshd.service', state = 'disable' })

    assert(ok == true, 'Expected set_filestate to succeed with resolved systemctl path')
    assert(
        cmd_run:match('^/usr/bin/systemctl disable sshd%.service 2>&1$'),
        'Expected systemctl command to use the resolved absolute path'
    )
end

function test_services_set_filestate_rejects_invalid_unit()
    services_enforcer._test_set_dependencies({
        io_popen = function()
            return nil
        end,
    })
    local ok, err = services_enforcer.set_filestate({ name = 'bad;name', state = 'disable' })
    assert(ok == nil, 'Expected error for invalid unit name')
    assert(err ~= nil, 'Expected error message')
end

function test_services_set_filestate_rejects_invalid_state()
    services_enforcer._test_set_dependencies({
        io_popen = function()
            return nil
        end,
    })
    local ok, err = services_enforcer.set_filestate({ name = 'sshd.service', state = 'explode' })
    assert(ok == nil, 'Expected error for invalid state')
    assert(err ~= nil, 'Expected error message')
end

function test_services_set_active_state_calls_systemctl()
    local cmd_run = nil
    services_enforcer._test_set_dependencies({
        io_popen = function(cmd)
            cmd_run = cmd
            return {
                read = function()
                    return ''
                end,
                close = function()
                    return true
                end,
            }
        end,
    })
    local ok = services_enforcer.set_active_state({ name = 'sshd.service', state = 'stop' })
    assert(ok == true, 'Expected set_active_state to succeed')
    assert(cmd_run:find('stop') and cmd_run:find('sshd'), 'Expected correct systemctl stop command')
end

function test_services_set_active_state_rejects_filestate_operations()
    services_enforcer._test_set_dependencies({
        io_popen = function()
            error('systemctl should not run for invalid active state')
        end,
    })

    local ok, err = services_enforcer.set_active_state({ name = 'sshd.service', state = 'mask' })

    assert(ok == nil, 'Expected file-state operations to be rejected by active-state enforcer')
    assert(err:find('use set_filestate', 1, true), 'Expected active-state error to point to set_filestate')
end

function test_services_set_filestate_reports_systemctl_failures()
    services_enforcer._test_set_dependencies({
        io_popen = function()
            return {
                read = function()
                    return 'Unit demo.service not found.\n'
                end,
                close = function()
                    return nil, 'exit', 1
                end,
            }
        end,
    })

    local ok, err = services_enforcer.set_filestate({ name = 'demo.service', state = 'disable' })
    assert(ok == nil, 'Expected service enforcer to report systemctl failure')
    assert(err:find('not found'), 'Expected stderr/stdout from failed systemctl to be surfaced')
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
    local ok = packages_enforcer.install({ name = 'aide' })
    assert(ok == true, 'Expected install to succeed')
    assert(cmd_run:find('dnf install') and cmd_run:find('aide'), 'Expected dnf install command')
end

function test_packages_install_rejects_wildcard()
    packages_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
    })
    local ok, err = packages_enforcer.install({ name = 'aide*' })
    assert(ok == nil, 'Expected error for wildcard package name')
    assert(err ~= nil, 'Expected error message')
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
                        return 'telnet'
                    end
                end,
                close = function()
                    return true, nil, 0
                end,
            }
        end,
    })
    local ok = packages_enforcer.remove({ name = 'telnet' })
    assert(ok == true, 'Expected remove to succeed')
    assert(cmd_run:find('dnf remove') and cmd_run:find('telnet'), 'Expected dnf remove command')
end

function test_packages_remove_matching_calls_dnf_with_sorted_matches()
    local cmd_run = nil
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_popen = function(cmd)
            assert(cmd:find('rpm %-qa', 1) ~= nil, 'Expected remove_matching to inspect installed packages')
            local packages = { 'bluez-libs', 'telnet-server', 'bluez' }
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return packages[i]
                    end
                end,
                close = function()
                    return true, nil, 0
                end,
            }
        end,
    })

    local ok = packages_enforcer.remove_matching({ pattern = 'bluez*' })
    assert(ok == true, 'Expected remove_matching to succeed')
    assert(cmd_run ~= nil, 'Expected dnf remove command to be issued')
    assert(
        cmd_run:find('dnf remove %-y bluez bluez%-libs', 1) ~= nil,
        'Expected matched packages to be removed in deterministic order'
    )
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
                    return function()
                        return nil
                    end
                end,
                close = function()
                    return true, nil, 0
                end,
            }
        end,
    })

    local ok = packages_enforcer.remove_matching({ pattern = 'wdaemon*' })
    assert(ok == true, 'Expected remove_matching to no-op when nothing matches')
    assert(cmd_run == nil, 'Expected dnf not to run when no packages match the pattern')
end

function test_packages_remove_matching_rejects_unsafe_pattern()
    packages_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
        io_popen = function()
            return nil
        end,
    })

    local ok, err = packages_enforcer.remove_matching({ pattern = 'bluez*;rm' })
    assert(ok == nil, 'Expected unsafe glob pattern to be rejected')
    assert(err ~= nil, 'Expected error message for unsafe glob pattern')
end

function test_packages_remove_matching_rejects_malformed_glob_without_querying_rpm()
    local popen_called = false
    packages_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
        io_popen = function()
            popen_called = true
            return nil
        end,
    })

    local ok, err = packages_enforcer.remove_matching({ pattern = '[]' })
    assert(ok == nil, 'Expected malformed glob pattern to be rejected')
    assert(err ~= nil, 'Expected error message for malformed glob pattern')
    assert(popen_called == false, 'Expected malformed glob validation to fail before querying installed packages')
end

function test_packages_update_calls_dnf_update()
    local cmds = {}
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            return true, nil, 0
        end,
    })
    local ok = packages_enforcer.update({ name = 'aide' })
    assert(ok == true, 'Expected update to succeed')
    assert(cmds[1]:find('dnf update') and cmds[1]:find('aide'), 'Expected dnf update command')
end

function test_packages_update_falls_back_to_install_when_not_installed()
    local cmds = {}
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            if cmd:find('dnf update') then
                return true, nil, 0
            end
            if cmd:find('rpm %-q') then
                return nil, 'not installed', 1
            end
            if cmd:find('dnf install') then
                return true, nil, 0
            end
            return true, nil, 0
        end,
    })
    local ok = packages_enforcer.update({ name = 'aide' })
    assert(ok == true, 'Expected fallback install to succeed')
    local found_install = false
    for _, cmd in ipairs(cmds) do
        if cmd:find('dnf install') and cmd:find('aide') then
            found_install = true
        end
    end
    assert(found_install, 'Expected dnf install fallback when package not installed')
end

function test_packages_update_rejects_wildcard()
    packages_enforcer._test_set_dependencies({
        os_execute = function()
            return true
        end,
    })
    local ok, err = packages_enforcer.update({ name = 'aide*' })
    assert(ok == nil, 'Expected error for wildcard package name')
    assert(err ~= nil, 'Expected error message')
end

function test_packages_update_requires_name()
    packages_enforcer._test_set_dependencies({})
    local ok, err = packages_enforcer.update({})
    assert(ok == nil, 'Expected error when name is missing')
    assert(err ~= nil, 'Expected error message')
end

function test_packages_update_propagates_dnf_update_failure()
    packages_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            if cmd:find('dnf update') then
                return nil, 'dnf update failed', 1
            end
            if cmd:find('rpm %-q') then
                return true, nil, 0
            end
            return true, nil, 0
        end,
    })
    local ok, err = packages_enforcer.update({ name = 'aide' })
    assert(ok == nil, 'Expected error when dnf update fails')
    assert(err ~= nil, 'Expected error message')
end

--------------------------------------------------------------------------------
-- audit / pam / sudo enforcers
