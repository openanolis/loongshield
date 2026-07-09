--------------------------------------------------------------------------------
-- crypto_policy enforcer
--------------------------------------------------------------------------------

local helpers = require('seharden_enforcer_helpers')
local make_fs_attr = helpers.make_fs_attr

local crypto_policy_enforcer = require('seharden.enforcers.crypto_policy')
local sudo_enforcer = require('seharden.enforcers.sudo')

function test_crypto_policy_set_policy_calls_update_crypto_policies()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function()
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({ policy = 'DEFAULT' })
    assert(ok == true, 'Expected set_policy to succeed')
    assert(cmd_run:find('update%-crypto%-policies'), 'Expected update-crypto-policies command')
    assert(cmd_run:find('DEFAULT'), 'Expected policy name in command')
end

function test_crypto_policy_set_policy_writes_module_file()
    local written = {}
    local written_content = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function()
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == 'r' then
                return nil
            end
            if mode == 'w' then
                written[#written + 1] = path
                return {
                    write = function(_, s)
                        written_content = s
                    end,
                    close = function()
                        return true
                    end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT',
        modules = { { name = 'NO-SHA1', content = 'hash = SHA256\nsign = RSA-SHA256' } },
    })
    assert(ok == true, 'Expected set_policy with modules to succeed')
    assert(#written > 0, 'Expected module file to be written')
    assert(written[1]:find('NO%-SHA1%.pmod'), 'Expected .pmod filename')
    assert(written_content:find('SHA256'), 'Expected module content to be written')
end

function test_crypto_policy_set_policy_idempotent_module()
    local write_called = false
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function()
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == 'r' then
                return {
                    read = function()
                        return 'hash = SHA256\nsign = RSA-SHA256'
                    end,
                    close = function() end,
                }
            end
            write_called = true
            return {
                write = function() end,
                close = function()
                    return true
                end,
            }
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT',
        modules = { { name = 'NO-SHA1', content = 'hash = SHA256\nsign = RSA-SHA256' } },
    })
    assert(ok == true, 'Expected idempotent skip to succeed')
    assert(write_called == false, 'Expected no write when module content already matches')
end

function test_crypto_policy_set_policy_returns_error_when_module_write_open_fails()
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function()
            error('update-crypto-policies should not run after module write failure')
        end,
        io_open = function(path, mode)
            if mode == 'r' then
                return nil
            end
            if mode == 'w' then
                assert(path:find('NO%-SHA1%.pmod'), 'Expected module file path to be opened for writing')
                return nil
            end
            return nil
        end,
    })

    local ok, err = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT',
        modules = { { name = 'NO-SHA1', content = 'hash = SHA256' } },
    })

    assert(ok == nil, 'Expected module write open failure to abort set_policy')
    assert(err:find('cannot write', 1, true), 'Expected cannot write error')
end

function test_crypto_policy_set_policy_returns_error_when_module_close_fails()
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function()
            error('update-crypto-policies should not run after module close failure')
        end,
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
            end
            if mode == 'w' then
                return {
                    write = function() end,
                    close = function()
                        return nil
                    end,
                }
            end
            return nil
        end,
    })

    local ok, err = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT',
        modules = { { name = 'NO-SHA1', content = 'hash = SHA256' } },
    })

    assert(ok == nil, 'Expected module close failure to abort set_policy')
    assert(err:find('cannot close', 1, true), 'Expected cannot close error')
end

function test_crypto_policy_set_policy_rejects_missing_policy()
    crypto_policy_enforcer._test_set_dependencies({})
    local ok, err = crypto_policy_enforcer.set_policy({})
    assert(ok == nil, 'Expected error when policy is missing')
    assert(err ~= nil, 'Expected error message')
end

function test_crypto_policy_set_policy_rejects_invalid_characters()
    crypto_policy_enforcer._test_set_dependencies({})
    local ok, err = crypto_policy_enforcer.set_policy({ policy = 'DEFAULT; rm -rf /' })
    assert(ok == nil, 'Expected error for policy with shell metacharacters')
    assert(err ~= nil, 'Expected error message')
end

function test_crypto_policy_set_policy_rejects_invalid_module_content()
    crypto_policy_enforcer._test_set_dependencies({
        io_open = function()
            return nil
        end,
    })
    local ok, err = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT',
        modules = { { name = 'MOD', content = 'hash = SHA256; evil' } },
    })
    assert(ok == nil, 'Expected error for module content with shell metacharacters')
    assert(err ~= nil, 'Expected error message')
end

function test_crypto_policy_set_policy_preserves_current_base_policy()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == 'r' and path:find('config') then
                return {
                    read = function()
                        return 'FIPS'
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT:NO-SHA1',
        current_policy_path = '/etc/crypto-policies/config',
    })
    assert(ok == true, 'Expected set_policy to succeed')
    assert(
        cmd_run:find('FIPS:NO%-SHA1'),
        'Expected FIPS base preserved with NO-SHA1 appended, got: ' .. tostring(cmd_run)
    )
end

function test_crypto_policy_set_policy_allows_base_policy_switch()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == 'r' and path:find('config') then
                return {
                    read = function()
                        return 'LEGACY'
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT',
        current_policy_path = '/etc/crypto-policies/config',
    })
    assert(ok == true, 'Expected set_policy to succeed')
    assert(cmd_run:find('update%-crypto%-policies'), 'Expected update-crypto-policies command')
    assert(cmd_run:find('DEFAULT%s'), 'Expected requested base policy to be used as-is, got: ' .. tostring(cmd_run))
    assert(
        not cmd_run:find('LEGACY'),
        'Expected LEGACY base not to be preserved for bare base policy switch, got: ' .. tostring(cmd_run)
    )
end

function test_crypto_policy_set_policy_switches_legacy_base_for_default_subpolicy_requests()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == 'r' and path:find('config') then
                return {
                    read = function()
                        return 'LEGACY:NO-WEAK-MACS'
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT:NO-SHA1',
        current_policy_path = '/etc/crypto-policies/config',
    })
    assert(ok == true, 'Expected set_policy to succeed')
    assert(
        cmd_run:find('DEFAULT:NO%-WEAK%-MACS:NO%-SHA1'),
        'Expected LEGACY hosts to switch to DEFAULT while preserving existing subpolicies, got: ' .. tostring(cmd_run)
    )
    assert(
        not cmd_run:find('LEGACY'),
        'Expected LEGACY base not to be preserved for DEFAULT subpolicy requests, got: ' .. tostring(cmd_run)
    )
end

function test_crypto_policy_set_policy_deduplicates_subpolicies()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == 'r' and path:find('config') then
                return {
                    read = function()
                        return 'DEFAULT:NO-SHA1'
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT:NO-SHA1',
        current_policy_path = '/etc/crypto-policies/config',
    })
    assert(ok == true, 'Expected set_policy to succeed')
    assert(cmd_run:find('DEFAULT:NO%-SHA1%s'), 'Expected no duplicate NO-SHA1, got: ' .. tostring(cmd_run))
    assert(not cmd_run:find('NO%-SHA1:NO%-SHA1'), 'Expected no duplicate subpolicies, got: ' .. tostring(cmd_run))
end

function test_crypto_policy_set_policy_merges_multiple_subpolicies()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function(path, mode)
            if mode == 'r' and path:find('config') then
                return {
                    read = function()
                        return 'DEFAULT:NO-SHA1'
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({
        policy = 'DEFAULT:NO-WEAK-MACS',
        current_policy_path = '/etc/crypto-policies/config',
    })
    assert(ok == true, 'Expected set_policy to succeed')
    assert(
        cmd_run:find('DEFAULT:NO%-SHA1:NO%-WEAK%-MACS'),
        'Expected both subpolicies present, got: ' .. tostring(cmd_run)
    )
end

function test_crypto_policy_set_policy_falls_back_when_config_unreadable()
    local cmd_run = nil
    crypto_policy_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmd_run = cmd
            return true, nil, 0
        end,
        io_open = function()
            return nil
        end,
    })
    local ok = crypto_policy_enforcer.set_policy({ policy = 'DEFAULT:NO-SHA1' })
    assert(ok == true, 'Expected set_policy to succeed')
    assert(cmd_run:find('DEFAULT:NO%-SHA1'), 'Expected requested policy used as-is, got: ' .. tostring(cmd_run))
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
            {
                path = '/var/log/secure',
                exists = true,
                configured = false,
                mode_ok = false,
                expected_mode = tonumber('600', 8),
                owner_ok = true,
                group_ok = true,
            },
        },
    })
    assert(ok == true, 'Expected fix_logfile_access to succeed')
    local found_chmod = false
    for _, cmd in ipairs(cmds) do
        if cmd:find('chmod') and cmd:find('0600') then
            found_chmod = true
        end
    end
    assert(found_chmod, 'Expected chmod command with correct mode')
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
            {
                path = '/var/log/messages',
                exists = true,
                configured = false,
                mode_ok = true,
                owner_ok = false,
                group_ok = true,
                allowed_owners = { 'root' },
                allowed_groups = { 'root' },
            },
        },
    })
    assert(ok == true, 'Expected fix_logfile_access to succeed')
    local found_chown = false
    for _, cmd in ipairs(cmds) do
        if cmd:find('chown') and cmd:find('root:root') then
            found_chown = true
        end
    end
    assert(found_chown, 'Expected chown command with correct owner')
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
            { path = '/var/log/secure', exists = true, configured = true },
        },
    })
    assert(ok == true, 'Expected success when all entries are already configured')
    assert(cmd_called == false, 'Expected no os_execute calls for configured entries')
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
            { path = '/var/log/nonexistent', exists = false, configured = false },
        },
    })
    assert(ok == true, "Expected success when files don't exist")
    assert(cmd_called == false, 'Expected no os_execute calls for missing files')
end

function test_logging_fix_logfile_access_requires_details()
    logging_enforcer._test_set_dependencies({})
    local ok, err = logging_enforcer.fix_logfile_access({})
    assert(ok == nil, 'Expected error when details is missing')
    assert(err ~= nil, 'Expected error message')
end

function test_logging_fix_logfile_access_propagates_chmod_failure()
    logging_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, 'failed', 1
        end,
    })
    local ok, err = logging_enforcer.fix_logfile_access({
        details = {
            {
                path = '/var/log/secure',
                exists = true,
                configured = false,
                mode_ok = false,
                expected_mode = tonumber('600', 8),
                owner_ok = true,
                group_ok = true,
            },
        },
    })
    assert(ok == nil, 'Expected error when chmod fails')
    assert(err ~= nil, 'Expected error message')
end

--------------------------------------------------------------------------------
-- ssh enforcer
--------------------------------------------------------------------------------

local ssh_enforcer = require('seharden.enforcers.ssh')

function test_ssh_remove_disallowed_algorithms_removes_algos()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    ssh_enforcer._test_set_dependencies({
        io_open = function(path, mode)
            if path == '/usr/sbin/sshd' and mode == 'r' then
                return { close = function() end }
            end
            if path == '/proc/sys/kernel/hostname' and mode == 'r' then
                return {
                    read = function()
                        return 'testhost'
                    end,
                    close = function() end,
                }
            end
            if path == '/etc/hosts' and mode == 'r' then
                return {
                    lines = function()
                        local lines = { '127.0.0.1 localhost' }
                        local i = 0
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            if mode == 'r' then
                return nil
            end
            return fake_out
        end,
        io_popen = function()
            local lines = { 'ciphers aes128-ctr,aes256-ctr,3des-cbc' }
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function()
                    return true, nil, 0
                end,
            }
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        lfs_attributes = function()
            return nil
        end,
        lfs_dir = function()
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
    local ok = ssh_enforcer.remove_disallowed_algorithms({
        key = 'ciphers',
        conditions = { user = 'root' },
        disallowed_algorithms = { '3des-cbc' },
    })
    assert(ok == true, 'Expected remove_disallowed_algorithms to succeed')
    local content = table.concat(written, '\n')
    assert(content:find('Ciphers'), 'Expected Ciphers directive in output')
    assert(content:find('aes128%-ctr'), 'Expected safe algorithm preserved')
    assert(not content:find('3des%-cbc'), 'Expected disallowed algorithm removed')
end

function test_ssh_remove_disallowed_algorithms_comments_out_conflicting_sshd_config()
    local written_files = {}
    local fake_filesystem = {
        ['/usr/sbin/sshd'] = '',
        ['/proc/sys/kernel/hostname'] = 'testhost',
        ['/etc/hosts'] = '127.0.0.1 localhost',
        ['/etc/ssh/sshd_config'] = 'Include /etc/ssh/sshd_config.d/*.conf\nCiphers 3des-cbc,aes128-ctr,aes256-ctr\nPort 22\n',
        ['/etc/ssh/sshd_config.d/00-cis-hardening.conf'] = nil,
    }
    ssh_enforcer._test_set_dependencies({
        io_open = function(path, mode)
            if mode == 'r' then
                local content = fake_filesystem[path]
                if content == nil then
                    return nil
                end
                local lines = {}
                for line in (content .. '\n'):gmatch('(.-)\n') do
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
                    read = function()
                        return lines[1]
                    end,
                    close = function() end,
                }
            end
            -- write mode
            local buf = {}
            written_files[path] = buf
            return {
                write = function(_, s)
                    table.insert(buf, s)
                end,
                close = function()
                    return true
                end,
            }
        end,
        io_popen = function()
            local lines = { 'ciphers aes128-ctr,aes256-ctr,3des-cbc' }
            local i = 0
            return {
                lines = function()
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function()
                    return true, nil, 0
                end,
            }
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        lfs_attributes = function()
            return nil
        end,
        lfs_dir = function()
            return function()
                return nil
            end
        end,
        os_rename = function(src, dst)
            -- simulate rename by copying buf reference
            written_files[dst] = written_files[src]
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = ssh_enforcer.remove_disallowed_algorithms({
        key = 'ciphers',
        conditions = { user = 'root' },
        disallowed_algorithms = { '3des-cbc' },
        sshd_config_path = '/etc/ssh/sshd_config',
    })
    assert(ok == true, 'Expected remove_disallowed_algorithms to succeed')
    -- Verify sshd_config had the Ciphers line commented out
    local sshd_config_buf = written_files['/etc/ssh/sshd_config']
    assert(sshd_config_buf ~= nil, 'Expected sshd_config to be rewritten')
    local sshd_content = table.concat(sshd_config_buf)
    assert(
        sshd_content:find('# Ciphers'),
        'Expected Ciphers directive to be commented out in sshd_config, got: ' .. sshd_content
    )
    assert(sshd_content:find('Port 22'), 'Expected non-conflicting directives preserved')
end

function test_ssh_remove_disallowed_algorithms_reports_conflicting_config_write_failure()
    ssh_enforcer._test_set_dependencies({
        io_open = function(path, mode)
            if mode == 'r' and path == '/usr/sbin/sshd' then
                return { close = function() end }
            end
            if mode == 'r' and path == '/proc/sys/kernel/hostname' then
                return {
                    read = function()
                        return 'testhost'
                    end,
                    close = function() end,
                }
            end
            if mode == 'r' and path == '/etc/hosts' then
                return {
                    lines = function()
                        local lines = { '127.0.0.1 localhost' }
                        local i = 0
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            if mode == 'r' and path == '/etc/ssh/sshd_config' then
                return {
                    lines = function()
                        local lines = { 'Ciphers 3des-cbc,aes128-ctr' }
                        local i = 0
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            if mode == 'r' then
                return nil
            end
            return {
                write = function() end,
                close = function()
                    return true
                end,
            }
        end,
        io_popen = function()
            return {
                lines = function()
                    local lines = { 'ciphers aes128-ctr,3des-cbc' }
                    local i = 0
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function()
                    return true, nil, 0
                end,
            }
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        lfs_attributes = function()
            return nil
        end,
        lfs_dir = function()
            return function()
                return nil
            end
        end,
        os_rename = function()
            return nil, 'rename failed'
        end,
        os_remove = function()
            return true
        end,
    })
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({
        key = 'ciphers',
        conditions = { user = 'root' },
        disallowed_algorithms = { '3des-cbc' },
        sshd_config_path = '/etc/ssh/sshd_config',
    })
    assert(ok == nil, 'Expected failure when conflicting config cannot be updated')
    assert(err:find('/etc/ssh/sshd_config'), 'Expected sshd_config path in error message')
end

function test_ssh_remove_disallowed_algorithms_reports_conflicting_config_read_failure()
    ssh_enforcer._test_set_dependencies({
        io_open = function(path, mode)
            if mode == 'r' and path == '/usr/sbin/sshd' then
                return { close = function() end }
            end
            if mode == 'r' and path == '/proc/sys/kernel/hostname' then
                return {
                    read = function()
                        return 'testhost'
                    end,
                    close = function() end,
                }
            end
            if mode == 'r' and path == '/etc/hosts' then
                return {
                    lines = function()
                        local lines = { '127.0.0.1 localhost' }
                        local i = 0
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            if mode == 'r' and path == '/etc/ssh/sshd_config' then
                return nil
            end
            if mode == 'r' then
                return nil
            end
            return {
                write = function() end,
                close = function()
                    return true
                end,
            }
        end,
        io_popen = function()
            return {
                lines = function()
                    local lines = { 'ciphers aes128-ctr,3des-cbc' }
                    local i = 0
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function()
                    return true, nil, 0
                end,
            }
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        lfs_attributes = function(path)
            if path == '/etc/ssh/sshd_config' then
                return { mode = 'file' }
            end
            return nil
        end,
        lfs_dir = function()
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
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({
        key = 'ciphers',
        conditions = { user = 'root' },
        disallowed_algorithms = { '3des-cbc' },
        sshd_config_path = '/etc/ssh/sshd_config',
    })
    assert(ok == nil, 'Expected failure when conflicting config cannot be read')
    assert(err:find('/etc/ssh/sshd_config'), 'Expected sshd_config path in error message')
end

function test_ssh_remove_disallowed_algorithms_rejects_missing_params()
    ssh_enforcer._test_set_dependencies({})
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({})
    assert(ok == nil, 'Expected error when params are missing')
    assert(err ~= nil, 'Expected error message')
end

function test_ssh_remove_disallowed_algorithms_rejects_unsupported_key()
    ssh_enforcer._test_set_dependencies({})
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({
        key = 'unsupported',
        conditions = {},
        disallowed_algorithms = {},
    })
    assert(ok == nil, 'Expected error for unsupported key')
    assert(err:find('unsupported'), "Expected 'unsupported' in error message")
end

function test_ssh_remove_disallowed_algorithms_rejects_symlink()
    ssh_enforcer._test_set_dependencies({
        lfs_symlinkattributes = function()
            return { mode = 'link' }
        end,
    })
    local ok, err = ssh_enforcer.remove_disallowed_algorithms({
        key = 'ciphers',
        conditions = {},
        disallowed_algorithms = {},
        path = '/etc/ssh/link.conf',
    })
    assert(ok == nil, 'Expected symlink rejection')
    assert(err:find('symlink'), 'Expected symlink error message')
end

--------------------------------------------------------------------------------
-- sudo.fix_permission_paths
--------------------------------------------------------------------------------

function test_sudo_fix_permission_paths_chmods_files_and_dirs()
    local chmod_calls = {}
    sudo_enforcer._test_set_dependencies({
        fs_stat = function(path)
            if path:find('sudoers%.d') then
                return make_fs_attr(0, 0, tonumber('755', 8))
            end
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
    local ok = sudo_enforcer.fix_permission_paths({
        list = {
            details = {
                { path = '/etc/sudoers', path_type = 'file' },
                { path = '/etc/sudoers.d', path_type = 'directory' },
            },
        },
    })
    assert(ok == true, 'Expected fix_permission_paths to succeed')
    assert(#chmod_calls == 2, 'Expected chmod for both entries, got ' .. #chmod_calls)
    assert(chmod_calls[1].mode == tonumber('0440', 8), 'Expected 0440 for file')
    assert(chmod_calls[2].mode == tonumber('0750', 8), 'Expected 0750 for directory')
end

function test_sudo_fix_permission_paths_skips_compliant()
    local chmod_called = false
    sudo_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(0, 0, tonumber('0440', 8))
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
    local ok = sudo_enforcer.fix_permission_paths({
        list = { details = {
            { path = '/etc/sudoers', path_type = 'file' },
        } },
    })
    assert(ok == true, 'Expected success for compliant entry')
    assert(chmod_called == false, 'Expected no chmod when already correct')
end

function test_sudo_fix_permission_paths_skips_symlinks()
    local chmod_called = false
    sudo_enforcer._test_set_dependencies({
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
    local ok = sudo_enforcer.fix_permission_paths({
        list = { details = { { path = '/etc/sudoers', path_type = 'file' } } },
    })
    assert(ok == true, 'Expected success when symlink is skipped')
    assert(chmod_called == false, 'Expected no chmod on symlink')
end

function test_sudo_fix_permission_paths_requires_list()
    sudo_enforcer._test_set_dependencies({})
    local ok, err = sudo_enforcer.fix_permission_paths({})
    assert(ok == nil, 'Expected error when list is missing')
    assert(err ~= nil, 'Expected error message')
end

function test_sudo_fix_permission_paths_propagates_chown_failure()
    sudo_enforcer._test_set_dependencies({
        fs_stat = function()
            return make_fs_attr(1000, 1000, tonumber('644', 8))
        end,
        fs_chmod = function()
            return true
        end,
        fs_chown = function()
            return nil, 'chown failed'
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
    })
    local ok, err = sudo_enforcer.fix_permission_paths({
        list = { details = { { path = '/etc/sudoers', path_type = 'file' } } },
    })
    assert(ok == nil, 'Expected error when chown fails')
    assert(err:find('chown failed'), 'Expected chown error in message')
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
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    local deps = {
        io_open = function(_, mode)
            if mode == 'w' then
                return fake_out
            end
            return nil
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return make_fs_attr(0, 640, tonumber('640', 8))
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
    local ok = fsutil.write_lines_atomically_preserving_attrs('/etc/shadow', { 'line1', 'line2' }, 'test', deps)
    assert(ok == true, 'Expected write to succeed')
    assert(chown_called ~= nil, 'Expected chown to restore owner')
    assert(chown_called.uid == 0, 'Expected uid 0 to be restored')
    assert(chown_called.gid == 640, 'Expected gid 640 to be restored')
    assert(chmod_called ~= nil, 'Expected chmod to restore mode')
    assert(chmod_called.mode == tonumber('640', 8), 'Expected mode 0640 to be restored')
end

function test_fsutil_write_lines_preserving_attrs_writes_content()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    local deps = {
        io_open = function(_, mode)
            if mode == 'w' then
                return fake_out
            end
            return nil
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return nil
        end,
        fs_chown = function()
            return true
        end,
        fs_chmod = function()
            return true
        end,
    }
    local ok = fsutil.write_lines_atomically_preserving_attrs('/etc/test', { 'alpha', 'beta' }, 'test', deps)
    assert(ok == true, 'Expected write to succeed')
    local content = table.concat(written)
    assert(content:find('alpha'), 'Expected alpha in output')
    assert(content:find('beta'), 'Expected beta in output')
end

--------------------------------------------------------------------------------
-- fsutil.append_unique_line
--------------------------------------------------------------------------------

function test_fsutil_append_unique_line_appends_when_missing()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    local deps = {
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { 'existing_line' }
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
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return nil
        end,
        fs_chown = function()
            return true
        end,
        fs_chmod = function()
            return true
        end,
    }
    local ok = fsutil.append_unique_line('/etc/test.rules', 'new_rule_line', 'test', deps)
    assert(ok == true, 'Expected append to succeed')
    local content = table.concat(written)
    assert(content:find('existing_line'), 'Expected existing line preserved')
    assert(content:find('new_rule_line'), 'Expected new line appended')
end

function test_fsutil_append_unique_line_idempotent()
    local write_called = false
    local deps = {
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { 'existing_line', 'target_line' }
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
            return {
                write = function() end,
                close = function()
                    return true
                end,
            }
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return nil
        end,
        fs_chown = function()
            return true
        end,
        fs_chmod = function()
            return true
        end,
    }
    local ok = fsutil.append_unique_line('/etc/test.rules', 'target_line', 'test', deps)
    assert(ok == true, 'Expected idempotent skip to succeed')
    assert(write_called == false, 'Expected no write when line already present')
end

function test_fsutil_append_unique_line_rejects_symlink()
    local deps = {
        lfs_symlinkattributes = function()
            return { mode = 'link' }
        end,
    }
    local ok, err = fsutil.append_unique_line('/etc/link', 'line', 'test', deps)
    assert(ok == nil, 'Expected symlink rejection')
    assert(err:find('symlink'), 'Expected symlink error message')
end

function test_fsutil_append_unique_line_creates_new_file()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    local deps = {
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
        lfs_symlinkattributes = function()
            return nil
        end,
        fs_stat = function()
            return nil
        end,
        fs_chown = function()
            return true
        end,
        fs_chmod = function()
            return true
        end,
    }
    local ok = fsutil.append_unique_line('/etc/new.rules', 'first_line', 'test', deps)
    assert(ok == true, 'Expected creation to succeed')
    local content = table.concat(written)
    assert(content:find('first_line'), 'Expected first line written to new file')
end
