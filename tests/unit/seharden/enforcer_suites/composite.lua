--------------------------------------------------------------------------------

local audit_enforcer = require('seharden.enforcers.audit')
local pam_enforcer = require('seharden.enforcers.pam')
local sudo_enforcer = require('seharden.enforcers.sudo')
local helpers = require('seharden_enforcer_helpers')
local make_fake_text_fs = helpers.make_fake_text_fs
local merge_tables = helpers.merge_tables

function test_audit_ensure_watch_rule_appends_canonical_line_idempotently_and_preserves_attrs()
    local rule_file = '/etc/audit/rules.d/99-loongshield-seharden.rules'
    local deps, files, attrs = make_fake_text_fs({
        [rule_file] = '# managed by test\n',
    }, {
        ['/etc/audit/rules.d'] = { type = 'directory' },
        [rule_file] = { type = 'file', uid = 0, gid = 0, mode = 384 },
    }, {
        ['/etc/audit/rules.d'] = {},
    })

    audit_enforcer._test_set_dependencies(merge_tables(deps, {
        rules_dir = '/etc/audit/rules.d',
        fallback_rules_path = '/etc/audit/audit.rules',
    }))

    local ok = audit_enforcer.ensure_watch_rule({ path = '/etc/passwd', permissions = 'aw' })
    assert(ok == true, 'Expected audit watch rule creation to succeed')

    ok = audit_enforcer.ensure_watch_rule({ path = '/etc/passwd', permissions = 'aw' })
    assert(ok == true, 'Expected audit watch rule creation to be idempotent')

    local content = files[rule_file]
    assert(
        content:find('-w /etc/passwd -p wa', 1, true),
        'Expected watch rule permissions to be canonicalized in stable order'
    )
    local _, count = content:gsub('%-w /etc/passwd %-p wa', '')
    assert(count == 1, 'Expected duplicate audit watch rules to be avoided')
    assert(
        attrs[rule_file].uid == 0 and attrs[rule_file].gid == 0,
        'Expected audit rule file ownership to be preserved when rewriting'
    )
    assert(attrs[rule_file].mode == 384, 'Expected audit rule file mode to be preserved when rewriting')
end

function test_audit_ensure_syscall_rule_writes_each_arch_once()
    local rule_file = '/etc/audit/rules.d/99-loongshield-seharden.rules'
    local deps, files = make_fake_text_fs({
        [rule_file] = '',
    }, {
        ['/etc/audit/rules.d'] = { type = 'directory' },
        [rule_file] = { type = 'file', uid = 0, gid = 0, mode = 384 },
    }, {
        ['/etc/audit/rules.d'] = {},
    })

    audit_enforcer._test_set_dependencies(merge_tables(deps, {
        rules_dir = '/etc/audit/rules.d',
        fallback_rules_path = '/etc/audit/audit.rules',
    }))

    local ok = audit_enforcer.ensure_syscall_rule({
        syscalls = { 'unlinkat', 'unlink' },
        required_arches = { 'b64', 'b32' },
        auid_min = 1000,
    })
    assert(ok == true, 'Expected syscall audit rule creation to succeed')

    ok = audit_enforcer.ensure_syscall_rule({
        syscalls = { 'unlinkat', 'unlink' },
        required_arches = { 'b64', 'b32' },
        auid_min = 1000,
    })
    assert(ok == true, 'Expected syscall audit rule creation to be idempotent')

    local content = files[rule_file]
    assert(
        content:find('-F arch=b32 -S unlink -S unlinkat -F auid>=1000 -F auid!=unset', 1, true),
        'Expected syscall audit rule for b32 to be written with sorted syscalls'
    )
    assert(
        content:find('-F arch=b64 -S unlink -S unlinkat -F auid>=1000 -F auid!=unset', 1, true),
        'Expected syscall audit rule for b64 to be written with sorted syscalls'
    )
    local _, count = content:gsub('%-a always,exit', '')
    assert(count == 2, 'Expected exactly one syscall audit rule per architecture')
end

function test_pam_ensure_entry_inserts_before_anchor_and_preserves_attrs()
    local path = '/etc/pam.d/system-auth'
    local deps, files, attrs = make_fake_text_fs({
        [path] = table.concat({
            'auth required pam_env.so',
            'auth sufficient pam_unix.so',
        }, '\n') .. '\n',
    }, {
        [path] = { type = 'file', uid = 0, gid = 0, mode = 416 },
    })

    pam_enforcer._test_set_dependencies(deps)

    local ok = pam_enforcer.ensure_entry({
        path = path,
        kind = 'auth',
        module = 'pam_faillock.so',
        control = 'required',
        args = { 'preauth' },
        match_args = { 'preauth' },
        anchor_kind = 'auth',
        anchor_module = 'pam_unix.so',
    })
    assert(ok == true, 'Expected PAM entry insertion to succeed')

    local content = files[path]
    local env_pos = content:find('auth required pam_env.so', 1, true)
    local faillock_pos = content:find('auth required pam_faillock.so preauth', 1, true)
    local unix_pos = content:find('auth sufficient pam_unix.so', 1, true)
    assert(
        env_pos and faillock_pos and unix_pos and env_pos < faillock_pos and faillock_pos < unix_pos,
        'Expected PAM entry to be inserted immediately before the anchor module'
    )
    assert(attrs[path].uid == 0 and attrs[path].gid == 0, 'Expected PAM file ownership to be preserved when rewriting')
    assert(attrs[path].mode == 416, 'Expected PAM file mode to be preserved when rewriting')
end

function test_pam_ensure_entry_normalizes_duplicate_entries()
    local path = '/etc/pam.d/su'
    local deps, files = make_fake_text_fs({
        [path] = table.concat({
            'auth required pam_wheel.so trust',
            'auth sufficient pam_unix.so',
            'auth required pam_wheel.so use_uid',
        }, '\n') .. '\n',
    }, {
        [path] = { type = 'file', uid = 0, gid = 0, mode = 420 },
    })

    pam_enforcer._test_set_dependencies(deps)

    local ok = pam_enforcer.ensure_entry({
        path = path,
        kind = 'auth',
        module = 'pam_wheel.so',
        control = 'required',
        args = { 'use_uid' },
    })
    assert(ok == true, 'Expected duplicate PAM entry normalization to succeed')

    local content = files[path]
    local _, count = content:gsub('auth required pam_wheel.so use_uid', '')
    assert(count == 1, 'Expected duplicate PAM entries to collapse into one desired line')
    assert(
        not content:find('pam_wheel.so trust', 1, true),
        'Expected non-compliant duplicate PAM entries to be removed'
    )
end

function test_sudo_set_use_pty_strips_negated_entries_and_preserves_attrs()
    local root_path = '/etc/sudoers'
    local include_dir = '/etc/sudoers.d'
    local include_file = include_dir .. '/custom'
    local deps, files, attrs = make_fake_text_fs({
        [root_path] = table.concat({
            'Defaults !use_pty',
            '#includedir /etc/sudoers.d',
        }, '\n') .. '\n',
        [include_file] = table.concat({
            'Defaults !use_pty',
            'Defaults !authenticate',
        }, '\n') .. '\n',
    }, {
        [root_path] = { type = 'file', uid = 0, gid = 0, mode = 288 },
        [include_dir] = { type = 'directory' },
        [include_file] = { type = 'file', uid = 0, gid = 0, mode = 288 },
    }, {
        [include_dir] = { 'custom' },
    })

    sudo_enforcer._test_set_dependencies(merge_tables(deps, {
        root_path = root_path,
    }))

    local ok = sudo_enforcer.set_use_pty({ root_path = root_path })
    assert(ok == true, 'Expected sudo use_pty enforcement to succeed')

    assert(
        files[root_path]:find('Defaults use_pty', 1, true),
        'Expected the root sudoers file to gain a global Defaults use_pty line'
    )
    assert(
        not files[root_path]:find('!use_pty', 1, true),
        'Expected negated use_pty directives to be removed from the root sudoers file'
    )
    assert(
        not files[include_file]:find('!use_pty', 1, true),
        'Expected negated use_pty directives to be removed from included sudoers files'
    )
    assert(
        files[include_file]:find('Defaults !authenticate', 1, true),
        'Expected unrelated Defaults directives in included sudoers files to be preserved'
    )
    assert(
        attrs[root_path].mode == 288 and attrs[include_file].mode == 288,
        'Expected sudoers file modes to be preserved when rewriting'
    )

    ok = sudo_enforcer.set_use_pty({ root_path = root_path })
    assert(ok == true, 'Expected sudo use_pty enforcement to be idempotent')
    local _, count = files[root_path]:gsub('Defaults use_pty', '')
    assert(count == 1, 'Expected only one global Defaults use_pty line after repeated runs')
end

function test_sudo_ensure_audit_watches_resolves_dynamic_sudoers_paths()
    local root_path = '/etc/sudoers'
    local include_file = '/etc/sudoers.local'
    local include_dir = '/etc/sudoers.d'
    local included_member = include_dir .. '/custom'
    local captured = {}
    local deps = make_fake_text_fs({
        [root_path] = table.concat({
            '#include /etc/sudoers.local',
            '#includedir /etc/sudoers.d',
        }, '\n') .. '\n',
        [include_file] = 'Defaults env_reset\n',
        [included_member] = 'Defaults secure_path=/usr/sbin\n',
    }, {
        [root_path] = { type = 'file', uid = 0, gid = 0, mode = 288 },
        [include_file] = { type = 'file', uid = 0, gid = 0, mode = 288 },
        [include_dir] = { type = 'directory' },
        [included_member] = { type = 'file', uid = 0, gid = 0, mode = 288 },
    }, {
        [include_dir] = { 'custom' },
    })

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

    local ok = sudo_enforcer.ensure_audit_watches({ root_path = root_path, permissions = 'wa' })
    assert(ok == true, 'Expected sudo audit-watch enforcement to succeed')
    assert(
        #captured == 3,
        'Expected sudo audit-watch enforcement to cover the root file, explicit include, and includedir'
    )
    assert(captured[1].path == root_path, 'Expected the root sudoers file to be watched')
    assert(captured[2].path == include_file, 'Expected explicit include files to be watched individually')
    assert(captured[3].path == include_dir, 'Expected includedir paths to be watched at the directory level')
    assert(
        captured[1].permissions == 'wa' and captured[2].permissions == 'wa' and captured[3].permissions == 'wa',
        'Expected sudo audit-watch enforcement to pass through the requested permissions'
    )
end

--------------------------------------------------------------------------------
-- users enforcer: username injection hardening
--------------------------------------------------------------------------------

local users_enforcer = require('seharden.enforcers.users')

function test_users_set_password_max_days_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error('os_execute must NOT be called for unsafe usernames')
        end,
    })

    local ok, err = users_enforcer.set_password_max_days_for_root({
        max_days = 90,
        entries = {
            { user = 'alice;touch /tmp/x', pass_max_days = 999 },
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, 'Expected unsafe username to be rejected')
    assert(err:find('unsafe username', 1, true), 'Expected error to mention unsafe username')
end

function test_users_set_password_min_days_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error('os_execute must NOT be called for unsafe usernames')
        end,
    })

    local ok, err = users_enforcer.set_password_min_days_for_root({
        min_days = 7,
        entries = {
            { user = 'bob$(rm -rf /)', pass_min_days = 0 },
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, 'Expected unsafe username to be rejected')
    assert(err:find('unsafe username', 1, true), 'Expected error to mention unsafe username')
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
            { user = 'alice', pass_max_days = 999 },
            { user = 'bob_smith', pass_max_days = 100 },
            { user = 'carol.admin', pass_max_days = 50 }, -- already compliant, skipped
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == true, 'Expected safe usernames to succeed')
    assert(#commands == 2, 'Expected two chage commands (carol.admin already compliant)')
    assert(commands[1]:find('alice'), 'Expected alice command to be built')
    assert(commands[2]:find('bob_smith'), 'Expected bob_smith command to be built')
end

function test_users_lock_empty_password_accounts_locks_empty()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    users_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = {
                    'root:$6$hash:19000:0:99999:7:::',
                    'emptyuser::19000:0:99999:7:::',
                    'locked:!$6$hash:19000:0:99999:7:::',
                }
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
        lfs_symlinkattributes = function()
            return nil
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = users_enforcer.lock_empty_password_accounts({ shadow_path = '/etc/shadow' })
    assert(ok == true, 'Expected lock to succeed')
    local content = table.concat(written, '\n')
    assert(content:find('emptyuser:!'), 'Expected empty password to be locked with ! prefix')
    assert(content:find('root:%$6%$'), 'Expected non-empty password to be preserved')
end

function test_users_lock_empty_password_accounts_idempotent()
    local write_called = false
    users_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                local lines = { 'root:$6$hash:19000:0:99999:7:::', 'emptyuser:!locked:19000:0:99999:7:::' }
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
        lfs_symlinkattributes = function()
            return nil
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
    })
    local ok = users_enforcer.lock_empty_password_accounts({ shadow_path = '/etc/shadow' })
    assert(ok == true, 'Expected idempotent skip to return true')
    assert(write_called == false, 'Expected no write when no empty passwords found')
end

function test_users_lock_empty_password_accounts_rejects_symlink()
    users_enforcer._test_set_dependencies({
        lfs_symlinkattributes = function()
            return { mode = 'link' }
        end,
    })
    local ok, err = users_enforcer.lock_empty_password_accounts({ shadow_path = '/etc/shadow' })
    assert(ok == nil, 'Expected symlink rejection')
    assert(err:find('symlink'), 'Expected symlink error message')
end

function test_users_lock_shutdown_and_halt_accounts_locks_existing()
    local cmds = {}
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            cmds[#cmds + 1] = cmd
            if cmd:find('getent passwd') then
                return true, nil, 0
            end
            if cmd:find('passwd %-l') then
                return true, nil, 0
            end
            return true, nil, 0
        end,
    })
    local ok = users_enforcer.lock_shutdown_and_halt_accounts()
    assert(ok == true, 'Expected lock to succeed')
    local found_shutdown = false
    local found_halt = false
    for _, cmd in ipairs(cmds) do
        if cmd:find('passwd %-l shutdown') then
            found_shutdown = true
        end
        if cmd:find('passwd %-l halt') then
            found_halt = true
        end
    end
    assert(found_shutdown, 'Expected shutdown account to be locked')
    assert(found_halt, 'Expected halt account to be locked')
end

function test_users_lock_shutdown_and_halt_accounts_skips_missing()
    local lock_called = false
    users_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            if cmd:find('getent passwd') then
                return nil, 'not found', 2
            end
            if cmd:find('passwd %-l') then
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
            { user = 'alice', pass_max_days = 99999, pass_warn_age = 0, inactive = -1 },
        },
    })
    assert(ok == true, 'Expected set_password_defaults to succeed')
    assert(#cmds > 0, 'Expected at least one chage command')
    local cmd = cmds[1]
    assert(cmd:find('%-%-maxdays 90'), 'Expected --maxdays in command')
    assert(cmd:find('%-%-warndays 7'), 'Expected --warndays in command')
    assert(cmd:find('%-%-inactive 30'), 'Expected --inactive in command')
    assert(cmd:find('alice'), 'Expected username in command')
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
            { user = 'alice', pass_max_days = 60 },
        },
    })
    assert(ok == true, 'Expected success for compliant user')
    assert(cmd_called == false, 'Expected no chage when already compliant')
end

function test_users_set_password_defaults_requires_entries()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.set_password_defaults({ max_days = 90 })
    assert(ok == nil, 'Expected error when entries missing')
    assert(err ~= nil, 'Expected error message')
end

function test_users_set_password_defaults_requires_at_least_one_policy()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.set_password_defaults({ entries = { { user = 'alice' } } })
    assert(ok == nil, 'Expected error when no policy params given')
    assert(err ~= nil, 'Expected error message')
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
        details = { { user = 'alice' }, { user = 'bob' } },
    })
    assert(ok == true, 'Expected fix_future_password_changes to succeed')
    assert(#cmds == 2, 'Expected two chage commands')
    assert(cmds[1]:find('chage %-%-lastday'), 'Expected chage --lastday command')
    assert(cmds[1]:find('alice'), 'Expected username in command')
end

function test_users_fix_future_password_changes_requires_details()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.fix_future_password_changes({})
    assert(ok == nil, 'Expected error when details missing')
    assert(err ~= nil, 'Expected error message')
end

function test_users_fix_future_password_changes_propagates_failure()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, 'failed', 1
        end,
    })
    local ok, err = users_enforcer.fix_future_password_changes({
        details = { { user = 'alice' } },
    })
    assert(ok == nil, 'Expected error when chage fails')
    assert(err ~= nil, 'Expected error message')
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
        details = { { user = 'daemon' }, { user = 'bin' } },
    })
    assert(ok == true, 'Expected lock_nologin_accounts to succeed')
    assert(#cmds == 2, 'Expected two passwd -l commands')
    assert(cmds[1]:find('passwd %-l daemon'), 'Expected passwd -l for daemon')
end

function test_users_lock_nologin_accounts_requires_details()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.lock_nologin_accounts({})
    assert(ok == nil, 'Expected error when details missing')
    assert(err ~= nil, 'Expected error message')
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
    assert(ok == true, 'Expected lock_root_account to succeed')
    assert(cmd_run:find('passwd %-l root'), 'Expected passwd -l root command')
end

function test_users_lock_root_account_propagates_failure()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, 'failed', 1
        end,
    })
    local ok, err = users_enforcer.lock_root_account()
    assert(ok == nil, 'Expected error when passwd -l fails')
    assert(err ~= nil, 'Expected error message')
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
        details = { { user = 'daemon' }, { user = 'lp' } },
    })
    assert(ok == true, 'Expected disable_system_account_shells to succeed')
    assert(#cmds == 2, 'Expected two usermod commands')
    assert(cmds[1]:find('usermod %-s /usr/sbin/nologin daemon'), 'Expected usermod with nologin')
end

function test_users_disable_system_account_shells_requires_details()
    users_enforcer._test_set_dependencies({})
    local ok, err = users_enforcer.disable_system_account_shells({})
    assert(ok == nil, 'Expected error when details missing')
    assert(err ~= nil, 'Expected error message')
end

function test_users_disable_system_account_shells_propagates_failure()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, 'failed', 1
        end,
    })
    local ok, err = users_enforcer.disable_system_account_shells({
        details = { { user = 'daemon' } },
    })
    assert(ok == nil, 'Expected error when usermod fails')
    assert(err ~= nil, 'Expected error message')
end

function test_users_set_password_defaults_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error('os_execute must NOT be called for unsafe usernames')
        end,
    })

    local ok, err = users_enforcer.set_password_defaults({
        max_days = 90,
        entries = {
            { user = 'alice;touch /tmp/x', pass_max_days = 999, pass_warn_age = 7, inactive = 30 },
        },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, 'Expected unsafe username to be rejected')
    assert(err:find('unsafe username', 1, true), 'Expected error to mention unsafe username')
end

function test_users_fix_future_password_changes_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error('os_execute must NOT be called for unsafe usernames')
        end,
    })

    local ok, err = users_enforcer.fix_future_password_changes({
        details = { { user = 'bob$(whoami)' } },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, 'Expected unsafe username to be rejected')
    assert(err:find('unsafe username', 1, true), 'Expected error to mention unsafe username')
end

function test_users_lock_nologin_accounts_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error('os_execute must NOT be called for unsafe usernames')
        end,
    })

    local ok, err = users_enforcer.lock_nologin_accounts({
        details = { { user = '`touch /tmp/pwned`' } },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, 'Expected unsafe username to be rejected')
    assert(err:find('unsafe username', 1, true), 'Expected error to mention unsafe username')
end

function test_users_disable_system_account_shells_rejects_unsafe_username()
    users_enforcer._test_set_dependencies({
        os_execute = function()
            error('os_execute must NOT be called for unsafe usernames')
        end,
    })

    local ok, err = users_enforcer.disable_system_account_shells({
        details = { { user = 'nobody|cat /etc/shadow' } },
    })
    users_enforcer._test_set_dependencies()

    assert(ok == nil, 'Expected unsafe username to be rejected')
    assert(err:find('unsafe username', 1, true), 'Expected error to mention unsafe username')
end

function test_users_fix_dotfiles_removes_forbidden_files()
    local removed = {}
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/passwd' then
                local lines = { 'testuser:x:1000:1000::/home/testuser:/bin/bash' }
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
            if path == '/home/testuser' then
                return { mode = 'directory', dev = 1 }
            end
            if path == '/home/testuser/.forward' then
                return { mode = 'file', dev = 1 }
            end
            return nil
        end,
        lfs_dir = function(path)
            if path == '/home/testuser' then
                local items = { '.forward' }
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
        fs_stat = function()
            return nil
        end,
        fs_chmod = function()
            return true
        end,
        fs_chown = function()
            return true
        end,
        passwd_path = '/etc/passwd',
    })
    local ok = users_enforcer.fix_dotfiles()
    assert(ok == true, 'Expected fix_dotfiles to succeed')
    assert(#removed > 0, 'Expected .forward to be removed')
    assert(removed[1]:find('%.forward'), 'Expected .forward path in removals')
end

function test_users_fix_dotfiles_fixes_permissions()
    local chmod_called = false
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/passwd' then
                local lines = { 'testuser:x:1000:1000::/home/testuser:/bin/bash' }
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
            if path == '/home/testuser' then
                return { mode = 'directory', dev = 1 }
            end
            if path == '/home/testuser/.bashrc' then
                return { mode = 'file', dev = 1 }
            end
            return nil
        end,
        lfs_dir = function(path)
            if path == '/home/testuser' then
                local items = { '.bashrc' }
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
                mode = function()
                    return tonumber('777', 8)
                end,
                uid = function()
                    return 1000
                end,
                gid = function()
                    return 1000
                end,
            }
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        fs_chown = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        passwd_path = '/etc/passwd',
    })
    local ok = users_enforcer.fix_dotfiles()
    assert(ok == true, 'Expected fix_dotfiles to succeed')
    assert(chmod_called, 'Expected chmod for overly permissive dotfile')
end

function test_users_fix_dotfiles_idempotent()
    local chmod_called = false
    local chown_called = false
    local remove_called = false
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/passwd' then
                local lines = { 'testuser:x:1000:1000::/home/testuser:/bin/bash' }
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
            if path == '/home/testuser' then
                return { mode = 'directory', dev = 1 }
            end
            if path == '/home/testuser/.bashrc' then
                return { mode = 'file', dev = 1 }
            end
            return nil
        end,
        lfs_dir = function(path)
            if path == '/home/testuser' then
                local items = { '.bashrc' }
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
                mode = function()
                    return tonumber('644', 8)
                end,
                uid = function()
                    return 1000
                end,
                gid = function()
                    return 1000
                end,
            }
        end,
        fs_chmod = function()
            chmod_called = true
            return true
        end,
        fs_chown = function()
            chown_called = true
            return true
        end,
        os_remove = function()
            remove_called = true
            return true
        end,
        passwd_path = '/etc/passwd',
    })
    local ok = users_enforcer.fix_dotfiles()
    assert(ok == true, 'Expected idempotent run to succeed')
    assert(chmod_called == false, 'Expected no chmod for compliant dotfile')
    assert(chown_called == false, 'Expected no chown for compliant dotfile')
    assert(remove_called == false, 'Expected no removal for non-forbidden dotfile')
end

function test_users_fix_dotfiles_reports_os_remove_failure()
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/passwd' then
                local lines = { 'testuser:x:1000:1000::/home/testuser:/bin/bash' }
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
            if path == '/home/testuser' then
                return { mode = 'directory', dev = 1 }
            end
            if path == '/home/testuser/.forward' then
                return { mode = 'file', dev = 1 }
            end
            return nil
        end,
        lfs_dir = function(path)
            if path == '/home/testuser' then
                local items = { '.forward' }
                local i = 0
                return function()
                    i = i + 1
                    return items[i]
                end
            end
            return nil
        end,
        os_remove = function()
            return nil, 'Permission denied'
        end,
        fs_stat = function()
            return nil
        end,
        fs_chmod = function()
            return true
        end,
        fs_chown = function()
            return true
        end,
        passwd_path = '/etc/passwd',
    })
    local ok, err = users_enforcer.fix_dotfiles()
    assert(ok == nil, 'Expected fix_dotfiles to report failure when os_remove fails')
    assert(err and err:find('remove'), 'Expected error message mentioning remove, got: ' .. tostring(err))
end

function test_users_fix_dotfiles_reports_fs_chmod_failure()
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/passwd' then
                local lines = { 'testuser:x:1000:1000::/home/testuser:/bin/bash' }
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
            if path == '/home/testuser' then
                return { mode = 'directory', dev = 1 }
            end
            if path == '/home/testuser/.bashrc' then
                return { mode = 'file', dev = 1 }
            end
            return nil
        end,
        lfs_dir = function(path)
            if path == '/home/testuser' then
                local items = { '.bashrc' }
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
                mode = function()
                    return tonumber('777', 8)
                end,
                uid = function()
                    return 1000
                end,
                gid = function()
                    return 1000
                end,
            }
        end,
        fs_chmod = function()
            return nil, 'Operation not permitted'
        end,
        fs_chown = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        passwd_path = '/etc/passwd',
    })
    local ok, err = users_enforcer.fix_dotfiles()
    assert(ok == nil, 'Expected fix_dotfiles to report failure when fs_chmod fails')
    assert(err and err:find('chmod'), 'Expected error message mentioning chmod, got: ' .. tostring(err))
end

function test_users_fix_dotfiles_reports_fs_chown_failure()
    users_enforcer._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/passwd' then
                local lines = { 'testuser:x:1000:1000::/home/testuser:/bin/bash' }
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
            if path == '/home/testuser' then
                return { mode = 'directory', dev = 1 }
            end
            if path == '/home/testuser/.bashrc' then
                return { mode = 'file', dev = 1 }
            end
            return nil
        end,
        lfs_dir = function(path)
            if path == '/home/testuser' then
                local items = { '.bashrc' }
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
                mode = function()
                    return tonumber('644', 8)
                end,
                uid = function()
                    return 0
                end,
                gid = function()
                    return 0
                end,
            }
        end,
        fs_chmod = function()
            return true
        end,
        fs_chown = function()
            return nil, 'Operation not permitted'
        end,
        os_remove = function()
            return true
        end,
        passwd_path = '/etc/passwd',
    })
    local ok, err = users_enforcer.fix_dotfiles()
    assert(ok == nil, 'Expected fix_dotfiles to report failure when fs_chown fails')
    assert(err and err:find('chown'), 'Expected error message mentioning chown, got: ' .. tostring(err))
end

--------------------------------------------------------------------------------
-- sudo enforcer: !authenticate Defaults handling
--------------------------------------------------------------------------------

function test_sudo_remove_nopasswd_strips_authenticate_disabled_defaults()
    local root_path = '/etc/sudoers'
    local include_dir = '/etc/sudoers.d'
    local include_file = include_dir .. '/custom'
    local deps, files, attrs = make_fake_text_fs({
        [root_path] = table.concat({
            'Defaults !authenticate',
            '#includedir /etc/sudoers.d',
        }, '\n') .. '\n',
        [include_file] = table.concat({
            'Defaults:deploy !authenticate',
            'deploy ALL=(ALL) NOPASSWD: ALL',
        }, '\n') .. '\n',
    }, {
        [root_path] = { type = 'file', uid = 0, gid = 0, mode = 288 },
        [include_dir] = { type = 'directory' },
        [include_file] = { type = 'file', uid = 0, gid = 0, mode = 288 },
    }, {
        [include_dir] = { 'custom' },
    })

    sudo_enforcer._test_set_dependencies(deps)
    local ok = sudo_enforcer.remove_nopasswd({ root_path = root_path })
    sudo_enforcer._test_set_dependencies()

    assert(ok == true, 'Expected remove_nopasswd to succeed')
    assert(
        not files[root_path]:find('!authenticate', 1, true),
        'Expected global !authenticate Defaults line to be dropped'
    )
    assert(
        not files[include_file]:find('!authenticate', 1, true),
        'Expected scoped !authenticate Defaults line to be dropped'
    )
    assert(not files[include_file]:find('NOPASSWD:', 1, true), 'Expected NOPASSWD tag to be removed from rule line')
end

function test_sudo_remove_nopasswd_preserves_other_tokens_when_stripping_authenticate()
    local root_path = '/etc/sudoers'
    local deps, files, attrs = make_fake_text_fs({
        [root_path] = table.concat({
            'Defaults authenticate, !authenticate, use_pty',
        }, '\n') .. '\n',
    }, {
        [root_path] = { type = 'file', uid = 0, gid = 0, mode = 288 },
    }, {})

    sudo_enforcer._test_set_dependencies(deps)
    local ok = sudo_enforcer.remove_nopasswd({ root_path = root_path })
    sudo_enforcer._test_set_dependencies()

    assert(ok == true, 'Expected remove_nopasswd to succeed')
    assert(not files[root_path]:find('!authenticate', 1, true), 'Expected !authenticate token to be removed')
    assert(files[root_path]:find('authenticate', 1, true), 'Expected positive authenticate token to be preserved')
    assert(files[root_path]:find('use_pty', 1, true), 'Expected other tokens like use_pty to be preserved')
end

--------------------------------------------------------------------------------
-- audit enforcer (new functions)
--------------------------------------------------------------------------------

function test_audit_ensure_path_exec_rule_writes_rule()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    audit_enforcer._test_set_dependencies({
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
        lfs_attributes = function()
            return { mode = 'directory' }
        end,
        rules_dir = '/etc/audit/rules.d',
    })
    local ok = audit_enforcer.ensure_path_exec_rule({ path = '/usr/bin/sudo', key = 'privileged', arches = { 'b64' } })
    assert(ok == true, 'Expected ensure_path_exec_rule to succeed')
    local content = table.concat(written)
    assert(content:find('path=/usr/bin/sudo'), 'Expected path in rule')
    assert(content:find('arch=b64'), 'Expected arch in rule')
    assert(content:find('%-k privileged'), 'Expected key in rule')
end

function test_audit_ensure_path_exec_rule_rejects_unsafe_path()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_path_exec_rule({ path = '' })
    assert(ok == nil, 'Expected error for empty path')
    assert(err ~= nil, 'Expected error message')
end

function test_audit_ensure_path_exec_rule_rejects_invalid_key()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_path_exec_rule({ path = '/usr/bin/sudo', key = 'bad key!' })
    assert(ok == nil, 'Expected error for invalid key')
    assert(err ~= nil, 'Expected error message')
end

function test_audit_ensure_privileged_command_rules_scans_and_writes()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    local popen_calls = {}
    audit_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
            end
            return fake_out
        end,
        io_popen = function(cmd)
            popen_calls[#popen_calls + 1] = cmd
            local lines
            if cmd:find('findmnt') then
                lines = { '/' }
            else
                lines = { '/usr/bin/sudo', '/usr/bin/passwd' }
            end
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
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        lfs_attributes = function()
            return { mode = 'directory' }
        end,
        rules_dir = '/etc/audit/rules.d',
    })
    local ok = audit_enforcer.ensure_privileged_command_rules({ key = 'privileged' })
    assert(ok == true, 'Expected ensure_privileged_command_rules to succeed')
    local content = table.concat(written)
    assert(content:find('path=/usr/bin/sudo'), 'Expected sudo path in rules')
    assert(content:find('path=/usr/bin/passwd'), 'Expected passwd path in rules')
    assert(#popen_calls >= 1 and popen_calls[1]:find('findmnt'), 'Expected findmnt call for mount-point scanning')
end

function test_audit_ensure_privileged_command_rules_scans_multiple_mounts()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    local popen_calls = {}
    audit_enforcer._test_set_dependencies({
        io_open = function(_, mode)
            if mode == 'r' then
                return nil
            end
            return fake_out
        end,
        io_popen = function(cmd)
            popen_calls[#popen_calls + 1] = cmd
            local lines
            if cmd:find('findmnt') then
                lines = { '/', '/usr' }
            elseif cmd:find("find '/'") then
                lines = { '/usr/bin/sudo' }
            elseif cmd:find("find '/usr'") then
                lines = { '/usr/libexec/dbus-daemon-launch-helper' }
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
                close = function()
                    return true, nil, 0
                end,
            }
        end,
        os_rename = function()
            return true
        end,
        os_remove = function()
            return true
        end,
        lfs_attributes = function()
            return { mode = 'directory' }
        end,
        rules_dir = '/etc/audit/rules.d',
    })
    local ok = audit_enforcer.ensure_privileged_command_rules({ key = 'privileged' })
    assert(ok == true, 'Expected ensure_privileged_command_rules to succeed')
    local content = table.concat(written)
    assert(content:find('path=/usr/bin/sudo'), 'Expected sudo from / filesystem')
    assert(
        content:find('path=/usr/libexec/dbus%-daemon%-launch%-helper'),
        'Expected binary from /usr filesystem (cross-mount scanning)'
    )
end

function test_audit_ensure_privileged_command_rules_rejects_invalid_key()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_privileged_command_rules({ key = 'bad key!' })
    assert(ok == nil, 'Expected error for invalid key')
    assert(err ~= nil, 'Expected error message')
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
    assert(ok == true, 'Expected reload_rules to succeed')
    assert(cmd_run:find('augenrules'), 'Expected augenrules command')
    assert(cmd_run:find('%-%-load'), 'Expected --load flag')
end

function test_audit_reload_rules_propagates_failure()
    audit_enforcer._test_set_dependencies({
        os_execute = function()
            return nil, 'failed', 1
        end,
    })
    local ok, err = audit_enforcer.reload_rules()
    assert(ok == nil, 'Expected error when augenrules fails')
    assert(err ~= nil, 'Expected error message')
end

function test_audit_ensure_directive_appends_line()
    local written = {}
    local fake_out = {
        write = function(_, s)
            table.insert(written, s)
        end,
        close = function()
            return true
        end,
    }
    audit_enforcer._test_set_dependencies({
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
        lfs_attributes = function()
            return { mode = 'directory' }
        end,
        rules_dir = '/etc/audit/rules.d',
    })
    local ok = audit_enforcer.ensure_directive({ directive = '-e', value = '2' })
    assert(ok == true, 'Expected ensure_directive to succeed')
    local content = table.concat(written)
    assert(content:find('%-e 2'), 'Expected directive with value in output')
end

function test_audit_ensure_directive_rejects_missing_directive()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_directive({})
    assert(ok == nil, 'Expected error when directive is missing')
    assert(err ~= nil, 'Expected error message')
end

function test_audit_ensure_directive_rejects_directive_without_dash()
    audit_enforcer._test_set_dependencies({})
    local ok, err = audit_enforcer.ensure_directive({ directive = 'badvalue' })
    assert(ok == nil, 'Expected error for directive without leading dash')
    assert(err:find("must start with '-'"), 'Expected specific error message')
end
