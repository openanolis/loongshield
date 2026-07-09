local audit_rules = require('seharden.shared.audit_rules')

function test_audit_rules_matches_key_permission_and_watch_syntax()
    local watch_line = '-w /etc/sudoers.d/ -p aw -F key=scope'
    local syscall_watch_line = '-a exit,always -F dir=/etc/sudoers.d/ -F perm=wa -k scope'

    assert(audit_rules.canonicalize_permissions('aw') == 'wa', 'Expected permissions to be canonicalized')
    assert(audit_rules.has_permissions('aw', 'wa') == true, 'Expected permission order not to matter')
    assert(audit_rules.extract_key(watch_line) == 'scope', 'Expected -F key= format to be parsed')
    assert(audit_rules.key_matches(syscall_watch_line, 'scope', true), 'Expected -k key format to match')

    local path, kind = audit_rules.extract_watch_target(syscall_watch_line)
    assert(path == '/etc/sudoers.d/', 'Expected syscall-style dir target to be parsed')
    assert(kind == 'dir', 'Expected dir target kind to be reported')
    assert(audit_rules.extract_watch_permissions(watch_line) == 'aw', 'Expected watch permissions to be parsed')
    assert(audit_rules.extract_watch_permissions(syscall_watch_line) == 'wa', 'Expected perm field to be parsed')
    assert(audit_rules.is_always_exit_rule(syscall_watch_line), 'Expected exit,always order to be accepted')
end

function test_audit_rules_collects_syscalls_arch_and_filters()
    local line =
        '-a always,exit -F arch=b64 -S unlink,unlinkat -S rename -F exit=-13 -F auid>=500 -F auid!=-1 -C euid!=uid -F dir=/tmp -k delete'

    local syscalls = audit_rules.collect_syscalls(line)
    assert(syscalls.unlink == true, 'Expected comma-separated syscall to be collected')
    assert(syscalls.unlinkat == true, 'Expected second comma-separated syscall to be collected')
    assert(syscalls.rename == true, 'Expected repeated -S syscall to be collected')
    assert(audit_rules.extract_syscall_arch(line) == 'b64', 'Expected arch field to be parsed')
    assert(audit_rules.matches_auid_filters(line, 1000, true), 'Expected lower auid_min rule to satisfy threshold')
    assert(audit_rules.line_has_exit(line, 13), 'Expected exit sign to be ignored for matching')
    assert(audit_rules.line_has_field(line, { name = 'dir', value = '/tmp' }), 'Expected field match by name/value')
    assert(
        audit_rules.line_has_any_comparison(line, { 'uid!=euid' }),
        'Expected uid/euid comparison order to normalize'
    )
end

function test_audit_rules_accepts_unset_auid_aliases()
    assert(audit_rules.line_excludes_unset_auid('-F auid!=unset'), 'Expected unset alias to be accepted')
    assert(audit_rules.line_excludes_unset_auid('-F auid!=-1'), 'Expected -1 alias to be accepted')
    assert(audit_rules.line_excludes_unset_auid('-F auid!=4294967295'), 'Expected uint32 alias to be accepted')
end

function test_audit_rules_builds_canonical_lines()
    local watch_line = audit_rules.build_watch_line({
        path = '/etc/passwd',
        permissions = 'wa',
        key = 'identity',
    })
    assert(watch_line == '-w /etc/passwd -p wa -k identity', 'Expected canonical watch rule line')

    local syscall_lines = audit_rules.build_syscall_rule_lines({
        arches = { 'b64' },
        syscalls = { 'unlink', 'unlinkat' },
        comparisons_any = { 'uid!=euid' },
        fields = { { name = 'dir', value = '/tmp' } },
        exits = { -13 },
        auid_min = 1000,
        include_auid_unset = true,
        key = 'delete',
    })
    assert(
        syscall_lines[1]
            == '-a always,exit -F arch=b64 -S unlink -S unlinkat -C uid!=euid -F dir=/tmp -F exit=-13 -F auid>=1000 -F auid!=unset -k delete',
        'Expected syscall builder to preserve existing canonical line layout'
    )

    local path_exec_lines = audit_rules.build_path_exec_rule_lines({
        arches = { 'b64' },
        path = '/usr/bin/sudo',
        key = 'privileged',
    })
    assert(
        path_exec_lines[1] == '-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -k privileged',
        'Expected path exec builder to preserve existing canonical line layout'
    )
end
