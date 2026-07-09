local sysctl_keys = require('seharden.shared.sysctl_keys')

function test_sysctl_keys_normalize_assignment_forms()
    assert(sysctl_keys.normalize('-net/ipv4/ip_forward') == 'net.ipv4.ip_forward')
    assert(sysctl_keys.normalize('kernel.randomize_va_space') == 'kernel.randomize_va_space')
end

function test_sysctl_keys_validate_rejects_path_traversal_and_bad_tokens()
    assert(sysctl_keys.validate('net.ipv4.ip_forward') == 'net.ipv4.ip_forward')
    assert(sysctl_keys.validate('../../etc/passwd') == nil)
    assert(sysctl_keys.validate('net.ipv4.ip forward') == nil)
end

function test_sysctl_keys_builds_procfs_paths()
    assert(
        sysctl_keys.procfs_path('kernel.randomize_va_space', '/tmp/proc-sys')
            == '/tmp/proc-sys/kernel/randomize_va_space'
    )
    assert(sysctl_keys.procfs_path('../../etc/passwd', '/tmp/proc-sys') == nil)
end
