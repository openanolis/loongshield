local sysctl_probe = require('seharden.probes.sysctl')

local function reset_probe()
    sysctl_probe.set_procfs_root('/proc/sys')
    sysctl_probe._test_set_dependencies()
end

local function lines_handle(lines)
    return {
        read = function()
            return lines[1]
        end,
        lines = function()
            local index = 0
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function()
            return true
        end,
    }
end

function test_sysctl_get_live_value_uses_procfs_path_for_dotted_key()
    sysctl_probe.set_procfs_root('/tmp/proc-sys')
    sysctl_probe._test_set_dependencies({
        io_open = function(path, mode)
            assert(path == '/tmp/proc-sys/kernel/randomize_va_space')
            assert(mode == 'r')
            return lines_handle({ '2' })
        end,
    })

    local result = sysctl_probe.get_live_value({ key = 'kernel.randomize_va_space' })

    reset_probe()
    assert(result.available == true)
    assert(result.path == '/tmp/proc-sys/kernel/randomize_va_space')
    assert(result.value == '2')
end

function test_sysctl_get_persistent_value_normalizes_assignment_keys()
    local sysctl_conf = '/tmp/test-sysctl.conf'
    sysctl_probe._test_set_dependencies({
        lfs_attributes = function(path)
            if path == sysctl_conf then
                return 'file'
            end
            return nil
        end,
        lfs_dir = function()
            return nil
        end,
        io_open = function(path, mode)
            assert(path == sysctl_conf)
            assert(mode == 'r')
            return lines_handle({
                '-net/ipv4/ip_forward = 0',
                'net.ipv4.conf.all.rp_filter = 1',
            })
        end,
    })

    local result = sysctl_probe.get_persistent_value({
        key = 'net.ipv4.ip_forward',
        sysctl_d_dirs = {},
        sysctl_conf = sysctl_conf,
    })

    reset_probe()
    assert(result.found == true)
    assert(result.value == '0')
    assert(result.source == sysctl_conf)
end

function test_sysctl_get_persistent_value_rejects_invalid_key()
    local result, err = sysctl_probe.get_persistent_value({ key = '../../etc/passwd' })

    reset_probe()
    assert(result == nil)
    assert(err == 'Invalid key')
end
