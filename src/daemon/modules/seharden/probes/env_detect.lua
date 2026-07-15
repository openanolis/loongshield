--- Environment detection probes for seharden reinforce guards.
-- These probes detect the runtime environment so that dangerous
-- reinforce actions (e.g. disabling overlay, killing ip_forward)
-- can be safely skipped on container hosts.
local log = require('runtime.log')
local M = {}

local _default_dependencies = {
    io_open    = io.open,
    io_popen   = io.popen,
    os_execute = os.execute,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

--- Check whether a file exists on disk.
local function file_exists(path)
    local f = _dependencies.io_open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

--- Check whether kubelet is running (hardcoded to avoid shell injection).
local function kubelet_running()
    local ok, _, code = _dependencies.os_execute(
        "pgrep -x kubelet >/dev/null 2>&1")
    return ok == true or code == 0
end

--- Detect whether the host is running a container runtime.
-- Checks: Docker socket, containerd socket, kubelet, /.dockerenv
-- Returns: true, reason  when container runtime is detected
--          false          when no container runtime found
function M.is_container_host(_params)
    if file_exists("/run/docker.sock") then
        return true, "container runtime detected: /run/docker.sock exists"
    end

    if file_exists("/run/containerd/containerd.sock") then
        return true, "container runtime detected: /run/containerd/containerd.sock exists"
    end

    if kubelet_running() then
        return true, "container runtime detected: kubelet process found"
    end

    if file_exists("/.dockerenv") then
        return true, "container runtime detected: /.dockerenv exists"
    end

    log.debug("env_detect.is_container_host: no container runtime detected")
    return false
end

--- Check whether at least one non-root sudo/wheel user exists.
-- Reads /etc/group for the wheel group, then verifies that at least one
-- listed member has UID >= 1000 in /etc/passwd and an interactive shell.
-- Returns: true, reason  when a sudo user is found
--          false          when no sudo user is found
function M.has_sudo_user(params)
    params = params or {}
    local group_path = params.group_path or '/etc/group'
    local passwd_path = params.passwd_path or '/etc/passwd'

    -- Read wheel group members
    local gf = _dependencies.io_open(group_path, 'r')
    if not gf then
        log.debug('env_detect.has_sudo_user: cannot open %s', group_path)
        return false
    end

    local wheel_members = {}
    for line in gf:lines() do
        local fields = {}
        for field in (line .. ':'):gmatch('([^:]*):') do
            fields[#fields + 1] = field
        end
        if fields[1] == 'wheel' or fields[1] == 'sudo' then
            -- Fourth field is comma-separated member list; collect members
            -- from both groups (no break: either may carry the sudo users).
            if fields[4] and fields[4] ~= '' then
                for member in fields[4]:gmatch('([^,]+)') do
                    wheel_members[member] = true
                end
            end
        end
    end
    gf:close()

    if next(wheel_members) == nil then
        log.debug('env_detect.has_sudo_user: wheel/sudo group is empty')
        return false
    end

    -- Check passwd for non-root interactive users in wheel
    local pf = _dependencies.io_open(passwd_path, 'r')
    if not pf then
        log.debug('env_detect.has_sudo_user: cannot open %s', passwd_path)
        return false
    end

    local nologin_shells = {
        ['/usr/sbin/nologin'] = true,
        ['/sbin/nologin']     = true,
        ['/bin/false']        = true,
        ['/usr/bin/false']    = true,
    }

    for line in pf:lines() do
        local fields = {}
        for field in (line .. ':'):gmatch('([^:]*):') do
            fields[#fields + 1] = field
        end
        if #fields >= 7 then
            local username = fields[1]
            local uid = tonumber(fields[3])
            local shell = fields[7]
            if username ~= 'root'
                and uid and uid >= 1000
                and wheel_members[username]
                and not nologin_shells[shell] then
                pf:close()
                return true, string.format('sudo user found: %s (uid=%d)', username, uid)
            end
        end
    end
    pf:close()

    log.debug('env_detect.has_sudo_user: no non-root sudo user found')
    return false
end

--- Check whether NO non-root sudo/wheel user exists.
-- Inverse of `has_sudo_user`, for use as a lockout-protection reinforce guard:
-- returns truthy when disabling root login would leave no administrative
-- access, so that `evaluate_guard()` (truthy = skip) skips the reinforcement.
-- Returns: true, reason  when no sudo user is found (reinforce should be skipped)
--          false          when a sudo user exists
function M.no_sudo_user(params)
    local found = M.has_sudo_user(params)
    if found then
        return false
    end
    return true, 'no non-root sudo user detected'
end

--- Check whether the system has out-of-band console access available.
-- Checks the kernel console= boot parameter, cloud management console
-- markers, and IPMI/BMC devices.
-- Returns: true, reason  when console access is detected
--          false          when no console access is found
function M.has_console_access(_params)
    -- Check the kernel console= boot parameter (a serial console actually
    -- configured for the kernel, not merely a ttyS0 device node).
    local f = _dependencies.io_open('/proc/cmdline', 'r')
    if f then
        local cmdline = f:read('*a') or ''
        f:close()
        if cmdline:match('console=%S*ttyS') then
            return true, 'serial console configured via kernel console= parameter'
        end
    end

    -- Check for cloud-init (indicates cloud VM with management console)
    if file_exists('/var/lib/cloud/instance') then
        return true, 'cloud instance detected: /var/lib/cloud/instance exists'
    end

    -- Check for IPMI/BMC
    if file_exists('/dev/ipmi0') or file_exists('/dev/ipmi/0') then
        return true, 'IPMI/BMC detected: out-of-band management available'
    end

    log.debug('env_detect.has_console_access: no console access detected')
    return false
end

--- Check whether NO out-of-band console access is available.
-- Inverse of `has_console_access`, for use as a lockout-protection reinforce
-- guard: returns truthy when enabling even_deny_root could lock out all
-- administrators, so that `evaluate_guard()` (truthy = skip) skips it.
-- Returns: true, reason  when no console access is found (reinforce should be skipped)
--          false          when console access is available
function M.no_console_access(params)
    local found = M.has_console_access(params)
    if found then
        return false
    end
    return true, 'no out-of-band console access detected'
end

--- Detect whether the SSH server is a legacy version that may lack support
-- for CIS-recommended cipher/KexAlgorithm/MAC algorithms.
-- OpenSSH >= 6.5 (released 2014) supports all CIS-recommended algorithms.
-- AL3 ships OpenSSH 8.x, so this guard only triggers on heavily customised
-- or very old installations.
-- Returns: true, reason  when legacy SSH is detected (guard should skip)
--          false          when SSH is modern or not installed
function M.is_legacy_ssh_client(_params)
    local handle = _dependencies.io_popen('ssh -V 2>&1')
    if not handle then
        log.debug('env_detect.is_legacy_ssh_client: ssh not available')
        return false
    end

    local output = handle:read('*a') or ''
    handle:close()

    local major, minor = output:match('OpenSSH_(%d+)%.(%d+)')
    if not major then
        log.debug('env_detect.is_legacy_ssh_client: could not parse SSH version')
        return false
    end

    major = tonumber(major)
    minor = tonumber(minor) or 0

    -- OpenSSH 6.5+ supports all CIS-recommended algorithms
    if major > 6 or (major == 6 and minor >= 5) then
        log.debug('env_detect.is_legacy_ssh_client: OpenSSH %d.%d is modern', major, minor)
        return false
    end

    return true, string.format('legacy SSH detected: OpenSSH %d.%d (< 6.5)', major, minor)
end

return M
