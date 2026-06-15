local lfs = require('lfs')
local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    io_popen = io.popen,
    os_rename = os.rename,
    os_remove = os.remove,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function trim(s)
    return (tostring(s or ''):match('^%s*(.-)%s*$'))
end

local SAFE_SHELL_ARG_PATTERN = '^[a-zA-Z0-9%._-]+$'
local SAFE_SHELL_ADDR_PATTERN = '^[a-zA-Z0-9%._:-]+$'
local SSHD_CANDIDATE_PATHS = {
    '/usr/sbin/sshd',
    '/usr/local/sbin/sshd',
    '/sbin/sshd',
    '/usr/bin/sshd',
    '/usr/local/bin/sshd',
    '/bin/sshd',
}

local function sanitize_shell_arg(arg, pattern)
    pattern = pattern or SAFE_SHELL_ARG_PATTERN
    if not arg or not tostring(arg):match(pattern) then
        return nil
    end
    return tostring(arg)
end

local function resolve_sshd_path()
    for _, path in ipairs(SSHD_CANDIDATE_PATHS) do
        local file = _dependencies.io_open(path, 'r')
        if file then
            file:close()
            return path
        end
    end
    return nil
end

local function read_local_hostname()
    local file = _dependencies.io_open('/proc/sys/kernel/hostname', 'r')
    if not file then
        return nil
    end
    local hostname = trim(file:read('*l'))
    file:close()
    return hostname ~= '' and hostname or nil
end

local function resolve_localhost()
    local hostname = read_local_hostname()
    local localhost_ip
    local f_hosts = _dependencies.io_open('/etc/hosts', 'r')
    if f_hosts then
        for line in f_hosts:lines() do
            if not line:match('^#') then
                local line_ip = line:match('^(%S+)')
                for word in line:gmatch('%S+') do
                    if hostname and word == hostname then
                        break
                    end
                    if word == 'localhost' then
                        localhost_ip = localhost_ip or line_ip
                    end
                end
            end
        end
        f_hosts:close()
    end
    hostname = hostname or 'localhost'
    return { host = hostname, addr = localhost_ip or '127.0.0.1' }
end

local function run_sshd_T(conditions)
    local sshd_path = resolve_sshd_path()
    if not sshd_path then
        return nil, 'sshd binary not found'
    end

    local localhost = resolve_localhost()
    local safe_user = sanitize_shell_arg(conditions.user or 'root')
    local safe_host = sanitize_shell_arg(localhost.host)
    local safe_addr = sanitize_shell_arg(localhost.addr, SAFE_SHELL_ADDR_PATTERN)

    if not (safe_user and safe_host and safe_addr) then
        return nil, 'Invalid shell arguments'
    end

    local cmd = string.format('%s -T -C user=%s -C host=%s -C addr=%s', sshd_path, safe_user, safe_host, safe_addr)

    log.debug('ssh.remove_disallowed_algorithms: running: %s', cmd)
    local handle = _dependencies.io_popen(cmd, 'r')
    if not handle then
        return nil, 'Failed to execute sshd -T'
    end

    local values = {}
    for line in handle:lines() do
        local key, value = line:match('^%s*(%S+)%s+(.*)$')
        if key then
            values[key:lower()] = value
        end
    end

    local ok, _, code = handle:close()
    if not ok or code ~= 0 then
        return nil, string.format('sshd -T failed with exit code: %s', tostring(code))
    end

    return values
end

local function split_algorithm_list(value)
    local algorithms = {}
    for algo in tostring(value or ''):gmatch('[^,%s]+') do
        algorithms[#algorithms + 1] = algo
    end
    return algorithms
end

local function build_algorithm_set(values)
    local set = {}
    for _, v in ipairs(values or {}) do
        set[v:lower()] = true
    end
    return set
end

-- Map lowercase key to sshd_config directive name
local DIRECTIVE_NAMES = {
    ciphers = 'Ciphers',
    kexalgorithms = 'KexAlgorithms',
    macs = 'MACs',
}

-- Comment out all occurrences of a directive in a config file.
-- This ensures that an earlier directive does not shadow the value
-- written to the CIS hardening drop-in (OpenSSH first-match-wins).
local function comment_out_directive_in_file(file_path, directive)
    local f = _dependencies.io_open(file_path, 'r')
    if not f then
        return false
    end

    local escaped_directive = directive:gsub('([%^%$%(%)%%%.%[%]%*%+%-%?])', '%%%1')
    local match_pattern = '^%s*' .. escaped_directive .. '%s+'
    local lines = {}
    local modified = false

    for line in f:lines() do
        if line:match(match_pattern) and not line:match('^%s*#') then
            lines[#lines + 1] = '# ' .. line .. '  # commented by loongshield CIS hardening'
            modified = true
        else
            lines[#lines + 1] = line
        end
    end
    f:close()

    if not modified then
        return false
    end

    log.debug('ssh: commenting out %s directive in %s', directive, file_path)
    local ok, err = fsutil.write_lines_atomically(file_path, lines, 'ssh.remove_disallowed_algorithms', _dependencies)
    if not ok then
        log.warn('ssh: failed to update %s: %s', file_path, err)
    end
    return true
end

-- Remove disallowed algorithms from the effective SSH algorithm list.
-- Dynamically queries sshd -T, computes the safe list, and writes it
-- to the target config file.  Also comments out conflicting directives
-- in sshd_config and lexically earlier drop-in files so that the CIS
-- hardening value is guaranteed to take effect (OpenSSH first-match-wins).
-- Idempotent.
-- params: {
--   key: "ciphers" | "kexalgorithms" | "macs",
--   conditions: { user: "root", from: "localhost" },
--   disallowed_algorithms: { "3des-cbc", ... },
--   path: "/etc/ssh/sshd_config.d/00-cis-hardening.conf" (optional),
--   sshd_config_path: "/etc/ssh/sshd_config" (optional),
--   sshd_config_d_path: "/etc/ssh/sshd_config.d" (optional)
-- }
function M.remove_disallowed_algorithms(params)
    if not params or not params.key or not params.conditions or not params.disallowed_algorithms then
        return nil, "ssh.remove_disallowed_algorithms: requires 'key', 'conditions', and 'disallowed_algorithms'"
    end

    local search_key = params.key:lower()
    local directive = DIRECTIVE_NAMES[search_key]
    if not directive then
        return nil, string.format("ssh.remove_disallowed_algorithms: unsupported key '%s'", params.key)
    end

    local config_path = params.path or '/etc/ssh/sshd_config.d/00-cis-hardening.conf'

    if fsutil.is_symlink(config_path, _dependencies) then
        return nil, string.format("ssh.remove_disallowed_algorithms: refusing to overwrite symlink '%s'", config_path)
    end

    -- Step 1: Get current effective algorithms from sshd -T
    local values, err = run_sshd_T(params.conditions)
    if not values then
        return nil, string.format('ssh.remove_disallowed_algorithms: %s', err)
    end

    local current_value = values[search_key]
    if not current_value or current_value == '' then
        log.debug("ssh.remove_disallowed_algorithms: no effective value for '%s', nothing to fix", search_key)
        return true
    end

    -- Step 2: Remove disallowed algorithms
    local current_algos = split_algorithm_list(current_value)
    local disallowed_set = build_algorithm_set(params.disallowed_algorithms)
    local safe_algos = {}

    for _, algo in ipairs(current_algos) do
        if not disallowed_set[algo:lower()] then
            safe_algos[#safe_algos + 1] = algo
        end
    end

    if #safe_algos == 0 then
        return nil,
            string.format(
                'ssh.remove_disallowed_algorithms: removing all %s algorithms would leave sshd with none',
                directive
            )
    end

    local new_value = table.concat(safe_algos, ',')
    local new_line = directive .. ' ' .. new_value

    -- Step 3: Read existing config and update or append the directive
    local lines = {}
    local found = false

    local f_in = _dependencies.io_open(config_path, 'r')
    if f_in then
        local escaped_directive = directive:gsub('([%^%$%(%)%%%.%[%]%*%+%-%?])', '%%%1')
        local match_pattern = '^%s*' .. escaped_directive .. '%s+'
        for line in f_in:lines() do
            if line:match(match_pattern) then
                if not found then
                    table.insert(lines, new_line)
                    found = true
                end
                -- skip duplicate lines (first match wins in sshd)
            else
                table.insert(lines, line)
            end
        end
        f_in:close()
    end

    if not found then
        table.insert(lines, new_line)
    end

    log.debug('Enforcer ssh.remove_disallowed_algorithms: writing %s to %s', directive, config_path)
    local write_ok, write_err = fsutil.write_lines_atomically(config_path, lines, 'ssh.remove_disallowed_algorithms', _dependencies)
    if not write_ok then
        return nil, write_err
    end

    -- Step 4: Comment out conflicting directives in sshd_config.
    -- OpenSSH uses first-match-wins, so an earlier Ciphers/KexAlgorithms/MACs
    -- in the main sshd_config (before the Include) would shadow our drop-in.
    local sshd_config_path = params.sshd_config_path or '/etc/ssh/sshd_config'
    comment_out_directive_in_file(sshd_config_path, directive)

    -- Step 5: Comment out conflicting directives in lexically earlier drop-in
    -- files within the same config directory.
    local sshd_config_d_path = params.sshd_config_d_path or '/etc/ssh/sshd_config.d'
    local dir_attr = _dependencies.lfs_attributes and _dependencies.lfs_attributes(sshd_config_d_path)
    if dir_attr and dir_attr.mode == 'directory' then
        local config_basename = config_path:match('[^/]+$') or ''
        for name in _dependencies.lfs_dir(sshd_config_d_path) do
            if name ~= '.' and name ~= '..' and name < config_basename and name:match('%.conf$') then
                local drop_path = sshd_config_d_path .. '/' .. name
                comment_out_directive_in_file(drop_path, directive)
            end
        end
    end

    return true
end

return M
