local log = require('runtime.log')
local policy_strings = require('seharden.shared.crypto_policy')
local M = {}

local DEFAULT_MODULES_DIR = '/etc/crypto-policies/policies/modules'
local DEFAULT_CURRENT_POLICY_CONFIG = '/etc/crypto-policies/config'

local _default_dependencies = {
    os_execute = os.execute,
    io_open = io.open,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.os_execute = deps.os_execute or _default_dependencies.os_execute
    _dependencies.io_open = deps.io_open or _default_dependencies.io_open
end

M._test_set_dependencies()

local function run(cmd)
    local ok, _, code = _dependencies.os_execute(cmd)
    if ok == true or code == 0 then
        return true
    end
    return nil, string.format('command failed (exit %s): %s', tostring(code), cmd)
end

local function sanitize_policy_token(value, context)
    if type(value) ~= 'string' or value == '' then
        return nil, string.format('crypto_policy.set_policy: invalid %s', context)
    end
    if value:match('[^%w%:%._%-]') then
        return nil,
            string.format("crypto_policy.set_policy: %s '%s' contains invalid characters", context, tostring(value))
    end
    return value
end

local function sanitize_module_content(content)
    if type(content) ~= 'string' then
        return nil
    end
    -- Reject content with shell metacharacters
    if content:match('[%;%|%&%$%(%)%`%!%<%>]') then
        return nil
    end
    return content
end

-- Detect the currently active crypto policy from the config file.
-- Returns the raw policy string (e.g. "DEFAULT:NO-SHA1") or nil on failure.
local function detect_current_policy(config_path)
    config_path = config_path or DEFAULT_CURRENT_POLICY_CONFIG
    local f = _dependencies.io_open(config_path, 'r')
    if not f then
        return nil
    end
    local content = f:read('*l')
    f:close()
    if not content or content == '' then
        return nil
    end
    return content:gsub('^%s+', ''):gsub('%s+$', '')
end

local function read_file(path)
    local file = _dependencies.io_open(path, 'r')
    if not file then
        return nil
    end

    local content = file:read('*a')
    file:close()
    return content
end

local function write_file_if_changed(path, content)
    if read_file(path) == content then
        return true
    end

    log.debug("crypto_policy.set_policy: writing module '%s'", path)
    local file = _dependencies.io_open(path, 'w')
    if not file then
        return nil, string.format("crypto_policy.set_policy: cannot write '%s'", path)
    end

    file:write(content)
    local ok = file:close()
    if not ok then
        return nil, string.format("crypto_policy.set_policy: cannot close '%s'", path)
    end
    return true
end

local function write_module(mod, modules_dir)
    if not mod.name or mod.content == nil then
        return nil, "crypto_policy.set_policy: each module entry requires 'name' and 'content'"
    end

    local mod_name, name_err = sanitize_policy_token(mod.name, 'module name')
    if not mod_name then
        return nil, name_err
    end

    local content = sanitize_module_content(mod.content)
    if not content then
        return nil, string.format("crypto_policy.set_policy: invalid content for module '%s'", mod_name)
    end

    return write_file_if_changed(modules_dir .. '/' .. mod_name .. '.pmod', content)
end

-- Apply a system-wide crypto policy, optionally creating sub-policy module files.
-- Detects the host's currently active base policy and merges requested subpolicies
-- on top, so that an existing FIPS, FUTURE, or site-local base is preserved.
-- params: {
--   policy (required, base policy name, e.g. "DEFAULT" or "DEFAULT:NO-SHA1"),
--   modules (optional array of {name, content}),
--   modules_dir (optional, default "/etc/crypto-policies/policies/modules"),
--   current_policy_path (optional, default "/etc/crypto-policies/config")
-- }
function M.set_policy(params)
    if not params or not params.policy then
        return nil, "crypto_policy.set_policy: requires 'policy' parameter"
    end

    local policy, policy_err = sanitize_policy_token(params.policy, 'policy')
    if not policy then
        return nil, policy_err
    end

    local modules_dir = params.modules_dir or DEFAULT_MODULES_DIR

    -- Create/update module files if specified
    if params.modules then
        for _, mod in ipairs(params.modules) do
            local ok, module_err = write_module(mod, modules_dir)
            if not ok then
                return nil, module_err
            end
        end
    end

    -- Detect the host's current active policy and merge subpolicies
    -- to avoid silently replacing an existing FIPS / site-local base.
    local current_policy_path = params.current_policy_path or DEFAULT_CURRENT_POLICY_CONFIG
    local current_policy_str = detect_current_policy(current_policy_path)
    local effective_policy = policy_strings.build_effective_policy(policy, current_policy_str)

    if current_policy_str then
        log.debug(
            'crypto_policy.set_policy: current=%s, requested=%s, effective=%s',
            current_policy_str,
            policy,
            effective_policy
        )
    else
        log.debug('crypto_policy.set_policy: no current policy detected, using requested=%s', policy)
    end

    -- Run update-crypto-policies with the effective (merged) policy
    local cmd = string.format('update-crypto-policies --set %s 2>&1', effective_policy)
    log.debug('crypto_policy.set_policy: %s', cmd)
    return run(cmd)
end

return M
