local log = require('runtime.log')
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

-- Parse a policy string like "BASE:SUB1:SUB2" into base and subpolicies.
local function parse_policy_string(policy_str)
    policy_str = tostring(policy_str or ''):gsub('%s+', '')
    if policy_str == '' then
        return nil, {}
    end
    local parts = {}
    for part in policy_str:gmatch('[^:]+') do
        parts[#parts + 1] = part
    end
    if #parts == 0 then
        return nil, {}
    end
    local base = parts[1]
    local subpolicies = {}
    for i = 2, #parts do
        subpolicies[#subpolicies + 1] = parts[i]
    end
    return base, subpolicies
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

-- Merge the requested policy with the host's currently active policy.
-- Preserves the host's existing base policy and appends any missing
-- subpolicies from the requested policy, avoiding silent replacement
-- of site-local or FIPS base policies.
local function build_effective_policy(requested_policy, current_policy_str)
    local _, requested_subs = parse_policy_string(requested_policy)

    if not current_policy_str or current_policy_str == '' then
        return requested_policy
    end

    local current_base, current_subs = parse_policy_string(current_policy_str)
    if not current_base then
        return requested_policy
    end

    -- Collect current subpolicies into a set for deduplication.
    local seen = {}
    for _, sub in ipairs(current_subs) do
        seen[sub] = true
    end

    -- Append only the subpolicies not already active.
    local merged_subs = {}
    for _, sub in ipairs(current_subs) do
        merged_subs[#merged_subs + 1] = sub
    end
    for _, sub in ipairs(requested_subs) do
        if not seen[sub] then
            merged_subs[#merged_subs + 1] = sub
            seen[sub] = true
        end
    end

    local result = current_base
    for _, sub in ipairs(merged_subs) do
        result = result .. ':' .. sub
    end

    return result
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

            local mod_path = modules_dir .. '/' .. mod_name .. '.pmod'

            -- Check if file exists with matching content
            local f_in = _dependencies.io_open(mod_path, 'r')
            local existing_content = nil
            if f_in then
                existing_content = f_in:read('*a')
                f_in:close()
            end

            if existing_content ~= content then
                log.debug("crypto_policy.set_policy: writing module '%s'", mod_path)
                local f_out = _dependencies.io_open(mod_path, 'w')
                if not f_out then
                    return nil, string.format("crypto_policy.set_policy: cannot write '%s'", mod_path)
                end
                f_out:write(content)
                local ok = f_out:close()
                if not ok then
                    return nil, string.format("crypto_policy.set_policy: cannot close '%s'", mod_path)
                end
            end
        end
    end

    -- Detect the host's current active policy and merge subpolicies
    -- to avoid silently replacing an existing FIPS / site-local base.
    local current_policy_path = params.current_policy_path or DEFAULT_CURRENT_POLICY_CONFIG
    local current_policy_str = detect_current_policy(current_policy_path)
    local effective_policy = build_effective_policy(policy, current_policy_str)

    if current_policy_str then
        log.debug('crypto_policy.set_policy: current=%s, requested=%s, effective=%s',
            current_policy_str, policy, effective_policy)
    else
        log.debug('crypto_policy.set_policy: no current policy detected, using requested=%s', policy)
    end

    -- Run update-crypto-policies with the effective (merged) policy
    local cmd = string.format('update-crypto-policies --set %s 2>&1', effective_policy)
    log.debug('crypto_policy.set_policy: %s', cmd)
    return run(cmd)
end

return M
