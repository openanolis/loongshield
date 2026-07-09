local M = {}

function M.parse_policy_string(policy_str)
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

    local subpolicies = {}
    for index = 2, #parts do
        subpolicies[#subpolicies + 1] = parts[index]
    end

    return parts[1], subpolicies
end

-- Bare base-policy requests are exact. DEFAULT subpolicy requests preserve
-- stronger/site-local current bases, but move LEGACY hosts onto DEFAULT.
function M.build_effective_policy(requested_policy, current_policy_str)
    local requested_base, requested_subs = M.parse_policy_string(requested_policy)

    if not current_policy_str or current_policy_str == '' then
        return requested_policy
    end

    local current_base, current_subs = M.parse_policy_string(current_policy_str)
    if not current_base then
        return requested_policy
    end

    if #requested_subs == 0 then
        return requested_policy
    end

    local result_base = requested_base
    if requested_base == 'DEFAULT' and current_base ~= 'DEFAULT' and current_base ~= 'LEGACY' then
        result_base = current_base
    end

    local seen = {}
    local merged_subs = {}
    for _, subpolicy in ipairs(current_subs) do
        if not seen[subpolicy] then
            merged_subs[#merged_subs + 1] = subpolicy
            seen[subpolicy] = true
        end
    end
    for _, subpolicy in ipairs(requested_subs) do
        if not seen[subpolicy] then
            merged_subs[#merged_subs + 1] = subpolicy
            seen[subpolicy] = true
        end
    end

    local result = result_base
    for _, subpolicy in ipairs(merged_subs) do
        result = result .. ':' .. subpolicy
    end

    return result
end

return M
