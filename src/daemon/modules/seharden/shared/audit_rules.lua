local M = {}

M.AUDIT_UNSET_AUID = 4294967295

function M.canonicalize_permissions(permissions)
    if type(permissions) ~= 'string' or permissions == '' then
        return nil
    end

    local seen = {}
    for char in permissions:gmatch('.') do
        if not char:match('[rwax]') then
            return nil
        end
        seen[char] = true
    end

    local ordered = {}
    for _, char in ipairs({ 'r', 'w', 'a', 'x' }) do
        if seen[char] then
            ordered[#ordered + 1] = char
        end
    end

    return table.concat(ordered)
end

function M.has_permissions(actual, required)
    local present = {}

    for permission in tostring(actual):gmatch('.') do
        if permission:match('[rwax]') then
            present[permission] = true
        end
    end

    for permission in tostring(required):gmatch('.') do
        if permission:match('[rwax]') and not present[permission] then
            return false
        end
    end

    return true
end

function M.line_has_key(line)
    return line:match('%-k%s+%S+') ~= nil or line:match('%-F%s+key=%S+') ~= nil
end

function M.extract_key(line)
    return line:match('%-k%s+(%S+)') or line:match('%-F%s+key=(%S+)')
end

function M.key_matches(line, key, require_key)
    if require_key == false then
        return true
    end
    if key == nil then
        return M.line_has_key(line)
    end
    return M.extract_key(line) == key
end

function M.extract_watch_target(line)
    local watched_path = line:match('^%-w%s+(%S+)')
    if watched_path then
        return watched_path, 'watch'
    end

    watched_path = line:match('%-F%s+path=(%S+)')
    if watched_path then
        return watched_path, 'path'
    end

    watched_path = line:match('%-F%s+dir=(%S+)')
    if watched_path then
        return watched_path, 'dir'
    end
end

function M.extract_watch_permissions(line)
    return (line:match('%-p%s+([rwax]+)') or line:match('%-F%s+perm=([rwax]+)') or '')
end

function M.is_always_exit_rule(line)
    return line:match('^%-a%s+always,exit%f[%s]') ~= nil or line:match('^%-a%s+exit,always%f[%s]') ~= nil
end

function M.line_matches_auid_min(line, threshold)
    for raw_value in line:gmatch('%-F%s+auid>=(%d+)') do
        local numeric_value = tonumber(raw_value)
        if numeric_value and numeric_value <= threshold then
            return true
        end
    end

    return false
end

function M.line_excludes_unset_auid(line)
    return line:match('%-F%s+auid!=unset') ~= nil
        or line:match('%-F%s+auid!=%-1') ~= nil
        or line:match('%-F%s+auid!=' .. M.AUDIT_UNSET_AUID) ~= nil
end

function M.matches_auid_filters(line, auid_min, require_unset_exclusion)
    if auid_min ~= nil and not M.line_matches_auid_min(line, auid_min) then
        return false
    end
    if require_unset_exclusion ~= false and not M.line_excludes_unset_auid(line) then
        return false
    end
    return true
end

function M.line_has_exit(line, expected_exit)
    if expected_exit == nil then
        return true
    end

    local normalized_expected = tostring(expected_exit):gsub('^%-', '')
    for value in line:gmatch('%-F%s+exit=([^%s]+)') do
        if value:gsub('^%-', '') == normalized_expected then
            return true
        end
    end
    return false
end

function M.line_has_field(line, field)
    if type(field) ~= 'table' or not field.name then
        return true
    end

    for value in line:gmatch('%-F%s+' .. tostring(field.name) .. '=([^%s]+)') do
        if field.value == nil or tostring(value) == tostring(field.value) then
            return true
        end
    end
    return false
end

function M.line_has_fields(line, fields)
    for _, field in ipairs(fields or {}) do
        if not M.line_has_field(line, field) then
            return false
        end
    end
    return true
end

local function normalize_comparison(value)
    value = tostring(value or '')
    if value == 'uid!=euid' or value == 'euid!=uid' then
        return 'uid!=euid'
    end
    return value
end

function M.line_has_comparison(line, expected)
    if expected == nil then
        return true
    end

    local normalized_expected = normalize_comparison(expected)
    for value in line:gmatch('%-C%s+([^%s]+)') do
        if normalize_comparison(value) == normalized_expected then
            return true
        end
    end
    return false
end

function M.line_has_any_comparison(line, comparisons)
    if comparisons == nil or #comparisons == 0 then
        return true
    end
    for _, comparison in ipairs(comparisons) do
        if M.line_has_comparison(line, comparison) then
            return true
        end
    end
    return false
end

function M.collect_syscalls(line)
    local syscalls = {}

    for token in line:gmatch('%-S%s+([^%s]+)') do
        for syscall in token:gmatch('([^,]+)') do
            if syscall ~= '' then
                syscalls[syscall] = true
            end
        end
    end

    return syscalls
end

function M.extract_syscall_arch(line)
    return line:match('%-F%s+arch=(%S+)')
end

function M.build_watch_line(params)
    local line = string.format('-w %s -p %s', params.path, params.permissions)
    if params.key then
        line = line .. string.format(' -k %s', params.key)
    end
    return line
end

local function build_comparison_fragment(comparisons_any)
    local parts = {}
    if type(comparisons_any) == 'table' and #comparisons_any > 0 then
        for _, cmp in ipairs(comparisons_any) do
            if type(cmp) == 'string' and cmp ~= '' then
                parts[#parts + 1] = '-C ' .. cmp
            end
        end
    end

    if #parts == 0 then
        return ''
    end
    return ' ' .. table.concat(parts, ' ')
end

local function build_fields_fragment(fields)
    local parts = {}
    if type(fields) == 'table' and #fields > 0 then
        for _, field in ipairs(fields) do
            if type(field) == 'table' and field.name and field.value then
                parts[#parts + 1] = string.format('-F %s=%s', tostring(field.name), tostring(field.value))
            end
        end
    end

    if #parts == 0 then
        return ''
    end
    return ' ' .. table.concat(parts, ' ')
end

local function build_exit_values(exits)
    if type(exits) ~= 'table' or #exits == 0 then
        return nil
    end

    local exit_values = {}
    for _, exit_val in ipairs(exits) do
        exit_values[#exit_values + 1] = tostring(exit_val):gsub('^%-', '')
    end
    return exit_values
end

local function build_auid_fragment(auid_min, include_auid_unset)
    if auid_min and include_auid_unset then
        return string.format(' -F auid>=%d -F auid!=unset', auid_min)
    elseif auid_min then
        return string.format(' -F auid>=%d', auid_min)
    elseif include_auid_unset then
        return ' -F auid!=unset'
    end
    return ''
end

local function build_syscall_rule_fragments(params)
    local syscall_parts = {}
    for _, syscall in ipairs(params.syscalls) do
        syscall_parts[#syscall_parts + 1] = '-S ' .. syscall
    end

    return {
        syscall_fragment = table.concat(syscall_parts, ' '),
        comparison_fragment = build_comparison_fragment(params.comparisons_any),
        fields_fragment = build_fields_fragment(params.fields),
        exit_values = build_exit_values(params.exits),
        auid_fragment = build_auid_fragment(params.auid_min, params.include_auid_unset),
        key_fragment = params.key and string.format(' -k %s', params.key) or '',
    }
end

local function build_syscall_rule_line(arch, fragments, exit_filter)
    local exit_fragment = exit_filter and string.format(' -F exit=-%s', exit_filter) or ''
    return string.format(
        '-a always,exit -F arch=%s %s%s%s%s%s%s',
        arch,
        fragments.syscall_fragment,
        fragments.comparison_fragment,
        fragments.fields_fragment,
        exit_fragment,
        fragments.auid_fragment,
        fragments.key_fragment
    )
end

function M.build_syscall_rule_lines(params)
    local lines = {}
    local fragments = build_syscall_rule_fragments(params)

    local function append_lines(exit_filter)
        for _, arch in ipairs(params.arches) do
            lines[#lines + 1] = build_syscall_rule_line(arch, fragments, exit_filter)
        end
    end

    if fragments.exit_values then
        for _, exit_filter in ipairs(fragments.exit_values) do
            append_lines(exit_filter)
        end
    else
        append_lines(nil)
    end

    return lines
end

function M.build_path_exec_rule_lines(params)
    local lines = {}
    local key_fragment = params.key and string.format(' -k %s', params.key) or ''
    for _, arch in ipairs(params.arches) do
        lines[#lines + 1] =
            string.format('-a always,exit -F arch=%s -F path=%s -F perm=x%s', arch, params.path, key_fragment)
    end
    return lines
end

return M
