local text = require('seharden.text')

local M = {}

function M.read_installed_names(deps, context)
    local handle = deps.io_popen("rpm -qa --qf '%{NAME}\\n'", "r")
    if not handle then
        return nil, string.format("%s: failed to execute 'rpm -qa'", context)
    end

    local packages = {}
    for line in handle:lines() do
        if line ~= "" then
            packages[#packages + 1] = line
        end
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil, string.format("%s: rpm -qa failed with exit %s", context, tostring(code))
    end

    table.sort(packages)
    return packages
end

function M.read_installed_index(deps, context)
    local packages, err = M.read_installed_names(deps, context)
    if not packages then
        return nil, err
    end

    local index = {}
    for _, package_name in ipairs(packages) do
        index[package_name] = true
    end

    return index
end

function M.compile_glob(pattern, context)
    local matcher = text.glob_to_pattern(pattern)
    local ok = pcall(string.match, "", matcher)
    if not ok then
        return nil, string.format("%s: invalid package pattern '%s'", context, tostring(pattern))
    end
    return matcher
end

function M.find_matching_names(pattern, packages, context)
    local matcher, err = M.compile_glob(pattern, context)
    if not matcher then
        return nil, err
    end

    return M.match_names(matcher, packages)
end

function M.match_names(matcher, packages)
    local matches = {}
    for _, package_name in ipairs(packages) do
        if package_name:match(matcher) then
            matches[#matches + 1] = package_name
        end
    end

    return matches
end

return M
