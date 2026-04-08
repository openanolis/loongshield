local log = require('runtime.log')
local text = require('seharden.text')
local M = {}

local _default_dependencies = {
    io_popen = io.popen,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
end

M._test_set_dependencies()

local function get_all_packages()
    log.debug("Loading installed package list...")
    local handle = _dependencies.io_popen("rpm -qa --qf '%{NAME}\\n'")
    if not handle then
        log.error("Failed to execute 'rpm -qa' command.")
        return nil, "Failed to execute 'rpm -qa' command."
    end

    local packages = {}
    for line in handle:lines() do
        packages[line] = true
    end

    local ok, status, code = handle:close()
    if not ok or code ~= 0 then
        log.error("The 'rpm -qa' command failed with exit code: %s", tostring(code))
        return nil, string.format("The 'rpm -qa' command failed with exit code: %s", tostring(code))
    end

    return packages
end

local function match_pattern(pattern, name)
    local ok, res = pcall(string.match, name, text.glob_to_pattern(pattern))
    if not ok then
        log.warn("Pattern match failed for '%s': %s", pattern, tostring(res))
        return false
    end
    return res ~= nil
end

function M.get_installed(params)
    if not params or not params.name then
        return nil, "Probe 'packages.get_installed' requires a 'name' parameter."
    end

    local pattern = params.name

    if not pattern:match("[*?%[]") then
        log.debug("Performing fast cache lookup for package '%s'", pattern)
        local all_pkgs, err = get_all_packages()
        if not all_pkgs then
            return nil, err
        end
        if all_pkgs[pattern] then
            return { count = 1, details = { { name = pattern } } }
        else
            return { count = 0, details = {} }
        end
    else
        local found_packages = {}
        local all_pkgs, err = get_all_packages()
        if not all_pkgs then
            return nil, err
        end
        if pattern:match("^gpg%-pubkey%-") then
            if all_pkgs["gpg-pubkey"] then
                return { count = 1, details = { { name = "gpg-pubkey" } } }
            end
            return { count = 0, details = {} }
        end
        for pkg_name, _ in pairs(all_pkgs) do
            if match_pattern(pattern, pkg_name) then
                table.insert(found_packages, { name = pkg_name })
            end
        end
        return { count = #found_packages, details = found_packages }
    end
end

return M
