local log = require('runtime.log')
local package_inventory = require('seharden.shared.package_inventory')
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
    return package_inventory.read_installed_index(_dependencies, "packages.get_installed")
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
        local installed_names = {}
        for pkg_name in pairs(all_pkgs) do
            installed_names[#installed_names + 1] = pkg_name
        end
        table.sort(installed_names)

        local matches, match_err = package_inventory.find_matching_names(
            pattern,
            installed_names,
            "packages.get_installed"
        )
        if not matches then
            log.warn("Pattern match failed for '%s': %s", pattern, tostring(match_err))
            return nil, match_err
        end

        for _, pkg_name in ipairs(matches) do
            table.insert(found_packages, { name = pkg_name })
        end
        return { count = #found_packages, details = found_packages }
    end
end

return M
