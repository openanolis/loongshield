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

local function shell_quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function read_command_lines(command)
    local handle = _dependencies.io_popen(command, "r")
    if not handle then
        return nil, string.format("failed to execute '%s'", command)
    end

    local lines = {}
    for line in handle:lines() do
        if line ~= "" then
            lines[#lines + 1] = line
        end
    end

    local ok, _, code = handle:close()
    if ok == true and (code == nil or code == 0) then
        return lines, nil, 0
    end

    return lines, nil, code or 1
end

local function parse_rpm_query_line(line)
    local name, epoch, version, release, arch = tostring(line or ""):match("^([^\t]+)\t([^\t]*)\t([^\t]+)\t([^\t]+)\t([^\t]+)$")
    if not name then
        return nil
    end

    local evr = version .. "-" .. release
    if epoch and epoch ~= "" and epoch ~= "(none)" and epoch ~= "0" then
        evr = epoch .. ":" .. evr
    end

    return {
        name = name,
        epoch = epoch,
        version = version,
        release = release,
        arch = arch,
        evr = evr,
    }
end

local function normalize_epoch(epoch)
    local number = tonumber(epoch)
    return number or 0
end

local function parse_evr(evr)
    local epoch, version_release = tostring(evr or ""):match("^([^:]+):(.+)$")
    if not version_release then
        version_release = tostring(evr or "")
    end

    local version, release = version_release:match("^([^-]+)%-(.+)$")
    if not version then
        version = version_release
        release = ""
    end

    return {
        epoch = normalize_epoch(epoch),
        version = version,
        release = release,
    }
end

local function is_alnum(char)
    return char and char:match("[%a%d]") ~= nil
end

local function skip_separators(value, index)
    while index <= #value do
        local char = value:sub(index, index)
        if is_alnum(char) or char == "~" then
            break
        end
        index = index + 1
    end
    return index
end

local function read_segment(value, index)
    local numeric = value:sub(index, index):match("%d") ~= nil
    local finish = index

    while finish <= #value do
        local char = value:sub(finish, finish)
        if numeric then
            if not char:match("%d") then
                break
            end
        elseif not char:match("%a") then
            break
        end
        finish = finish + 1
    end

    return value:sub(index, finish - 1), numeric, finish
end

local function compare_numeric_segments(left, right)
    left = left:gsub("^0+", "")
    right = right:gsub("^0+", "")
    if left == "" then
        left = "0"
    end
    if right == "" then
        right = "0"
    end

    if #left ~= #right then
        return #left > #right and 1 or -1
    end
    if left == right then
        return 0
    end
    return left > right and 1 or -1
end

local function rpmvercmp(left, right)
    left = tostring(left or "")
    right = tostring(right or "")
    if left == right then
        return 0
    end

    local left_index = 1
    local right_index = 1

    while left_index <= #left or right_index <= #right do
        left_index = skip_separators(left, left_index)
        right_index = skip_separators(right, right_index)

        local left_tilde = left:sub(left_index, left_index) == "~"
        local right_tilde = right:sub(right_index, right_index) == "~"
        if left_tilde or right_tilde then
            if not left_tilde then
                return 1
            end
            if not right_tilde then
                return -1
            end
            left_index = left_index + 1
            right_index = right_index + 1
        end

        left_index = skip_separators(left, left_index)
        right_index = skip_separators(right, right_index)

        local left_done = left_index > #left
        local right_done = right_index > #right
        if left_done or right_done then
            if left_done and right_done then
                return 0
            end
            return left_done and -1 or 1
        end

        local left_segment, left_numeric, next_left = read_segment(left, left_index)
        local right_segment, right_numeric, next_right = read_segment(right, right_index)

        if left_numeric ~= right_numeric then
            return left_numeric and 1 or -1
        end

        local result
        if left_numeric then
            result = compare_numeric_segments(left_segment, right_segment)
        elseif left_segment == right_segment then
            result = 0
        else
            result = left_segment > right_segment and 1 or -1
        end

        if result ~= 0 then
            return result
        end

        left_index = next_left
        right_index = next_right
    end

    return 0
end

local function evr_meets_minimum(installed_evr, minimum_evr)
    local installed = parse_evr(installed_evr)
    local minimum = parse_evr(minimum_evr)

    if installed.epoch ~= minimum.epoch then
        return installed.epoch > minimum.epoch
    end

    local version_cmp = rpmvercmp(installed.version, minimum.version)
    if version_cmp ~= 0 then
        return version_cmp > 0
    end

    return rpmvercmp(installed.release, minimum.release) >= 0
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

function M.inspect_min_version(params)
    if not params or not params.name or not params.minimum then
        return nil, "Probe 'packages.inspect_min_version' requires 'name' and 'minimum' parameters."
    end

    local name = tostring(params.name)
    local minimum = tostring(params.minimum)
    local metadata_command = "rpm -q --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\\n' "
        .. shell_quote(name) .. " 2>/dev/null"
    local metadata_lines, metadata_err, metadata_code = read_command_lines(metadata_command)
    if not metadata_lines then
        return nil, metadata_err
    end

    local result = {
        available = true,
        installed = false,
        version_ok = false,
        name = name,
        minimum = minimum,
        details = {},
    }

    if metadata_code ~= 0 then
        if metadata_code ~= 1 then
            result.available = false
            result.error = string.format("rpm package query failed with exit %s", tostring(metadata_code))
        end
        return result
    end

    local package_info = parse_rpm_query_line(metadata_lines[1])
    if not package_info then
        result.available = false
        result.error = "rpm package query returned an unexpected format"
        return result
    end

    result.installed = true
    result.installed_version = package_info.version
    result.installed_release = package_info.release
    result.installed_epoch = package_info.epoch
    result.installed_arch = package_info.arch
    result.installed_evr = package_info.evr
    result.details[1] = package_info

    result.version_ok = evr_meets_minimum(package_info.evr, minimum)

    return result
end

return M
