local log = require('runtime.log')
local text = require('seharden.text')
local M = {}

local _default_dependencies = {
    os_execute = os.execute,
    io_popen = io.popen,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.os_execute = deps.os_execute or _default_dependencies.os_execute
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
end

M._test_set_dependencies()

local function sanitize_package_name(name)
    if type(name) ~= "string" then return nil end
    -- Reject wildcards and shell metacharacters; allow typical package name chars
    if name:match("[%*%?%;%|%&%$%(%)%`%!%<%>]") then return nil end
    if not name:match("^[%w%.%-_+]+$") then return nil end
    return name
end

local function sanitize_package_pattern(pattern)
    if type(pattern) ~= "string" or pattern == "" then
        return nil
    end
    if pattern:match("[%s%c%;%|%&%$%(%)%`%!%<%>]") then
        return nil
    end
    if not pattern:match("^[%w%.%-%_+%*%?%[%]]+$") then
        return nil
    end
    return pattern
end

local function run(cmd)
    local ok, _, code = _dependencies.os_execute(cmd)
    if ok == true or code == 0 then return true end
    return nil, string.format("command failed (exit %s): %s", tostring(code), cmd)
end

local function get_all_packages()
    local handle = _dependencies.io_popen("rpm -qa --qf '%{NAME}\\n'", "r")
    if not handle then
        return nil, "packages.remove_matching: failed to execute 'rpm -qa'"
    end

    local packages = {}
    for line in handle:lines() do
        if line ~= "" then
            packages[#packages + 1] = line
        end
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil, string.format("packages.remove_matching: rpm -qa failed with exit %s", tostring(code))
    end

    table.sort(packages)
    return packages
end

local function compile_glob_pattern(glob)
    local matcher = text.glob_to_pattern(glob)
    local ok = pcall(string.match, "", matcher)
    if not ok then
        return nil, string.format("packages.remove_matching: invalid package pattern '%s'", tostring(glob))
    end
    return matcher
end

local function find_matching_packages(pattern)
    local matcher, matcher_err = compile_glob_pattern(pattern)
    if not matcher then
        return nil, matcher_err
    end

    local installed, err = get_all_packages()
    if not installed then
        return nil, err
    end

    local matches = {}
    for _, pkg in ipairs(installed) do
        if pkg:match(matcher) then
            local safe_name = sanitize_package_name(pkg)
            if not safe_name then
                return nil, string.format(
                    "packages.remove_matching: installed package name '%s' is not safe to pass to dnf",
                    tostring(pkg))
            end
            matches[#matches + 1] = safe_name
        end
    end

    return matches
end

-- Install a package. params: { name }
function M.install(params)
    if not params or not params.name then
        return nil, "packages.install: requires 'name' parameter"
    end

    local name = sanitize_package_name(params.name)
    if not name then
        return nil, string.format("packages.install: invalid package name '%s'", tostring(params.name))
    end

    log.debug("Enforcer packages.install: dnf install -y %s", name)
    local ok, err = run(string.format("dnf install -y %s 2>&1", name))
    if not ok then return nil, err end
    return true
end

-- Remove a package. params: { name }
function M.remove(params)
    if not params or not params.name then
        return nil, "packages.remove: requires 'name' parameter"
    end

    local name = sanitize_package_name(params.name)
    if not name then
        return nil, string.format("packages.remove: invalid package name '%s'", tostring(params.name))
    end

    log.debug("Enforcer packages.remove: dnf remove -y %s", name)
    local ok, err = run(string.format("dnf remove -y %s 2>&1", name))
    if not ok then return nil, err end
    return true
end

-- Remove all installed packages matching a safe glob pattern. Idempotent:
-- no-op when the pattern matches no installed packages.
-- params: { pattern }
function M.remove_matching(params)
    if not params or not params.pattern then
        return nil, "packages.remove_matching: requires 'pattern' parameter"
    end

    local pattern = sanitize_package_pattern(params.pattern)
    if not pattern then
        return nil, string.format("packages.remove_matching: invalid package pattern '%s'", tostring(params.pattern))
    end

    local matches, err = find_matching_packages(pattern)
    if not matches then
        return nil, err
    end

    if #matches == 0 then
        log.debug("packages.remove_matching: no installed packages matched '%s', skipping.", pattern)
        return true
    end

    log.debug("Enforcer packages.remove_matching: dnf remove -y %s", table.concat(matches, " "))
    local ok, run_err = run(string.format("dnf remove -y %s 2>&1", table.concat(matches, " ")))
    if not ok then
        return nil, run_err
    end
    return true
end

return M
