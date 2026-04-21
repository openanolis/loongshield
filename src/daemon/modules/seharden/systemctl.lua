local M = {}

local SYSTEMCTL_CANDIDATES = {
    "/usr/bin/systemctl",
    "/bin/systemctl",
    "/usr/sbin/systemctl",
    "/sbin/systemctl",
}

function M.sanitize_unit_name(name)
    if type(name) ~= "string" then
        return nil
    end
    if not name:match("^[%w@%._:-]+$") then
        return nil
    end
    return name
end

function M.normalize_unit_name(unit_name)
    local safe_name = M.sanitize_unit_name(unit_name)
    if not safe_name then
        return nil
    end
    if safe_name:match("%.[%w%-]+$") then
        return safe_name
    end
    return safe_name .. ".service"
end

function M.resolve_path(deps)
    for _, path in ipairs(SYSTEMCTL_CANDIDATES) do
        local attr = deps.lfs_attributes(path)
        if attr and attr.mode == "file" then
            return path
        end
    end

    return "systemctl"
end

function M.capture(args, deps, opts)
    opts = opts or {}

    local cmd = M.resolve_path(deps) .. " " .. args
    local stderr_redirect = opts.stderr_redirect
    if stderr_redirect == nil then
        stderr_redirect = "2>/dev/null"
    end
    if stderr_redirect ~= "" then
        cmd = cmd .. " " .. stderr_redirect
    end

    local handle = deps.io_popen(cmd, "r")
    if not handle then
        return nil, nil, nil, cmd
    end

    local out = handle:read("*a") or ""
    local ok, _, code = handle:close()
    return out, ok, code, cmd
end

function M.capture_checked(args, deps, opts)
    local out, ok, code, cmd = M.capture(args, deps, opts)
    if not out then
        return nil, "failed to run: " .. cmd
    end
    if ok == true or code == 0 then
        return true, out
    end

    local trimmed = out:match("^%s*(.-)%s*$")
    if trimmed == "" then
        trimmed = string.format("systemctl failed (exit %s): %s", tostring(code), cmd)
    end
    return nil, trimmed
end

function M.parse_show_properties(out)
    local properties = {}

    for line in ((out or "") .. "\n"):gmatch("([^\n]*)\n") do
        local key, value = line:match("^([%w]+)=(.*)$")
        if key then
            properties[key] = value
        end
    end

    return properties
end

return M
