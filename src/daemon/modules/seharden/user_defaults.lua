local log = require('runtime.log')

local M = {}

function M.read_uid_min(io_open, path)
    local file = io_open(path, "r")
    if not file then
        return 1000
    end

    for line in file:lines() do
        if not line:match("^%s*#") then
            local value = line:match("^%s*UID_MIN%s+([0-9]+)%s*$")
                or line:match("^%s*UID_MIN%s*=%s*([0-9]+)%s*$")
            if value then
                file:close()
                return tonumber(value)
            end
        end
    end

    file:close()
    return 1000
end

local function parse_useradd_defaults_lines(lines_iter)
    local defaults = {}
    for line in lines_iter do
        if not line:match("^%s*#") and not line:match("^%s*$") then
            local key, value = line:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
            if key and value then
                key = key:match("^%s*(.-)%s*$")
                if key == "INACTIVE" then
                    defaults[key] = tonumber(value)
                else
                    defaults[key] = value
                end
            end
        end
    end

    if not next(defaults) then
        return nil
    end

    return defaults
end

local function parse_useradd_defaults_file(io_open, path)
    local file = io_open(path, "r")
    if not file then
        return nil
    end

    local defaults = parse_useradd_defaults_lines(file:lines())
    file:close()
    return defaults
end

function M.get_useradd_defaults(io_popen, io_open, defaults_path)
    local handle = io_popen("useradd -D 2>/dev/null", "r")
    if handle then
        local defaults = parse_useradd_defaults_lines(handle:lines()) or {}
        local ok, _, code = handle:close()
        if ok == true and (code == nil or code == 0) then
            return defaults
        end

        local fallback = parse_useradd_defaults_file(io_open, defaults_path)
        if fallback then
            return fallback
        end

        log.warn("The 'useradd -D' command failed with exit code: %s", tostring(code))
        return nil, string.format("The 'useradd -D' command failed with exit code: %s",
            tostring(code))
    end

    local fallback = parse_useradd_defaults_file(io_open, defaults_path)
    if fallback then
        return fallback
    end

    log.warn("Failed to execute 'useradd -D' command.")
    return nil, "Failed to execute 'useradd -D' command."
end

return M
