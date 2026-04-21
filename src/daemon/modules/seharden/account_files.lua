local log = require('runtime.log')

local M = {}

local NON_LOGIN_SHELLS = {
    ["/bin/false"] = true,
    ["/bin/nologin"] = true,
    ["/usr/bin/false"] = true,
    ["/usr/sbin/nologin"] = true,
    ["/sbin/nologin"] = true,
    ["/usr/bin/nologin"] = true,
}

local function split_colon_fields(line)
    local parts = {}
    for part in (line .. ":"):gmatch("(.-):") do
        parts[#parts + 1] = part
    end
    return parts
end

local function read_entries(io_open, path, min_fields)
    local entries = {}
    local file = io_open(path, "r")
    if not file then
        log.warn("Could not open %s for reading.", path)
        return nil, string.format("Could not open %s for reading.", path)
    end

    for line in file:lines() do
        if not line:match("^#") then
            local parts = split_colon_fields(line)
            if #parts >= min_fields then
                entries[#entries + 1] = parts
            end
        end
    end
    file:close()
    return entries
end

function M.read_passwd(io_open, path)
    return read_entries(io_open, path, 7)
end

function M.read_shadow(io_open, path)
    return read_entries(io_open, path, 8)
end

function M.is_login_shell_user(user, shell)
    return user ~= "nfsnobody" and not NON_LOGIN_SHELLS[shell]
end

function M.build_real_user(parts)
    local user, uid, gid, home, shell = parts[1], parts[3], parts[4], parts[6], parts[7]
    if not M.is_login_shell_user(user, shell) then
        return nil
    end

    return {
        user = user,
        user_uid = tonumber(uid),
        user_gid = tonumber(gid),
        home = home,
    }
end

function M.build_shadow_entry(parts)
    return {
        user = parts[1],
        pass_min_days = tonumber(parts[4]),
        pass_max_days = tonumber(parts[5]),
        pass_warn_age = tonumber(parts[6]),
        inactive = tonumber(parts[7]),
    }
end

function M.index_login_shell_users(passwd_parts)
    local users = {}
    for _, parts in ipairs(passwd_parts) do
        local user = parts[1]
        local shell = parts[7]
        if M.is_login_shell_user(user, shell) then
            users[user] = true
        end
    end
    return users
end

return M
