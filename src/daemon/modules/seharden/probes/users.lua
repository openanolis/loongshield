local lfs = require('lfs')
local account_files = require('seharden.account_files')
local log = require('runtime.log')

local M = {}

local _default_dependencies = {
    io_open = io.open,
    io_popen = io.popen,
    lfs_attributes = lfs.attributes,
    passwd_path = "/etc/passwd",
    shadow_path = "/etc/shadow",
    login_defs_path = "/etc/login.defs",
    useradd_defaults_path = "/etc/default/useradd",
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function _get_uid_min_fallback()
    local file = _dependencies.io_open(_dependencies.login_defs_path, "r")
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

local function _parse_useradd_defaults_lines(lines_iter)
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

local function _parse_useradd_defaults_file()
    local file = _dependencies.io_open(_dependencies.useradd_defaults_path, "r")
    if not file then
        return nil
    end

    local defaults = _parse_useradd_defaults_lines(file:lines())
    file:close()
    return defaults
end

local function _get_real_users()
    local user_entries, err = account_files.read_passwd(_dependencies.io_open, _dependencies.passwd_path)
    if not user_entries then return nil, err end

    local real_users = {}
    for _, parts in ipairs(user_entries) do
        local user = account_files.build_real_user(parts)
        if user then
            table.insert(real_users, user)
        end
    end
    return real_users
end

function M.find_files(params)
    if not params or not params.filename then
        return nil, "Probe 'users.find_files' requires a 'filename' parameter."
    end

    local sane_filename = ""
    for part in params.filename:gmatch("([^/]+)") do
        sane_filename = part
    end

    if sane_filename == "" or sane_filename:match("%.%.") then
        return nil, string.format("Invalid 'filename' parameter: '%s'", params.filename)
    end

    local real_users, err = _get_real_users()
    if not real_users then
        return nil, err
    end

    local found_list = {}
    for _, u in ipairs(real_users) do
        local path = u.home .. "/" .. sane_filename
        local attr = _dependencies.lfs_attributes(path)
        if attr and attr.mode == 'file' then
            table.insert(found_list, { user = u.user, path = path })
        end
    end
    return { count = #found_list, details = found_list }
end

function M.get_shadow_entries()
    local shadow_parts, err = account_files.read_shadow(_dependencies.io_open, _dependencies.shadow_path)
    if not shadow_parts then return nil, err end

    local shadow_entries = {}
    for _, parts in ipairs(shadow_parts) do
        -- Filter out locked accounts (password field starts with ! or *)
        if not parts[2]:match("^[!*]") then
            table.insert(shadow_entries, account_files.build_shadow_entry(parts))
        end
    end
    return shadow_entries
end

function M.get_login_shadow_entries()
    local shadow_parts, err = account_files.read_shadow(_dependencies.io_open, _dependencies.shadow_path)
    if not shadow_parts then return nil, err end

    local passwd_parts, passwd_err = account_files.read_passwd(_dependencies.io_open, _dependencies.passwd_path)
    if not passwd_parts then return nil, passwd_err end

    local login_shell_users = account_files.index_login_shell_users(passwd_parts)

    local shadow_entries = {}
    for _, parts in ipairs(shadow_parts) do
        if login_shell_users[parts[1]] and not parts[2]:match("^[!*]") then
            table.insert(shadow_entries, account_files.build_shadow_entry(parts))
        end
    end

    return shadow_entries
end

function M.get_defaults()
    local handle = _dependencies.io_popen("useradd -D 2>/dev/null", "r")
    if handle then
        local defaults = _parse_useradd_defaults_lines(handle:lines()) or {}
        local ok, _, code = handle:close()
        if ok == true and (code == nil or code == 0) then
            return defaults
        end

        local fallback = _parse_useradd_defaults_file()
        if fallback then
            return fallback
        end

        log.warn("The 'useradd -D' command failed with exit code: %s", tostring(code))
        return nil, string.format("The 'useradd -D' command failed with exit code: %s",
            tostring(code))
    end

    local fallback = _parse_useradd_defaults_file()
    if fallback then
        return fallback
    end

    log.warn("Failed to execute 'useradd -D' command.")
    return nil, "Failed to execute 'useradd -D' command."
end

function M.get_all(params)
    return _get_real_users()
end

function M.get_existing_home_directories()
    local real_users, err = _get_real_users()
    if not real_users then
        return nil, err
    end

    local details = {}
    for _, user in ipairs(real_users) do
        if type(user.home) == "string" and user.home ~= "" and user.home:sub(1, 1) == "/" then
            local attr = _dependencies.lfs_attributes(user.home)
            if attr and attr.mode == "directory" then
                details[#details + 1] = {
                    user = user.user,
                    path = user.home,
                }
            end
        end
    end

    return {
        count = #details,
        details = details
    }
end

function M.find_interactive_system_accounts(params)
    local uid_min

    if params and params.uid_min ~= nil then
        uid_min = tonumber(params.uid_min)
    else
        uid_min = _get_uid_min_fallback()
    end

    if not uid_min or uid_min < 1 then
        return nil, "Probe 'users.find_interactive_system_accounts' requires a positive 'uid_min' parameter."
    end

    local user_entries, err = account_files.read_passwd(_dependencies.io_open, _dependencies.passwd_path)

    if not user_entries then
        return nil, err
    end

    local details = {}
    for _, parts in ipairs(user_entries) do
        local user = parts[1]
        local uid = tonumber(parts[3])
        local shell = parts[7]

        if uid and uid > 0 and uid < uid_min and account_files.is_login_shell_user(user, shell) then
            details[#details + 1] = {
                user = user,
                uid = uid,
                shell = shell
            }
        end
    end

    return {
        count = #details,
        details = details
    }
end

return M
