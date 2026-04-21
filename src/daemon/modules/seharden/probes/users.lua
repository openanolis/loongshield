local lfs = require('lfs')
local account_files = require('seharden.account_files')
local user_defaults = require('seharden.user_defaults')

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
    return user_defaults.get_useradd_defaults(
        _dependencies.io_popen,
        _dependencies.io_open,
        _dependencies.useradd_defaults_path)
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
        uid_min = user_defaults.read_uid_min(_dependencies.io_open, _dependencies.login_defs_path)
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
