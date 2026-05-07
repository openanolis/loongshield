local lfs = require('lfs')
local fs = require('fs')
local account_files = require('seharden.shared.account_files')
local comparators = require('seharden.comparators')
local user_defaults = require('seharden.shared.user_defaults')

local M = {}

local _default_dependencies = {
    io_open = io.open,
    io_popen = io.popen,
    lfs_attributes = lfs.attributes,
    lfs_symlinkattributes = lfs.symlinkattributes,
    lfs_dir = lfs.dir,
    fs_stat = fs.stat,
    passwd_path = "/etc/passwd",
    shadow_path = "/etc/shadow",
    group_path = "/etc/group",
    shells_path = "/etc/shells",
    login_defs_path = "/etc/login.defs",
    useradd_defaults_path = "/etc/default/useradd",
    os_time = os.time,
}

local _dependencies = {}

local function octal(value)
    return tonumber(value, 8)
end

local DEFAULT_DOTFILE_MAX_MODE = octal("644")
local STRICT_DOTFILE_MAX_MODES = {
    [".bash_history"] = octal("600"),
    [".netrc"] = octal("600"),
}
local FORBIDDEN_DOTFILES = {
    [".forward"] = true,
    [".rhosts"] = true,
}
local GID_ZERO_EXCLUDED_USERS = {
    sync = true,
    shutdown = true,
    halt = true,
    operator = true,
}
local SYSTEM_SHELL_EXCLUDED_USERS = {
    root = true,
    halt = true,
    sync = true,
    shutdown = true,
    nfsnobody = true,
}

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

local function trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

local function read_group_entries()
    local group_entries, err = account_files.read_group(_dependencies.io_open, _dependencies.group_path)
    if not group_entries then
        return nil, err
    end
    return group_entries
end

local function unavailable_result(check, path, err)
    return {
        available = false,
        compliant = false,
        count = 1,
        check = check,
        details = {
            {
                path = path,
                reason = "evidence_unavailable",
                error = err,
            }
        }
    }
end

local function shadow_password_by_user(shadow_entries)
    local index = {}
    for _, parts in ipairs(shadow_entries or {}) do
        index[parts[1]] = parts[2]
    end
    return index
end

local function password_is_locked(password)
    return type(password) == "string" and password:match("^[!*]") ~= nil
end

local function password_is_set_or_locked(password)
    if type(password) ~= "string" or password == "" then
        return false
    end
    return password_is_locked(password) or password:match("^%$.*%$") ~= nil
end

local function load_valid_shells()
    local file = _dependencies.io_open(_dependencies.shells_path, "r")
    if not file then
        return nil, string.format("Could not open %s for reading.", _dependencies.shells_path)
    end

    local shells = {}
    local nologin_entries = {}
    for line in file:lines() do
        local active = trim(line:gsub("%s+#.*$", ""))
        if active ~= "" and not active:match("^#") and active:sub(1, 1) == "/" then
            local basename = active:match("([^/]+)$") or active
            if basename == "nologin" then
                nologin_entries[#nologin_entries + 1] = active
            else
                shells[active] = true
            end
        end
    end
    file:close()

    return shells, nil, nologin_entries
end

local function path_from_root_env()
    local handle = _dependencies.io_popen("sudo -Hiu root env 2>/dev/null", "r")
    if not handle then
        return nil, "Failed to execute root environment probe."
    end

    local root_path
    for line in handle:lines() do
        local value = line:match("^PATH=(.*)$")
        if value then
            root_path = value
        end
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil, string.format("Root environment probe failed with exit %s.", tostring(code))
    end

    if not root_path then
        return nil, "Root PATH was not present in the root environment."
    end
    return root_path
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

function M.inspect_future_password_changes(params)
    params = params or {}
    local shadow_parts, err = account_files.read_shadow(_dependencies.io_open, _dependencies.shadow_path)
    if not shadow_parts then
        return unavailable_result("future_password_changes", _dependencies.shadow_path, err)
    end

    local now_days = math.floor((tonumber(params.now) or _dependencies.os_time()) / 86400)
    local details = {}

    for _, parts in ipairs(shadow_parts) do
        local password = parts[2] or ""
        local last_change_days = tonumber(parts[3])
        if password:match("^%$.*%$") and last_change_days and last_change_days > now_days then
            details[#details + 1] = {
                user = parts[1],
                last_change_days = last_change_days,
                now_days = now_days,
                reason = "last_change_in_future",
            }
        end
    end

    return {
        available = true,
        compliant = #details == 0,
        count = #details,
        details = details,
    }
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

function M.inspect_identity(params)
    params = params or {}
    local check = params.check
    if check ~= "uid_zero" and check ~= "gid_zero_users" and check ~= "gid_zero_groups" then
        return nil, "Probe 'users.inspect_identity' requires check to be one of: uid_zero, gid_zero_users, gid_zero_groups."
    end

    local details = {}

    if check == "gid_zero_groups" then
        local group_entries, group_err = read_group_entries()
        if not group_entries then
            return unavailable_result(check, _dependencies.group_path, group_err)
        end

        local root_group_gid_zero = false
        local non_root_gid_zero_group_count = 0
        for _, parts in ipairs(group_entries) do
            local name = parts[1]
            local gid = tonumber(parts[3])
            if name == "root" and gid == 0 then
                root_group_gid_zero = true
            elseif gid == 0 then
                non_root_gid_zero_group_count = non_root_gid_zero_group_count + 1
                details[#details + 1] = { group = name, gid = gid, reason = "non_root_gid_zero_group" }
            end
        end
        if not root_group_gid_zero then
            details[#details + 1] = { group = "root", reason = "root_group_gid_not_zero" }
        end

        return {
            available = true,
            compliant = root_group_gid_zero and non_root_gid_zero_group_count == 0,
            check = check,
            root_group_gid_zero = root_group_gid_zero,
            non_root_gid_zero_group_count = non_root_gid_zero_group_count,
            count = #details,
            details = details,
        }
    end

    local passwd_entries, passwd_err = account_files.read_passwd(_dependencies.io_open, _dependencies.passwd_path)
    if not passwd_entries then
        return unavailable_result(check, _dependencies.passwd_path, passwd_err)
    end

    local root_uid_zero = false
    local root_gid_zero = false
    local non_root_uid_zero_count = 0
    local non_root_gid_zero_count = 0

    for _, parts in ipairs(passwd_entries) do
        local user = parts[1]
        local uid = tonumber(parts[3])
        local gid = tonumber(parts[4])

        if user == "root" then
            root_uid_zero = uid == 0
            root_gid_zero = gid == 0
        elseif uid == 0 then
            non_root_uid_zero_count = non_root_uid_zero_count + 1
            details[#details + 1] = { user = user, uid = uid, reason = "non_root_uid_zero" }
        elseif gid == 0 and not GID_ZERO_EXCLUDED_USERS[user] then
            non_root_gid_zero_count = non_root_gid_zero_count + 1
            details[#details + 1] = { user = user, gid = gid, reason = "non_root_gid_zero" }
        end
    end

    if check == "uid_zero" and not root_uid_zero then
        details[#details + 1] = { user = "root", reason = "root_uid_not_zero" }
    elseif check == "gid_zero_users" and not root_gid_zero then
        details[#details + 1] = { user = "root", reason = "root_gid_not_zero" }
    end

    return {
        available = true,
        compliant = check == "uid_zero"
            and root_uid_zero and non_root_uid_zero_count == 0
            or check == "gid_zero_users"
            and root_gid_zero and non_root_gid_zero_count == 0,
        check = check,
        root_uid_zero = root_uid_zero,
        root_gid_zero = root_gid_zero,
        non_root_uid_zero_count = non_root_uid_zero_count,
        non_root_gid_zero_count = non_root_gid_zero_count,
        count = #details,
        details = details,
    }
end

function M.inspect_root_access()
    local shadow_parts, err = account_files.read_shadow(_dependencies.io_open, _dependencies.shadow_path)
    if not shadow_parts then
        return unavailable_result("root_access", _dependencies.shadow_path, err)
    end

    local root_password
    for _, parts in ipairs(shadow_parts) do
        if parts[1] == "root" then
            root_password = parts[2]
            break
        end
    end

    local controlled = password_is_set_or_locked(root_password)
    return {
        available = true,
        controlled = controlled,
        password_set = type(root_password) == "string" and root_password:match("^%$.*%$") ~= nil,
        locked = password_is_locked(root_password),
        count = controlled and 0 or 1,
        details = controlled and {} or {
            { user = "root", reason = root_password == nil and "root_missing" or "root_password_not_set_or_locked" }
        },
    }
end

function M.inspect_root_path(params)
    params = params or {}
    local root_path = params.path
    if not root_path then
        local err
        root_path, err = path_from_root_env()
        if not root_path then
            return unavailable_result("root_path", "root_environment", err)
        end
    end

    local details = {}
    for segment in (root_path .. ":"):gmatch("(.-):") do
        if segment == "" then
            details[#details + 1] = { path = segment, reason = "empty_path_segment" }
        elseif segment == "." then
            details[#details + 1] = { path = segment, reason = "current_directory" }
        elseif segment:sub(1, 1) ~= "/" then
            details[#details + 1] = { path = segment, reason = "relative_path" }
        else
            local attr = _dependencies.lfs_attributes(segment)
            if not attr or attr.mode ~= "directory" then
                details[#details + 1] = { path = segment, reason = "not_directory" }
            else
                local stat = _dependencies.fs_stat(segment)
                if not stat then
                    details[#details + 1] = { path = segment, reason = "stat_failed" }
                else
                    local uid = stat:uid()
                    local mode = stat:mode()
                    if uid ~= 0 then
                        details[#details + 1] = { path = segment, reason = "not_root_owned", uid = uid }
                    end
                    if not comparators.mode_is_no_more_permissive(mode, octal("755")) then
                        details[#details + 1] = {
                            path = segment,
                            reason = "mode_too_permissive",
                            mode = mode,
                            expected = octal("755"),
                        }
                    end
                end
            end
        end
    end

    return {
        available = true,
        compliant = #details == 0,
        path = root_path,
        count = #details,
        details = details,
    }
end

function M.inspect_shells(params)
    params = params or {}
    local valid_shells, err, nologin_entries = load_valid_shells()
    if not valid_shells then
        return unavailable_result(params.check or "shells", _dependencies.shells_path, err)
    end

    if params.check == "nologin_absent" then
        local details = {}
        for _, shell_path in ipairs(nologin_entries or {}) do
            details[#details + 1] = {
                path = _dependencies.shells_path,
                shell = shell_path,
                reason = "nologin_listed",
            }
        end
        return {
            available = true,
            compliant = #details == 0,
            count = #details,
            valid_shells = valid_shells,
            details = details,
        }
    end

    return nil, "Probe 'users.inspect_shells' requires check='nologin_absent'."
end

function M.inspect_system_account_shells(params)
    params = params or {}
    local valid_shells, shell_err = load_valid_shells()
    if not valid_shells then
        return unavailable_result("system_account_shells", _dependencies.shells_path, shell_err)
    end

    local uid_min = tonumber(params.uid_min) or user_defaults.read_uid_min(_dependencies.io_open, _dependencies.login_defs_path)
    local passwd_entries, passwd_err = account_files.read_passwd(_dependencies.io_open, _dependencies.passwd_path)
    if not passwd_entries then
        return unavailable_result("system_account_shells", _dependencies.passwd_path, passwd_err)
    end

    local details = {}
    for _, parts in ipairs(passwd_entries) do
        local user = parts[1]
        local uid = tonumber(parts[3])
        local shell = parts[7]
        if uid and not SYSTEM_SHELL_EXCLUDED_USERS[user]
            and (uid < uid_min or uid == 65534)
            and valid_shells[shell] then
            details[#details + 1] = {
                user = user,
                uid = uid,
                shell = shell,
                reason = "system_account_has_valid_shell",
            }
        end
    end

    return {
        available = true,
        compliant = #details == 0,
        count = #details,
        uid_min = uid_min,
        details = details,
    }
end

function M.inspect_nonlogin_accounts_locked()
    local valid_shells, shell_err = load_valid_shells()
    if not valid_shells then
        return unavailable_result("nonlogin_accounts_locked", _dependencies.shells_path, shell_err)
    end

    local passwd_entries, passwd_err = account_files.read_passwd(_dependencies.io_open, _dependencies.passwd_path)
    if not passwd_entries then
        return unavailable_result("nonlogin_accounts_locked", _dependencies.passwd_path, passwd_err)
    end

    local shadow_entries, shadow_err = account_files.read_shadow(_dependencies.io_open, _dependencies.shadow_path)
    if not shadow_entries then
        return unavailable_result("nonlogin_accounts_locked", _dependencies.shadow_path, shadow_err)
    end

    local shadow_passwords = shadow_password_by_user(shadow_entries)
    local details = {}

    for _, parts in ipairs(passwd_entries) do
        local user = parts[1]
        local shell = parts[7]
        if user ~= "root" and not valid_shells[shell] then
            local password = shadow_passwords[user]
            if not password_is_locked(password) then
                details[#details + 1] = {
                    user = user,
                    shell = shell,
                    reason = password == nil and "shadow_entry_missing" or "account_not_locked",
                }
            end
        end
    end

    return {
        available = true,
        compliant = #details == 0,
        count = #details,
        details = details,
    }
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

local function append_dotfile_failure(details, user, path, reason, actual, expected)
    details[#details + 1] = {
        user = user.user,
        path = path,
        reason = reason,
        actual = actual,
        expected = expected,
    }
end

local function inspect_dotfile(details, warnings, user, path, attr)
    local filename = path:match("([^/]+)$") or path

    if FORBIDDEN_DOTFILES[filename] then
        append_dotfile_failure(details, user, path, "forbidden_file")
        return
    end

    if attr and attr.mode ~= "file" then
        return
    end

    local stat = _dependencies.fs_stat(path)
    if not stat then
        append_dotfile_failure(details, user, path, "stat_failed")
        return
    end

    local max_mode = STRICT_DOTFILE_MAX_MODES[filename] or DEFAULT_DOTFILE_MAX_MODE

    local mode = stat:mode()
    if not comparators.mode_is_no_more_permissive(mode, max_mode) then
        append_dotfile_failure(details, user, path, "mode", mode, max_mode)
    end

    local uid = stat:uid()
    if uid ~= user.user_uid then
        append_dotfile_failure(details, user, path, "owner", uid, user.user_uid)
    end

    local gid = stat:gid()
    if gid ~= user.user_gid then
        append_dotfile_failure(details, user, path, "group", gid, user.user_gid)
    end

    if filename == ".netrc" then
        warnings[#warnings + 1] = {
            user = user.user,
            path = path,
            reason = "netrc_exists",
        }
    end
end

local function scan_dotfiles(details, warnings, user, dir_path, root_dev)
    local iter, dir_obj = _dependencies.lfs_dir(dir_path)
    if not iter then
        append_dotfile_failure(details, user, dir_path, "read_dir_failed")
        return
    end

    for name in iter, dir_obj do
        if name ~= "." and name ~= ".." then
            local path = dir_path .. "/" .. name
            local attr = _dependencies.lfs_symlinkattributes(path)
            if attr and (root_dev == nil or attr.dev == nil or attr.dev == root_dev) then
                if name:match("^%.") then
                    inspect_dotfile(details, warnings, user, path, attr)
                elseif attr.mode == "directory" then
                    scan_dotfiles(details, warnings, user, path, root_dev)
                end
            end
        end
    end
end

function M.inspect_dotfiles(params)
    params = params or {}

    local real_users, err = _get_real_users()
    if not real_users then
        return nil, err
    end

    local details = {}
    local warnings = {}
    local max_users = tonumber(params.max_users) or 1000

    if #real_users > max_users then
        return nil, string.format(
            "Probe 'users.inspect_dotfiles' found %d local interactive users, exceeding max_users=%d.",
            #real_users, max_users)
    end

    for _, user in ipairs(real_users) do
        if type(user.home) == "string" and user.home ~= "" and user.home:sub(1, 1) == "/" then
            local home_attr = _dependencies.lfs_symlinkattributes(user.home)
            if home_attr and home_attr.mode == "directory" then
                scan_dotfiles(details, warnings, user, user.home, home_attr.dev)
            end
        end
    end

    return {
        count = #details,
        details = details,
        warning_count = #warnings,
        warnings = warnings,
    }
end

return M
