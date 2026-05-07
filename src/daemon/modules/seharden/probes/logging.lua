local account_files = require('seharden.shared.account_files')
local comparators = require('seharden.comparators')
local fs = require('fs')
local lfs = require('lfs')
local log = require('runtime.log')

local M = {}

local _default_dependencies = {
    fs_stat = fs.stat,
    io_open = io.open,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function sorted_dir_entries(path)
    local ok, iter, dir_obj = pcall(_dependencies.lfs_dir, path)
    if not ok or not iter then
        return nil, tostring(iter or dir_obj)
    end

    local entries = {}
    for name in iter, dir_obj do
        if name ~= "." and name ~= ".." then
            entries[#entries + 1] = name
        end
    end
    table.sort(entries)
    return entries
end

local function collect_regular_files(path, out)
    local attr = _dependencies.lfs_attributes(path)
    if not attr then
        return true
    end
    if attr.mode == "file" then
        out[#out + 1] = path
        return true
    end
    if attr.mode ~= "directory" then
        return true
    end

    local entries, err = sorted_dir_entries(path)
    if not entries then
        return nil, string.format("Could not enumerate log directory '%s': %s", path, tostring(err))
    end

    for _, entry in ipairs(entries) do
        local ok, child_err = collect_regular_files(path .. "/" .. entry, out)
        if not ok then
            return nil, child_err
        end
    end
    return true
end

local function read_name_index(path, min_fields, id_field)
    local entries, err
    if min_fields == 7 then
        entries, err = account_files.read_passwd(_dependencies.io_open, path)
    else
        entries, err = account_files.read_group(_dependencies.io_open, path)
    end
    if not entries then
        return nil, err
    end

    local by_id = {}
    for _, parts in ipairs(entries) do
        local id = tonumber(parts[id_field])
        if id then
            by_id[id] = parts[1]
        end
    end
    return by_id
end

local function set_from_list(values)
    local set = {}
    for _, value in ipairs(values or {}) do
        set[value] = true
    end
    return set
end

local function basename(path)
    return tostring(path):match("([^/]+)$") or tostring(path)
end

local function policy_for_path(path)
    local name = basename(path)

    if name == "lastlog" or name == "wtmp" then
        return {
            name = "login_record",
            max_mode = tonumber("664", 8),
            owners = { "root" },
            groups = { "root", "utmp" },
        }
    end

    if name == "btmp" then
        return {
            name = "failed_login_record",
            max_mode = tonumber("660", 8),
            owners = { "root" },
            groups = { "root", "utmp" },
        }
    end

    if name == "README" then
        return {
            name = "readme",
            max_mode = tonumber("644", 8),
            owners = { "root", "syslog" },
            groups = { "root", "adm" },
        }
    end

    if path:match("%.journal~?$") then
        return {
            name = "journal",
            max_mode = tonumber("640", 8),
            owners = { "root" },
            groups = { "root", "systemd-journal", "adm" },
        }
    end

    if path:match("/sssd/") or path:match("/SSSD/") then
        return {
            name = "sssd",
            max_mode = tonumber("600", 8),
            owners = { "root", "sssd" },
            groups = { "root", "sssd" },
        }
    end

    if path:match("/gdm/") or path:match("/gdm3/") then
        return {
            name = "gdm",
            max_mode = tonumber("640", 8),
            owners = { "root", "gdm" },
            groups = { "root", "gdm", "adm" },
        }
    end

    return {
        name = "default",
        max_mode = tonumber("640", 8),
        owners = { "root", "syslog" },
        groups = { "root", "adm" },
    }
end

local function access_detail(path, passwd_by_uid, group_by_gid)
    local attr = _dependencies.fs_stat(path)
    if not attr then
        return {
            path = path,
            exists = false,
            configured = false,
            reason = "stat_failed",
        }
    end

    local uid = attr:uid()
    local gid = attr:gid()
    local mode = attr:mode()
    local owner = passwd_by_uid[uid]
    local group = group_by_gid[gid]
    local policy = policy_for_path(path)
    local owners = set_from_list(policy.owners)
    local groups = set_from_list(policy.groups)
    local mode_ok = comparators.mode_is_no_more_permissive(mode, policy.max_mode)
    local owner_ok = owner ~= nil and owners[owner] == true
    local group_ok = group ~= nil and groups[group] == true

    return {
        path = path,
        exists = true,
        policy = policy.name,
        uid = uid,
        gid = gid,
        owner = owner,
        group = group,
        mode = mode,
        expected_mode = policy.max_mode,
        allowed_owners = policy.owners,
        allowed_groups = policy.groups,
        mode_ok = mode_ok,
        owner_ok = owner_ok,
        group_ok = group_ok,
        configured = mode_ok and owner_ok and group_ok,
    }
end

function M.inspect_logfile_access(params)
    params = params or {}
    local root_path = params.root_path or "/var/log"
    local passwd_path = params.passwd_path or "/etc/passwd"
    local group_path = params.group_path or "/etc/group"

    local passwd_by_uid, passwd_err = read_name_index(passwd_path, 7, 3)
    if not passwd_by_uid then
        return {
            available = false,
            error = passwd_err,
            checked_count = 0,
            violation_count = 0,
            all_configured = false,
            details = {},
        }
    end

    local group_by_gid, group_err = read_name_index(group_path, 4, 3)
    if not group_by_gid then
        return {
            available = false,
            error = group_err,
            checked_count = 0,
            violation_count = 0,
            all_configured = false,
            details = {},
        }
    end

    local files = {}
    local ok, collect_err = collect_regular_files(root_path, files)
    if not ok then
        log.warn("%s", collect_err)
        return {
            available = false,
            error = collect_err,
            checked_count = 0,
            violation_count = 0,
            all_configured = false,
            details = {},
        }
    end

    table.sort(files)

    local details = {}
    local violation_count = 0
    for _, path in ipairs(files) do
        local detail = access_detail(path, passwd_by_uid, group_by_gid)
        details[#details + 1] = detail
        if not detail.configured then
            violation_count = violation_count + 1
        end
    end

    return {
        available = true,
        checked_count = #details,
        violation_count = violation_count,
        all_configured = #details > 0 and violation_count == 0,
        details = details,
    }
end

return M
