local common = require('seharden.pam.common')

local M = {}

local STACK_KINDS = { "auth", "account", "password", "session" }
local STRONG_HASHES = { sha512 = true, yescrypt = true }
local WEAK_HASHES = { md5 = true, bigcrypt = true, sha256 = true, blowfish = true }

local function entries_for(entries, kind)
    local matches = {}
    for _, entry in ipairs(entries) do
        if entry.module == "pam_unix.so" and (kind == nil or entry.kind == kind) then
            matches[#matches + 1] = entry
        end
    end
    return matches
end

local function has_entry(entries, kind)
    return #entries_for(entries, kind) > 0
end

local function has_any_arg(entry, names)
    for _, arg in ipairs(entry.args) do
        if names[arg] then
            return arg
        end
    end
    return nil
end

local function has_remember(entry)
    for _, arg in ipairs(entry.args) do
        if arg:match("^remember=") then
            return arg
        end
    end
    return nil
end

local function check_enabled(path, entries, details)
    for _, kind in ipairs(STACK_KINDS) do
        if not has_entry(entries, kind) then
            common.add_detail(details, path, "stack_missing", { kind = kind })
        end
    end
end

local function check_no_nullok(path, entries, details)
    local unix_entries = entries_for(entries)
    if #unix_entries == 0 then
        common.add_detail(details, path, "module_missing")
        return
    end

    for _, entry in ipairs(unix_entries) do
        if common.has_arg(entry.args, "nullok") then
            common.add_detail(details, path, "nullok_enabled", { kind = entry.kind })
        end
    end
end

local function check_no_remember(path, entries, details)
    local password_entries = entries_for(entries, "password")
    if #password_entries == 0 then
        common.add_detail(details, path, "password_stack_missing")
        return
    end

    for _, entry in ipairs(password_entries) do
        local remember = has_remember(entry)
        if remember then
            common.add_detail(details, path, "remember_enabled", { value = remember })
        end
    end
end

local function check_strong_hash(path, entries, details)
    local password_entries = entries_for(entries, "password")
    if #password_entries == 0 then
        common.add_detail(details, path, "password_stack_missing")
        return
    end

    for _, entry in ipairs(password_entries) do
        local weak = has_any_arg(entry, WEAK_HASHES)
        if weak then
            common.add_detail(details, path, "weak_hash", { value = weak })
        end
        if not has_any_arg(entry, STRONG_HASHES) then
            common.add_detail(details, path, "strong_hash_missing")
        end
    end
end

local function check_use_authtok(path, entries, details)
    local password_entries = entries_for(entries, "password")
    if #password_entries == 0 then
        common.add_detail(details, path, "password_stack_missing")
        return
    end

    for _, entry in ipairs(password_entries) do
        if not common.has_arg(entry.args, "use_authtok") then
            common.add_detail(details, path, "use_authtok_missing")
        end
    end
end

local CHECKS = {
    enabled = check_enabled,
    no_nullok = check_no_nullok,
    no_remember = check_no_remember,
    strong_hash = check_strong_hash,
    use_authtok = check_use_authtok,
}

function M.inspect(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.inspect_unix")
    if not pam_paths then
        return nil, path_err
    end

    local check = params.check
    local check_func = CHECKS[check]
    if not check_func then
        return nil, "Probe 'pam.inspect_unix' requires check to be one of: enabled, no_nullok, no_remember, strong_hash, use_authtok."
    end

    local details = {}
    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            common.add_detail(details, path, "pam_file_unreadable")
        else
            check_func(path, entries, details)
        end
    end

    return {
        count = #details,
        details = details,
    }
end

return M
