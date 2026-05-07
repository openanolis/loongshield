local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

-- Validate username against strict safe-token pattern.
-- Linux usernames: [a-zA-Z0-9._-], must not start with '-', max 32 chars.
-- This prevents shell injection via malformed account names.
local function is_safe_username(username)
    return type(username) == "string"
        and #username > 0
        and #username <= 32
        and username:match("^[a-zA-Z0-9._][a-zA-Z0-9._-]*$") ~= nil
end

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    os_execute = os.execute,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    fs_stat  = function(path) return require('fs').stat(path) end,
    fs_chmod = function(path, mode) return require('fs').chmod(path, mode) end,
    fs_chown = function(path, uid, gid) return require('fs').chown(path, uid, gid) end,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

-- Lock all accounts with empty passwords by prepending '!' to the password field.
-- This is idempotent: accounts that are already locked (! prefix) are skipped.
-- params: { shadow_path (optional, default "/etc/shadow") }
function M.lock_empty_password_accounts(params)
    local shadow_path = params.shadow_path or "/etc/shadow"
    
    if fsutil.is_symlink(shadow_path, _dependencies) then
        return nil, string.format("users.lock_empty_password_accounts: refusing to modify symlink '%s'", shadow_path)
    end
    
    local lines = {}
    local locked_count = 0
    
    local f_in = _dependencies.io_open(shadow_path, "r")
    if not f_in then
        return nil, string.format("users.lock_empty_password_accounts: could not open '%s'", shadow_path)
    end
    
    for line in f_in:lines() do
        -- Skip comments and empty lines
        if line:match("^#") or line:match("^%s*$") then
            table.insert(lines, line)
        else
            -- Parse shadow line: username:password:lastchg:min:max:warn:inactive:expire:reserved
            -- Check if password field is empty (username::...)
            local username, password_field, rest = line:match("^([^:]*):([^:]*):(.*)$")
            
            if username and password_field == "" then
                -- Empty password found - lock the account by setting password to "!"
                local new_line = username .. ":!:" .. rest
                table.insert(lines, new_line)
                locked_count = locked_count + 1
                log.info("users.lock_empty_password_accounts: locked account '%s' (was empty password)", username)
            else
                -- Non-empty password or already locked (! prefix)
                table.insert(lines, line)
            end
        end
    end
    f_in:close()
    
    if locked_count == 0 then
        log.debug("users.lock_empty_password_accounts: no accounts with empty passwords found, skipping.")
        return true
    end
    
    log.info("users.lock_empty_password_accounts: locked %d account(s) with empty passwords", locked_count)
    return fsutil.write_lines_atomically_preserving_attrs(shadow_path, lines, "users.lock_empty_password_accounts", _dependencies)
end

-- Set password max days for root account using chage command.
-- When the probe data (entries) is provided, iterates over ALL login-capable accounts
-- and fixes those with pass_max_days exceeding the threshold.
-- Without entries, falls back to fixing only root (original behavior).
-- This mirrors the DengBaoThree approach: chage --maxdays 90 <user>
-- params: { max_days (default 90), entries (optional, from shadow_entries probe) }
function M.set_password_max_days_for_root(params)
    local max_days = params.max_days or 90
    local entries = params.entries
    
    if entries and #entries > 0 then
        -- Fix ALL non-compliant login-capable accounts, not just root
        local fixed_count = 0
        for _, entry in ipairs(entries) do
            if not is_safe_username(entry.user) then
                return nil, string.format(
                    "users.set_password_max_days_for_root: refusing to process unsafe username '%s'",
                    tostring(entry.user))
            end
            local current = entry.pass_max_days
            if current == nil or current > max_days then
                local cmd = string.format("chage --maxdays %d %s", max_days, entry.user)
                local ok, _, code = _dependencies.os_execute(cmd)
                if not ok and code ~= 0 then
                    return nil, string.format("users.set_password_max_days_for_root: chage failed (exit %s) for user '%s': %s",
                        tostring(code), entry.user, cmd)
                end
                fixed_count = fixed_count + 1
                log.info("users.set_password_max_days_for_root: set PASS_MAX_DAYS=%d for user '%s'", max_days, entry.user)
            end
        end
        log.info("users.set_password_max_days_for_root: fixed %d account(s) with PASS_MAX_DAYS > %d", fixed_count, max_days)
        return true
    end
    
    -- Fallback: fix only root (original behavior, kept for backward compatibility)
    local cmd = string.format("chage --maxdays %d root", max_days)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil, string.format("users.set_password_max_days_for_root: command failed (exit %s): %s", tostring(code), cmd)
    end
    log.info("users.set_password_max_days_for_root: set PASS_MAX_DAYS=%d for root", max_days)
    
    return true
end

-- Set password min days for root account using chage command.
-- When the probe data (entries) is provided, iterates over ALL login-capable accounts
-- and fixes those with pass_min_days below the threshold.
-- Without entries, falls back to fixing only root (original behavior).
-- This mirrors the DengBaoThree approach: chage --mindays 7 <user>
-- params: { min_days (default 7), entries (optional, from shadow_entries probe) }
function M.set_password_min_days_for_root(params)
    local min_days = params.min_days or 7
    local entries = params.entries
    
    if entries and #entries > 0 then
        -- Fix ALL non-compliant login-capable accounts, not just root
        local fixed_count = 0
        for _, entry in ipairs(entries) do
            if not is_safe_username(entry.user) then
                return nil, string.format(
                    "users.set_password_min_days_for_root: refusing to process unsafe username '%s'",
                    tostring(entry.user))
            end
            local current = entry.pass_min_days
            if current == nil or current < min_days then
                local cmd = string.format("chage --mindays %d %s", min_days, entry.user)
                local ok, _, code = _dependencies.os_execute(cmd)
                if not ok and code ~= 0 then
                    return nil, string.format("users.set_password_min_days_for_root: chage failed (exit %s) for user '%s': %s",
                        tostring(code), entry.user, cmd)
                end
                fixed_count = fixed_count + 1
                log.info("users.set_password_min_days_for_root: set PASS_MIN_DAYS=%d for user '%s'", min_days, entry.user)
            end
        end
        log.info("users.set_password_min_days_for_root: fixed %d account(s) with PASS_MIN_DAYS < %d", fixed_count, min_days)
        return true
    end
    
    -- Fallback: fix only root (original behavior, kept for backward compatibility)
    local cmd = string.format("chage --mindays %d root", min_days)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil, string.format("users.set_password_min_days_for_root: command failed (exit %s): %s", tostring(code), cmd)
    end
    log.info("users.set_password_min_days_for_root: set PASS_MIN_DAYS=%d for root", min_days)
    
    return true
end

-- Lock shutdown and halt system accounts to prevent unauthorized system shutdown.
-- Uses 'passwd -l' command to lock accounts by prepending '!' to password field.
-- This is idempotent: already locked accounts are skipped gracefully.
-- params: {}
function M.lock_shutdown_and_halt_accounts(params)
    local accounts = {"shutdown", "halt"}
    local locked_count = 0
    local skipped_count = 0
    local errors = {}
    
    for _, account in ipairs(accounts) do
        -- Check if account exists in /etc/passwd before attempting to lock
        local check_cmd = string.format("getent passwd %s >/dev/null 2>&1", account)
        local exists = _dependencies.os_execute(check_cmd)
        
        if not exists then
            log.debug("users.lock_shutdown_and_halt_accounts: account '%s' does not exist, skipping", account)
            skipped_count = skipped_count + 1
            goto continue
        end
        
        -- Lock the account using passwd -l
        local lock_cmd = string.format("passwd -l %s 2>/dev/null", account)
        local ok, _, code = _dependencies.os_execute(lock_cmd)
        
        if ok and code == 0 then
            locked_count = locked_count + 1
            log.info("users.lock_shutdown_and_halt_accounts: locked '%s' account", account)
        else
            -- Account may already be locked or have no password
            log.debug("users.lock_shutdown_and_halt_accounts: '%s' may already be locked or have no password (exit %s)", 
                account, tostring(code))
            skipped_count = skipped_count + 1
        end
        
        ::continue::
    end
    
    if #errors > 0 then
        return nil, string.format("users.lock_shutdown_and_halt_accounts: %d error(s): %s", 
            #errors, table.concat(errors, "; "))
    end
    
    log.info("users.lock_shutdown_and_halt_accounts: locked %d account(s), skipped %d (already locked or not found)",
        locked_count, skipped_count)
    return true
end

return M
