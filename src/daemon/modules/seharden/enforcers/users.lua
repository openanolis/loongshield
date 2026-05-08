local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    os_execute = os.execute,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
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
    return fsutil.write_lines_atomically(shadow_path, lines, "users.lock_empty_password_accounts", _dependencies)
end

-- Set password max days for root account using chage command.
-- This mirrors the DengBaoThree approach: chage --maxdays 90 root
-- params: { max_days (default 90) }
function M.set_password_max_days_for_root(params)
    local max_days = params.max_days or 90
    
    -- Set PASS_MAX_DAYS for root
    local cmd = string.format("chage --maxdays %d root", max_days)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil, string.format("users.set_password_max_days_for_root: command failed (exit %s): %s", tostring(code), cmd)
    end
    log.info("users.set_password_max_days_for_root: set PASS_MAX_DAYS=%d for root", max_days)
    
    return true
end

-- Set password min days for root account using chage command.
-- This mirrors the DengBaoThree approach: chage --mindays 7 root
-- params: { min_days (default 7) }
function M.set_password_min_days_for_root(params)
    local min_days = params.min_days or 7
    
    -- Set PASS_MIN_DAYS for root
    local cmd = string.format("chage --mindays %d root", min_days)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil, string.format("users.set_password_min_days_for_root: command failed (exit %s): %s", tostring(code), cmd)
    end
    log.info("users.set_password_min_days_for_root: set PASS_MIN_DAYS=%d for root", min_days)
    
    return true
end

return M
