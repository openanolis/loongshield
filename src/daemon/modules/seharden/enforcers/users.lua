local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local account_files = require('seharden.shared.account_files')
local user_defaults = require('seharden.shared.user_defaults')
local comparators = require('seharden.comparators')
local M = {}

-- Validate username against strict safe-token pattern.
-- Linux usernames: [a-zA-Z0-9._-], must not start with '-', max 32 chars.
-- This prevents shell injection via malformed account names.
local function is_safe_username(username)
    return type(username) == 'string'
        and #username > 0
        and #username <= 32
        and username:match('^[a-zA-Z0-9._][a-zA-Z0-9._-]*$') ~= nil
end

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    os_execute = os.execute,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    lfs_dir = function(path)
        return require('lfs').dir(path)
    end,
    fs_stat = function(path)
        return require('fs').stat(path)
    end,
    fs_chmod = function(path, mode)
        return require('fs').chmod(path, mode)
    end,
    fs_chown = function(path, uid, gid)
        return require('fs').chown(path, uid, gid)
    end,
    passwd_path = '/etc/passwd',
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
    local shadow_path = params.shadow_path or '/etc/shadow'

    if fsutil.is_symlink(shadow_path, _dependencies) then
        return nil, string.format("users.lock_empty_password_accounts: refusing to modify symlink '%s'", shadow_path)
    end

    local lines = {}
    local locked_count = 0

    local f_in = _dependencies.io_open(shadow_path, 'r')
    if not f_in then
        return nil, string.format("users.lock_empty_password_accounts: could not open '%s'", shadow_path)
    end

    for line in f_in:lines() do
        -- Skip comments and empty lines
        if line:match('^#') or line:match('^%s*$') then
            table.insert(lines, line)
        else
            -- Parse shadow line: username:password:lastchg:min:max:warn:inactive:expire:reserved
            -- Check if password field is empty (username::...)
            local username, password_field, rest = line:match('^([^:]*):([^:]*):(.*)$')

            if username and password_field == '' then
                -- Empty password found - lock the account by setting password to "!"
                local new_line = username .. ':!:' .. rest
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
        log.debug('users.lock_empty_password_accounts: no accounts with empty passwords found, skipping.')
        return true
    end

    log.info('users.lock_empty_password_accounts: locked %d account(s) with empty passwords', locked_count)
    return fsutil.write_lines_atomically_preserving_attrs(
        shadow_path,
        lines,
        'users.lock_empty_password_accounts',
        _dependencies
    )
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
                return nil,
                    string.format(
                        "users.set_password_max_days_for_root: refusing to process unsafe username '%s'",
                        tostring(entry.user)
                    )
            end
            local current = entry.pass_max_days
            if current == nil or current > max_days then
                local cmd = string.format('chage --maxdays %d %s', max_days, entry.user)
                local ok, _, code = _dependencies.os_execute(cmd)
                if not ok and code ~= 0 then
                    return nil,
                        string.format(
                            "users.set_password_max_days_for_root: chage failed (exit %s) for user '%s': %s",
                            tostring(code),
                            entry.user,
                            cmd
                        )
                end
                fixed_count = fixed_count + 1
                log.info(
                    "users.set_password_max_days_for_root: set PASS_MAX_DAYS=%d for user '%s'",
                    max_days,
                    entry.user
                )
            end
        end
        log.info(
            'users.set_password_max_days_for_root: fixed %d account(s) with PASS_MAX_DAYS > %d',
            fixed_count,
            max_days
        )
        return true
    end

    -- Fallback: fix only root (original behavior, kept for backward compatibility)
    local cmd = string.format('chage --maxdays %d root', max_days)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil,
            string.format('users.set_password_max_days_for_root: command failed (exit %s): %s', tostring(code), cmd)
    end
    log.info('users.set_password_max_days_for_root: set PASS_MAX_DAYS=%d for root', max_days)

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
                return nil,
                    string.format(
                        "users.set_password_min_days_for_root: refusing to process unsafe username '%s'",
                        tostring(entry.user)
                    )
            end
            local current = entry.pass_min_days
            if current == nil or current < min_days then
                local cmd = string.format('chage --mindays %d %s', min_days, entry.user)
                local ok, _, code = _dependencies.os_execute(cmd)
                if not ok and code ~= 0 then
                    return nil,
                        string.format(
                            "users.set_password_min_days_for_root: chage failed (exit %s) for user '%s': %s",
                            tostring(code),
                            entry.user,
                            cmd
                        )
                end
                fixed_count = fixed_count + 1
                log.info(
                    "users.set_password_min_days_for_root: set PASS_MIN_DAYS=%d for user '%s'",
                    min_days,
                    entry.user
                )
            end
        end
        log.info(
            'users.set_password_min_days_for_root: fixed %d account(s) with PASS_MIN_DAYS < %d',
            fixed_count,
            min_days
        )
        return true
    end

    -- Fallback: fix only root (original behavior, kept for backward compatibility)
    local cmd = string.format('chage --mindays %d root', min_days)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil,
            string.format('users.set_password_min_days_for_root: command failed (exit %s): %s', tostring(code), cmd)
    end
    log.info('users.set_password_min_days_for_root: set PASS_MIN_DAYS=%d for root', min_days)

    return true
end

-- Lock shutdown and halt system accounts to prevent unauthorized system shutdown.
-- Uses 'passwd -l' command to lock accounts by prepending '!' to password field.
-- This is idempotent: already locked accounts are skipped gracefully.
-- params: {}
function M.lock_shutdown_and_halt_accounts(params)
    local accounts = { 'shutdown', 'halt' }
    local locked_count = 0
    local skipped_count = 0
    local errors = {}

    for _, account in ipairs(accounts) do
        -- Check if account exists in /etc/passwd before attempting to lock
        local check_cmd = string.format('getent passwd %s >/dev/null 2>&1', account)
        local exists = _dependencies.os_execute(check_cmd)

        if not exists then
            log.debug("users.lock_shutdown_and_halt_accounts: account '%s' does not exist, skipping", account)
            skipped_count = skipped_count + 1
            goto continue
        end

        -- Lock the account using passwd -l
        local lock_cmd = string.format('passwd -l %s 2>/dev/null', account)
        local ok, _, code = _dependencies.os_execute(lock_cmd)

        if ok and code == 0 then
            locked_count = locked_count + 1
            log.info("users.lock_shutdown_and_halt_accounts: locked '%s' account", account)
        else
            -- Account may already be locked or have no password
            log.debug(
                "users.lock_shutdown_and_halt_accounts: '%s' may already be locked or have no password (exit %s)",
                account,
                tostring(code)
            )
            skipped_count = skipped_count + 1
        end

        ::continue::
    end

    if #errors > 0 then
        return nil,
            string.format('users.lock_shutdown_and_halt_accounts: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.info(
        'users.lock_shutdown_and_halt_accounts: locked %d account(s), skipped %d (already locked or not found)',
        locked_count,
        skipped_count
    )
    return true
end

-- Set multiple password policy defaults for all non-locked accounts using chage.
-- Iterates shadow entries and applies chage only to non-compliant users.
-- params: {
--   max_days   (optional): enforce PASS_MAX_DAYS in 1..max_days range
--   warn_days  (optional): enforce PASS_WARN_AGE >= warn_days
--   inactive   (optional): enforce INACTIVE in 0..inactive range (and != -1)
--   entries    (required): shadow entries from users.get_shadow_entries probe
-- }
function M.set_password_defaults(params)
    if not params then
        return nil, 'users.set_password_defaults: requires params'
    end
    if not params.entries or type(params.entries) ~= 'table' then
        return nil, "users.set_password_defaults: requires 'entries' from shadow probe"
    end

    local max_days = params.max_days and tonumber(params.max_days) or nil
    local warn_days = params.warn_days and tonumber(params.warn_days) or nil
    local inactive = params.inactive and tonumber(params.inactive) or nil
    local entries = params.entries

    if not max_days and not warn_days and not inactive then
        return nil, 'users.set_password_defaults: at least one of max_days, warn_days, inactive is required'
    end

    local fixed_count = 0
    local errors = {}

    for _, entry in ipairs(entries) do
        local user = entry.user
        if not is_safe_username(user) then
            return nil,
                string.format(
                    "users.set_password_defaults: refusing to process unsafe username '%s'",
                    tostring(user)
                )
        end
        local chage_args = {}

        -- Check max_days: pass_max_days must be > 0 and <= max_days
        if max_days then
            local current = entry.pass_max_days
            if current == nil or current < 1 or current > max_days then
                chage_args[#chage_args + 1] = string.format('--maxdays %d', max_days)
            end
        end

        -- Check warn_days: pass_warn_age must be >= warn_days
        if warn_days then
            local current = entry.pass_warn_age
            if current == nil or current < warn_days then
                chage_args[#chage_args + 1] = string.format('--warndays %d', warn_days)
            end
        end

        -- Check inactive: must be >= 0, <= inactive, and != -1
        if inactive then
            local current = entry.inactive
            if current == nil or current < 0 or current > inactive or current == -1 then
                chage_args[#chage_args + 1] = string.format('--inactive %d', inactive)
            end
        end

        if #chage_args > 0 then
            local cmd = string.format('chage %s %s', table.concat(chage_args, ' '), user)
            log.debug('users.set_password_defaults: %s', cmd)
            local ok, _, code = _dependencies.os_execute(cmd)
            if not ok and code ~= 0 then
                errors[#errors + 1] = string.format("chage failed (exit %s) for user '%s'", tostring(code), user)
            else
                fixed_count = fixed_count + 1
            end
        end
    end

    if #errors > 0 then
        return nil, string.format('users.set_password_defaults: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.debug('users.set_password_defaults: fixed %d of %d account(s)', fixed_count, #entries)
    return true
end

-- Fix users whose last password change date is in the future.
-- Sets their last password change date to today using chage --lastday.
-- params: { details (required): list from users.inspect_future_password_changes probe }
function M.fix_future_password_changes(params)
    if not params or not params.details or type(params.details) ~= 'table' then
        return nil, "users.fix_future_password_changes: requires 'details' from probe"
    end

    local today = os.date('%Y-%m-%d')
    local fixed_count = 0
    local errors = {}

    for _, detail in ipairs(params.details) do
        local user = detail.user
        if user then
            if not is_safe_username(user) then
                return nil,
                    string.format(
                        "users.fix_future_password_changes: refusing to process unsafe username '%s'",
                        tostring(user)
                    )
            end
            local cmd = string.format('chage --lastday %s %s', today, user)
            log.debug('users.fix_future_password_changes: %s', cmd)
            local ok, _, code = _dependencies.os_execute(cmd)
            if not ok and code ~= 0 then
                errors[#errors + 1] = string.format("chage failed (exit %s) for user '%s'", tostring(code), user)
            else
                fixed_count = fixed_count + 1
            end
        end
    end

    if #errors > 0 then
        return nil,
            string.format('users.fix_future_password_changes: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.debug('users.fix_future_password_changes: fixed %d account(s)', fixed_count)
    return true
end

-- Lock accounts that have a non-login shell but an unlocked password.
-- Iterates the details from users.inspect_nonlogin_accounts_locked probe
-- and runs passwd -l for each non-compliant user.
-- params: { details (required): list from probe }
function M.lock_nologin_accounts(params)
    if not params or not params.details or type(params.details) ~= 'table' then
        return nil, "users.lock_nologin_accounts: requires 'details' from probe"
    end

    local fixed_count = 0
    local errors = {}

    for _, detail in ipairs(params.details) do
        local user = detail.user
        if user then
            if not is_safe_username(user) then
                return nil,
                    string.format(
                        "users.lock_nologin_accounts: refusing to process unsafe username '%s'",
                        tostring(user)
                    )
            end
            local cmd = string.format('passwd -l %s 2>&1', user)
            log.debug('users.lock_nologin_accounts: %s', cmd)
            local ok, _, code = _dependencies.os_execute(cmd)
            if not ok and code ~= 0 then
                errors[#errors + 1] = string.format("passwd -l failed (exit %s) for user '%s'", tostring(code), user)
            else
                fixed_count = fixed_count + 1
            end
        end
    end

    if #errors > 0 then
        return nil, string.format('users.lock_nologin_accounts: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.debug('users.lock_nologin_accounts: locked %d account(s)', fixed_count)
    return true
end

-- Lock the root account password using passwd -l.
-- This prepends '!' to the root password hash, preventing password-based login.
-- Idempotent: if already locked, passwd -l is a no-op.
-- params: {} (no parameters needed)
function M.lock_root_account(params)
    local cmd = 'passwd -l root 2>&1'
    log.debug('users.lock_root_account: %s', cmd)
    local ok, _, code = _dependencies.os_execute(cmd)
    if not ok and code ~= 0 then
        return nil, string.format('users.lock_root_account: passwd -l root failed (exit %s)', tostring(code))
    end
    log.debug('users.lock_root_account: root account locked')
    return true
end

-- Disable login shells for system accounts by setting their shell to /usr/sbin/nologin.
-- Iterates the details from users.inspect_system_account_shells probe
-- and runs usermod -s /usr/sbin/nologin for each non-compliant account.
-- params: { details (required): list from probe }
function M.disable_system_account_shells(params)
    if not params or not params.details or type(params.details) ~= 'table' then
        return nil, "users.disable_system_account_shells: requires 'details' from probe"
    end

    local fixed_count = 0
    local errors = {}

    for _, detail in ipairs(params.details) do
        local user = detail.user
        if user then
            if not is_safe_username(user) then
                return nil,
                    string.format(
                        "users.disable_system_account_shells: refusing to process unsafe username '%s'",
                        tostring(user)
                    )
            end
            local cmd = string.format('usermod -s /usr/sbin/nologin %s 2>&1', user)
            log.debug('users.disable_system_account_shells: %s', cmd)
            local ok, _, code = _dependencies.os_execute(cmd)
            if not ok and code ~= 0 then
                errors[#errors + 1] = string.format("usermod failed (exit %s) for user '%s'", tostring(code), user)
            else
                fixed_count = fixed_count + 1
            end
        end
    end

    if #errors > 0 then
        return nil,
            string.format('users.disable_system_account_shells: %d error(s): %s', #errors, table.concat(errors, '; '))
    end

    log.debug('users.disable_system_account_shells: disabled shell for %d account(s)', fixed_count)
    return true
end

--------------------------------------------------------------------------------
-- Dotfile access fix helpers
--------------------------------------------------------------------------------

local FORBIDDEN_DOTFILES = {
    ['.forward'] = true,
    ['.rhosts'] = true,
}

local DEFAULT_DOTFILE_MAX_MODE = tonumber('644', 8)
local STRICT_DOTFILE_MAX_MODES = {
    ['.bash_history'] = tonumber('600', 8),
    ['.netrc'] = tonumber('600', 8),
}

local function fix_dotfile(path, user, fixed_count_ref, deps)
    local filename = path:match('([^/]+)$') or path

    -- Remove forbidden files
    if FORBIDDEN_DOTFILES[filename] then
        log.info("users.fix_dotfiles: removing forbidden file '%s' (user %s)", path, user.user)
        local ok, err = deps.os_remove(path)
        if not ok then
            return nil,
                string.format("users.fix_dotfiles: failed to remove '%s': %s", path, tostring(err))
        end
        fixed_count_ref[1] = fixed_count_ref[1] + 1
        return true
    end

    -- Only fix regular files
    local attr = deps.lfs_symlinkattributes(path)
    if not attr or attr.mode ~= 'file' then
        return true
    end

    local stat = deps.fs_stat(path)
    if not stat then
        return true
    end

    local max_mode = STRICT_DOTFILE_MAX_MODES[filename] or DEFAULT_DOTFILE_MAX_MODE
    local fixed = false

    -- Fix permissions if too permissive
    if not comparators.mode_is_no_more_permissive(stat:mode(), max_mode) then
        log.debug("users.fix_dotfiles: chmod %o '%s' (user %s)", max_mode, path, user.user)
        local ok, err = deps.fs_chmod(path, max_mode)
        if not ok then
            return nil,
                string.format("users.fix_dotfiles: failed to chmod '%s': %s", path, tostring(err))
        end
        fixed = true
    end

    -- Fix ownership
    if stat:uid() ~= user.user_uid or stat:gid() ~= user.user_gid then
        log.debug("users.fix_dotfiles: chown %d:%d '%s' (user %s)", user.user_uid, user.user_gid, path, user.user)
        local ok, err = deps.fs_chown(path, user.user_uid, user.user_gid)
        if not ok then
            return nil,
                string.format("users.fix_dotfiles: failed to chown '%s': %s", path, tostring(err))
        end
        fixed = true
    end

    if fixed then
        fixed_count_ref[1] = fixed_count_ref[1] + 1
    end
    return true
end

local function scan_and_fix_dotfiles(fixed_count_ref, user, dir_path, root_dev, deps)
    local iter, dir_obj = deps.lfs_dir(dir_path)
    if not iter then
        return true
    end
    for name in iter, dir_obj do
        if name ~= '.' and name ~= '..' then
            local path = dir_path .. '/' .. name
            local attr = deps.lfs_symlinkattributes(path)
            if attr and (root_dev == nil or attr.dev == nil or attr.dev == root_dev) then
                if name:match('^%.') then
                    local ok, err = fix_dotfile(path, user, fixed_count_ref, deps)
                    if not ok then
                        return nil, err
                    end
                elseif attr.mode == 'directory' then
                    local ok, err = scan_and_fix_dotfiles(fixed_count_ref, user, path, root_dev, deps)
                    if not ok then
                        return nil, err
                    end
                end
            end
        end
    end
    return true
end

-- Fix dot file permissions and ownership for all local interactive users.
-- Removes forbidden files (.forward, .rhosts), fixes mode/owner/group.
-- params: { passwd_path (optional), max_users (optional, default 1000) }
function M.fix_dotfiles(params)
    params = params or {}
    local passwd_path = params.passwd_path or _dependencies.passwd_path

    local user_entries, err = account_files.read_passwd(_dependencies.io_open, passwd_path)
    if not user_entries then
        return nil, string.format('users.fix_dotfiles: %s', err)
    end

    local real_users = {}
    for _, parts in ipairs(user_entries) do
        local user = account_files.build_real_user(parts)
        if user then
            real_users[#real_users + 1] = user
        end
    end

    local max_users = tonumber(params.max_users) or 1000
    if #real_users > max_users then
        return nil,
            string.format(
                'users.fix_dotfiles: found %d local interactive users, exceeding max_users=%d',
                #real_users,
                max_users
            )
    end

    local fixed_count_ref = { 0 }

    for _, user in ipairs(real_users) do
        if type(user.home) == 'string' and user.home ~= '' and user.home:sub(1, 1) == '/' then
            local home_attr = _dependencies.lfs_symlinkattributes(user.home)
            if home_attr and home_attr.mode == 'directory' then
                local ok, err = scan_and_fix_dotfiles(fixed_count_ref, user, user.home, home_attr.dev, _dependencies)
                if not ok then
                    return nil, err
                end
            end
        end
    end

    if fixed_count_ref[1] == 0 then
        log.debug('users.fix_dotfiles: all dot files already compliant')
    else
        log.info('users.fix_dotfiles: fixed %d dot file(s)', fixed_count_ref[1])
    end

    return true
end

return M
