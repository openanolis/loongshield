local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
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

-- Update or append "key=value" / "key value" in a config file. Idempotent.
-- params: { path, key, value, separator (optional, default "=") }
function M.set_key_value(params)
    if not params or not params.path or not params.key or params.value == nil then
        return nil, "file.set_key_value: requires 'path', 'key', and 'value' parameters"
    end

    local sep   = params.separator or "="
    local key   = params.key
    local value = tostring(params.value)

    -- Build a pattern that matches the key with flexible spacing
    local escaped_key = key:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
    local match_pattern = "^%s*" .. escaped_key .. "%s*" .. sep:gsub(".", "%%%0") .. "%s*(.-)%s*$"
    local new_line = key .. sep .. value

    local lines = {}
    local match_count = 0
    local needs_write = false

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("file.set_key_value: refusing to overwrite symlink '%s'", params.path)
    end

    local f_in = _dependencies.io_open(params.path, "r")
    if f_in then
        for line in f_in:lines() do
            local existing_val = line:match(match_pattern)
            if existing_val ~= nil then
                match_count = match_count + 1
                if match_count == 1 then
                    table.insert(lines, new_line)
                end
                if existing_val ~= value or match_count > 1 then
                    needs_write = true
                end
            else
                table.insert(lines, line)
            end
        end
        f_in:close()
    end

    if match_count == 0 then
        table.insert(lines, new_line)
        needs_write = true
    elseif not needs_write then
        log.debug("file.set_key_value: '%s' already set to '%s', skipping.", key, value)
        return true
    end

    log.debug("Enforcer file.set_key_value: writing %s%s%s to %s", key, sep, value, params.path)
    return fsutil.write_lines_atomically(params.path, lines, "file.set_key_value", _dependencies)
end

-- Append a line to a file if not already present. Idempotent.
-- params: { path, line }
function M.append_line(params)
    if not params or not params.path or not params.line then
        return nil, "file.append_line: requires 'path' and 'line' parameters"
    end

    local target_line = params.line
    local lines = {}

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("file.append_line: refusing to overwrite symlink '%s'", params.path)
    end

    -- Check if line already exists
    local f_in = _dependencies.io_open(params.path, "r")
    if f_in then
        for line in f_in:lines() do
            table.insert(lines, line)
            if line == target_line then
                f_in:close()
                log.debug("file.append_line: line already present in '%s', skipping.", params.path)
                return true
            end
        end
        f_in:close()
    end

    table.insert(lines, target_line)
    log.debug("Enforcer file.append_line: appending to %s: %s", params.path, target_line)
    return fsutil.write_lines_atomically(params.path, lines, "file.append_line", _dependencies)
end

-- Remove all lines matching a Lua pattern from a file. Idempotent.
-- params: { path, pattern }
function M.remove_line_matching(params)
    if not params or not params.path or not params.pattern then
        return nil, "file.remove_line_matching: requires 'path' and 'pattern' parameters"
    end

    local lines = {}
    local removed = 0

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("file.remove_line_matching: refusing to overwrite symlink '%s'", params.path)
    end

    local f_in = _dependencies.io_open(params.path, "r")
    if not f_in then
        -- File doesn't exist — nothing to remove
        return true
    end
    for line in f_in:lines() do
        if line:match(params.pattern) then
            removed = removed + 1
        else
            table.insert(lines, line)
        end
    end
    f_in:close()

    if removed == 0 then
        log.debug("file.remove_line_matching: no matching lines in '%s', skipping.", params.path)
        return true
    end

    log.debug("Enforcer file.remove_line_matching: removing %d line(s) from %s", removed, params.path)
    return fsutil.write_lines_atomically(params.path, lines, "file.remove_line_matching", _dependencies)
end

return M
