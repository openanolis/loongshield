local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local path_list = require('seharden.shared.path_list')
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

    local sep = params.separator or '='
    local key = params.key
    local value = tostring(params.value)

    -- Build a pattern that matches the key with flexible spacing
    local escaped_key = key:gsub('([%^%$%(%)%%%.%[%]%*%+%-%?])', '%%%1')
    local match_pattern = '^%s*' .. escaped_key .. '%s*' .. sep:gsub('.', '%%%0') .. '%s*(.-)%s*$'
    local new_line = key .. sep .. value

    local lines = {}
    local match_count = 0
    local needs_write = false

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("file.set_key_value: refusing to overwrite symlink '%s'", params.path)
    end

    local f_in = _dependencies.io_open(params.path, 'r')
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

    log.debug('Enforcer file.set_key_value: writing %s%s%s to %s', key, sep, value, params.path)
    return fsutil.write_lines_atomically(params.path, lines, 'file.set_key_value', _dependencies)
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
    local f_in = _dependencies.io_open(params.path, 'r')
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
    log.debug('Enforcer file.append_line: appending to %s: %s', params.path, target_line)
    return fsutil.write_lines_atomically(params.path, lines, 'file.append_line', _dependencies)
end

-- Remove all lines matching a Lua pattern from one or more files. Idempotent.
-- params: { path, pattern } or { paths = { ... }, pattern }
--   'path'  — single file (backward compat)
--   'paths' — array of files/globs (e.g. {"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"})
--   'pattern' — Lua pattern to match lines to remove
function M.remove_line_matching(params)
    if not params or not params.pattern then
        return nil, "file.remove_line_matching: requires 'pattern' parameter"
    end

    -- Collect all target paths (expand globs via path_list)
    local targets = {}
    if params.paths then
        local resolved = path_list.expand_files(params.paths)
        for _, p in ipairs(resolved) do
            table.insert(targets, p)
        end
    elseif params.path then
        targets = { params.path }
    else
        return nil, "file.remove_line_matching: requires 'path' or 'paths' parameter"
    end

    -- Process each target file
    local any_removed = false
    for _, path in ipairs(targets) do
        local lines = {}
        local removed = 0

        if fsutil.is_symlink(path, _dependencies) then
            log.warn("file.remove_line_matching: refusing to overwrite symlink '%s'", path)
            goto continue
        end

        local f_in = _dependencies.io_open(path, 'r')
        if not f_in then
            -- File doesn't exist — skip
            goto continue
        end
        for line in f_in:lines() do
            if line:match(params.pattern) then
                removed = removed + 1
            else
                table.insert(lines, line)
            end
        end
        f_in:close()

        if removed > 0 then
            log.debug('Enforcer file.remove_line_matching: removing %d line(s) from %s', removed, path)
            local ok, err = fsutil.write_lines_atomically(path, lines, 'file.remove_line_matching', _dependencies)
            if not ok then
                return nil, string.format("file.remove_line_matching: failed to write '%s': %s", path, tostring(err))
            end
            any_removed = true
        else
            log.debug("file.remove_line_matching: no matching lines in '%s', skipping.", path)
        end

        ::continue::
    end

    if not any_removed then
        log.debug('file.remove_line_matching: no files had matching lines.')
    end
    return true
end

-- Comment out all lines matching a Lua pattern by prepending "# ". Idempotent.
-- params: { path, pattern, comment_prefix (optional, default "# ") }
function M.comment_line_matching(params)
    if not params or not params.path or not params.pattern then
        return nil, "file.comment_line_matching: requires 'path' and 'pattern' parameters"
    end

    local comment_prefix = params.comment_prefix or '# '
    local lines = {}
    local commented = 0

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("file.comment_line_matching: refusing to overwrite symlink '%s'", params.path)
    end

    local f_in = _dependencies.io_open(params.path, 'r')
    if not f_in then
        -- File doesn't exist — nothing to comment
        return true
    end
    for line in f_in:lines() do
        if
            line:match(params.pattern)
            and not line:match('^%s*' .. comment_prefix:gsub('([%^%$%(%)%%%.%[%]%*%+%-%?])', '%%%1'))
        then
            -- Line matches pattern and is not already commented
            table.insert(lines, comment_prefix .. line)
            commented = commented + 1
        else
            table.insert(lines, line)
        end
    end
    f_in:close()

    if commented == 0 then
        log.debug("file.comment_line_matching: no uncommented matching lines in '%s', skipping.", params.path)
        return true
    end

    log.debug('Enforcer file.comment_line_matching: commenting out %d line(s) in %s', commented, params.path)
    return fsutil.write_lines_atomically(params.path, lines, 'file.comment_line_matching', _dependencies)
end

-- Write exact content to a file. Idempotent (skips if content already matches).
-- params: { path, content }
--   'content' — string; may contain embedded \n for multi-line content
function M.write_content(params)
    if not params or not params.path or params.content == nil then
        return nil, "file.write_content: requires 'path' and 'content' parameters"
    end

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("file.write_content: refusing to overwrite symlink '%s'", params.path)
    end

    -- Split content into lines
    local lines = {}
    for line in (params.content .. '\n'):gmatch('(.-)\n') do
        table.insert(lines, line)
    end

    -- Read current content for idempotency check
    local current_lines = {}
    local f_in = _dependencies.io_open(params.path, 'r')
    if f_in then
        for line in f_in:lines() do
            table.insert(current_lines, line)
        end
        f_in:close()
    end

    -- Compare line-by-line
    if #current_lines == #lines then
        local same = true
        for i = 1, #lines do
            if current_lines[i] ~= lines[i] then
                same = false
                break
            end
        end
        if same then
            log.debug("file.write_content: '%s' already has desired content, skipping.", params.path)
            return true
        end
    end

    log.debug('Enforcer file.write_content: writing content to %s', params.path)
    return fsutil.write_lines_atomically(params.path, lines, 'file.write_content', _dependencies)
end

-- Set a key=value pair within a specific INI section. Section-aware. Idempotent.
-- params: { path, section, key, value }
--   'section' — INI section name (without brackets), e.g. "daemon"
--   'key'     — key name within the section
--   'value'   — desired value (will be converted to string)
function M.set_ini_key_value(params)
    if not params or not params.path or not params.section or not params.key or params.value == nil then
        return nil, "file.set_ini_key_value: requires 'path', 'section', 'key', and 'value' parameters"
    end

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("file.set_ini_key_value: refusing to overwrite symlink '%s'", params.path)
    end

    local target_section = params.section
    local target_key = params.key
    local target_value = tostring(params.value)

    -- Escape special Lua pattern characters in key for matching
    local escaped_key = target_key:gsub('([%^%$%(%)%%%.%[%]%*%+%-%?])', '%%%1')
    local key_pattern = '^%s*' .. escaped_key .. '%s*=%s*(.-)%s*$'

    local lines = {}
    local current_section
    local in_target_section = false
    local key_found = false
    local key_updated = false
    local insert_index -- where to insert key=value if not found

    local f_in = _dependencies.io_open(params.path, 'r')
    if f_in then
        for line in f_in:lines() do
            table.insert(lines, line)

            -- Check for section header
            local section_name = line:match('^%s*%[([^%]]+)%]%s*$')
            if section_name then
                if in_target_section and not key_found then
                    -- Leaving target section without finding key; record insertion point
                    insert_index = #lines
                end
                current_section = section_name
                in_target_section = (section_name == target_section)
            elseif in_target_section and not key_found then
                local existing_val = line:match(key_pattern)
                if existing_val ~= nil then
                    key_found = true
                    if existing_val == target_value then
                        log.debug(
                            "file.set_ini_key_value: [%s] %s already '%s', skipping.",
                            target_section,
                            target_key,
                            target_value
                        )
                        f_in:close()
                        return true
                    end
                    -- Replace value in-place
                    lines[#lines] = target_key .. '=' .. target_value
                    key_updated = true
                end
            end
        end
        f_in:close()

        if in_target_section and not key_found then
            insert_index = #lines + 1
        end
    end

    if key_found and not key_updated then
        -- Value already correct (caught in the loop above for normal flow)
        log.debug("file.set_ini_key_value: [%s] %s already '%s', skipping.", target_section, target_key, target_value)
        return true
    end

    if not key_found then
        if insert_index then
            -- Section exists but key does not; insert before the next section header
            table.insert(lines, insert_index, target_key .. '=' .. target_value)
        else
            -- Section does not exist; append [section] + key=value at end
            table.insert(lines, '[' .. target_section .. ']')
            table.insert(lines, target_key .. '=' .. target_value)
        end
    end

    log.debug(
        'Enforcer file.set_ini_key_value: [%s] %s=%s in %s',
        target_section,
        target_key,
        target_value,
        params.path
    )
    return fsutil.write_lines_atomically(params.path, lines, 'file.set_ini_key_value', _dependencies)
end

return M
