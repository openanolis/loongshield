local text = require('seharden.shared.text')
local M = {}

local DEFAULT_MAX_DEPTH = 128

local function get_dirname(path)
    return path:match('^(.*)/[^/]+$') or '.'
end

local function format_depth_error(error_context)
    if error_context then
        return string.format('%s: sudoers include depth exceeded the supported limit', error_context)
    end

    return 'Sudoers include depth exceeded the supported limit.'
end

local function format_loop_error(error_context, path)
    if error_context then
        return string.format("%s: detected a sudoers include loop at '%s'", error_context, path)
    end

    return string.format("Detected a sudoers include loop at '%s'.", path)
end

local function format_file_error(error_context, path)
    if error_context then
        return string.format("%s: could not open sudoers file '%s'", error_context, path)
    end

    return string.format("Could not open sudoers file '%s'.", path)
end

local function format_directory_error(error_context, path)
    if error_context then
        return string.format("%s: could not open sudoers include directory '%s'", error_context, path)
    end

    return string.format("Could not open sudoers include directory '%s'.", path)
end

local function resolve_include_path(raw_path, current_path, get_short_hostname)
    local path = text.trim(raw_path)
    if path:sub(1, 1) == '"' and path:sub(-1) == '"' and #path >= 2 then
        path = path:sub(2, -2)
    end

    local short_hostname = nil
    if type(get_short_hostname) == 'function' then
        short_hostname = get_short_hostname()
    end

    path = path:gsub('%%h', short_hostname or '')
    path = path:gsub('\\ ', ' ')
    path = path:gsub('\\\\', '\\')

    if path:sub(1, 1) ~= '/' then
        path = get_dirname(current_path) .. '/' .. path
    end

    return path
end

local function parse_include_directive(line)
    local path = line:match('^[@#]includedir%s+(.+)$')
    if path then
        return 'includedir', path
    end

    path = line:match('^[@#]include%s+(.+)$')
    if path then
        return 'include', path
    end

    return nil, nil
end

local function record_unique_path(paths, seen, path, path_type)
    local key = tostring(path_type) .. ':' .. tostring(path)
    if not seen[key] then
        seen[key] = true
        paths[#paths + 1] = {
            path = path,
            path_type = path_type,
        }
    end
end

local function record_unique_file(files, seen, path)
    if not seen[path] then
        seen[path] = true
        files[#files + 1] = path
    end
end

local function list_directory_files(path, dependencies, error_context)
    local attr = dependencies.lfs_attributes(path)
    if not attr or attr.mode ~= 'directory' then
        return nil, format_directory_error(error_context, path)
    end

    local entries = {}
    for name in dependencies.lfs_dir(path) do
        local is_includedir_member = name ~= '.'
            and name ~= '..'
            and not name:find('.', 1, true)
            and not name:match('~$')

        if is_includedir_member then
            local full_path = path .. '/' .. name
            local full_attr = dependencies.lfs_attributes(full_path)
            if full_attr and full_attr.mode == 'file' then
                entries[#entries + 1] = full_path
            end
        end
    end

    table.sort(entries)
    return entries
end

local function append_active_line(lines, path, trimmed)
    if trimmed:match('^#') then
        return
    end

    local active = text.trim((trimmed:gsub('%s+#.*$', '')))
    if active ~= '' then
        lines[#lines + 1] = {
            path = path,
            text = active,
        }
    end
end

local function split_defaults_options(raw_options)
    local options = {}
    local buffer = {}
    local quote = nil
    local escaped = false

    local function push()
        local option = text.trim(table.concat(buffer))
        if option ~= '' then
            options[#options + 1] = option
        end
        buffer = {}
    end

    for index = 1, #raw_options do
        local char = raw_options:sub(index, index)

        if escaped then
            buffer[#buffer + 1] = char
            escaped = false
        elseif char == '\\' then
            buffer[#buffer + 1] = char
            escaped = true
        elseif quote then
            buffer[#buffer + 1] = char
            if char == quote then
                quote = nil
            end
        elseif char == '"' or char == "'" then
            buffer[#buffer + 1] = char
            quote = char
        elseif char == ',' then
            push()
        else
            buffer[#buffer + 1] = char
        end
    end

    push()
    return options
end

local function unquote_defaults_value(value)
    value = text.trim(value or '')
    if #value >= 2 then
        local first = value:sub(1, 1)
        local last = value:sub(-1)
        if (first == '"' and last == '"') or (first == "'" and last == "'") then
            value = value:sub(2, -2)
        end
    end

    return value:gsub('\\(.)', '%1')
end

local function append_defaults_option(options, option_text)
    local name, operator, value = option_text:match('^(!?[%w_]+)%s*([+%-]?=)%s*(.-)%s*$')
    if name then
        options[#options + 1] = {
            name = name:gsub('^!', ''):lower(),
            negated = name:sub(1, 1) == '!',
            operator = operator,
            value = unquote_defaults_value(value),
            text = option_text,
        }
        return
    end

    for token in option_text:gmatch('%S+') do
        local negation, flag_name = token:match('^(!?)([%w_]+)$')
        if flag_name then
            options[#options + 1] = {
                name = flag_name:lower(),
                negated = negation == '!',
                text = token,
            }
        end
    end
end

function M.parse_defaults_entry(line)
    local active = text.trim(tostring(line or ''))
    local prefix, raw_options = active:match('^(%S+)%s+(.+)$')
    if not prefix then
        return nil
    end

    local lowered_prefix = prefix:lower()
    local scope = nil
    if lowered_prefix == 'defaults' then
        scope = 'global'
    elseif lowered_prefix:match('^defaults[@:!>]') then
        scope = 'scoped'
    else
        return nil
    end

    local options = {}
    for _, option_text in ipairs(split_defaults_options(raw_options)) do
        append_defaults_option(options, option_text)
    end

    return {
        prefix = prefix,
        scope = scope,
        options = options,
    }
end

function M.get_defaults_flag_state(line, flag_name)
    local state = nil
    local defaults = M.parse_defaults_entry(line)
    if not defaults then
        return state
    end

    flag_name = tostring(flag_name or ''):lower()
    for _, option in ipairs(defaults.options) do
        if option.operator == nil and option.name == flag_name then
            state = not option.negated
        end
    end

    return state
end

function M.rewrite_defaults_without_flag(line, flag_name, want_negated)
    local active = text.trim((line:gsub('%s+#.*$', '')))
    if active == '' or active:match('^#') then
        return line, false
    end

    local defaults = M.parse_defaults_entry(active)
    if not defaults then
        return line, false
    end

    flag_name = tostring(flag_name or ''):lower()
    local tokens = {}
    local removed = false
    for _, option in ipairs(defaults.options) do
        if option.operator == nil and option.name == flag_name and option.negated == want_negated then
            removed = true
        else
            tokens[#tokens + 1] = option.text
        end
    end

    if not removed then
        return line, false
    end

    if #tokens == 0 then
        return nil, true
    end

    return defaults.prefix .. ' ' .. table.concat(tokens, ','), true
end

function M.load(paths, options)
    options = options or {}

    local dependencies = options.dependencies or {}
    local error_context = options.error_context
    local max_depth = options.max_depth or DEFAULT_MAX_DEPTH
    local state = {
        lines = {},
        files = {},
        audit_paths = {},
        permission_paths = {},
    }

    local file_set = {}
    local audit_path_set = {}
    local permission_path_set = {}
    local stack = {}

    local visit_path

    local function visit_directory(path, depth)
        record_unique_path(state.audit_paths, audit_path_set, path, 'directory')
        record_unique_path(state.permission_paths, permission_path_set, path, 'directory')

        local entries, err = list_directory_files(path, dependencies, error_context)
        if not entries then
            return nil, err
        end

        for _, entry in ipairs(entries) do
            record_unique_path(state.permission_paths, permission_path_set, entry, 'file')

            local ok, visit_err = visit_path(entry, depth + 1, false)
            if not ok then
                return nil, visit_err
            end
        end

        return true
    end

    visit_path = function(path, depth, record_path_for_audit)
        if depth > max_depth then
            return nil, format_depth_error(error_context)
        end
        if stack[path] then
            return nil, format_loop_error(error_context, path)
        end

        if record_path_for_audit ~= false then
            record_unique_path(state.audit_paths, audit_path_set, path, 'file')
        end
        record_unique_path(state.permission_paths, permission_path_set, path, 'file')

        local attr = dependencies.lfs_attributes(path)
        if not attr or attr.mode ~= 'file' then
            return nil, format_file_error(error_context, path)
        end

        local file = dependencies.io_open(path, 'r')
        if not file then
            return nil, format_file_error(error_context, path)
        end

        record_unique_file(state.files, file_set, path)
        stack[path] = true

        for line in file:lines() do
            local trimmed = text.trim(line)
            if trimmed ~= '' then
                local include_kind, include_arg = parse_include_directive(trimmed)
                if include_kind == 'include' then
                    local include_path = resolve_include_path(include_arg, path, dependencies.get_short_hostname)
                    local ok, err = visit_path(include_path, depth + 1)
                    if not ok then
                        file:close()
                        stack[path] = nil
                        return nil, err
                    end
                elseif include_kind == 'includedir' then
                    local include_path = resolve_include_path(include_arg, path, dependencies.get_short_hostname)
                    local ok, err = visit_directory(include_path, depth + 1)
                    if not ok then
                        file:close()
                        stack[path] = nil
                        return nil, err
                    end
                else
                    append_active_line(state.lines, path, trimmed)
                end
            end
        end

        file:close()
        stack[path] = nil
        return true
    end

    for _, path in ipairs(paths or {}) do
        local ok, err = visit_path(path, 1)
        if not ok then
            return nil, err
        end
    end

    return state
end

return M
