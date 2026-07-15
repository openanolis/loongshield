local lfs = require('lfs')
local fsutil = require('seharden.enforcers.fsutil')
local pam_parser = require('seharden.parsers.pam')
local text = require('seharden.shared.text')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    lfs_attributes = lfs.attributes,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    fs_stat = function(path)
        return require('fs').stat(path)
    end,
    fs_chmod = function(path, mode)
        return require('fs').chmod(path, mode)
    end,
    fs_chown = function(path, uid, gid)
        return require('fs').chown(path, uid, gid)
    end,
}

local _dependencies = {}
local VALID_KINDS = {
    auth = true,
    account = true,
    password = true,
    session = true,
}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local trim = text.trim

local function is_safe_path(path)
    return type(path) == 'string' and path ~= '' and not path:find('[%c\n\r]')
end

local function is_safe_token(token)
    return type(token) == 'string' and token ~= '' and not token:find('[%s%c]')
end

local function normalize_tokens(values, field_name)
    if values == nil then
        return {}
    end
    if type(values) ~= 'table' then
        return nil, string.format("pam.ensure_entry: '%s' must be a list when provided", field_name)
    end

    local normalized = {}
    for index, value in ipairs(values) do
        if not is_safe_token(value) then
            return nil, string.format("pam.ensure_entry: invalid %s[%d] token '%s'", field_name, index, tostring(value))
        end
        normalized[#normalized + 1] = value
    end

    return normalized
end

local function entry_has_args(args, required_args)
    if type(required_args) ~= 'table' or #required_args == 0 then
        return true
    end

    local present = {}
    for _, arg in ipairs(args or {}) do
        present[arg] = true
    end

    for _, arg in ipairs(required_args) do
        if not present[arg] then
            return false
        end
    end

    return true
end

function M.ensure_entry(params)
    if not params or not is_safe_path(params.path) then
        return nil, "pam.ensure_entry: requires a safe 'path' parameter"
    end
    if not VALID_KINDS[params.kind] then
        return nil, string.format("pam.ensure_entry: invalid kind '%s'", tostring(params and params.kind))
    end
    if not is_safe_token(params.module) then
        return nil, string.format("pam.ensure_entry: invalid module '%s'", tostring(params and params.module))
    end
    if type(params.control) ~= 'string' or params.control == '' or params.control:find('[%c\n\r]') then
        return nil, string.format("pam.ensure_entry: invalid control '%s'", tostring(params and params.control))
    end

    local args, args_err = normalize_tokens(params.args, 'args')
    if not args then
        return nil, args_err
    end
    local match_args, match_err = normalize_tokens(params.match_args, 'match_args')
    if not match_args then
        return nil, match_err
    end
    local anchor_args, anchor_err = normalize_tokens(params.anchor_args, 'anchor_args')
    if not anchor_args then
        return nil, anchor_err
    end

    local anchor_kind = params.anchor_kind
    local anchor_module = params.anchor_module
    if anchor_kind ~= nil and not VALID_KINDS[anchor_kind] then
        return nil, string.format("pam.ensure_entry: invalid anchor_kind '%s'", tostring(anchor_kind))
    end
    if anchor_module ~= nil and not is_safe_token(anchor_module) then
        return nil, string.format("pam.ensure_entry: invalid anchor_module '%s'", tostring(anchor_module))
    end

    local file_path = fsutil.resolve_symlink(params.path, _dependencies)

    local desired_line = string.format('%s %s %s', params.kind, params.control, params.module)
    if #args > 0 then
        desired_line = desired_line .. ' ' .. table.concat(args, ' ')
    end

    local original_lines, read_err = fsutil.read_lines(file_path, 'pam.ensure_entry', _dependencies, {
        missing_as_empty = true,
    })
    if not original_lines then
        return nil, read_err
    end

    local new_lines = {}
    local inserted = false

    for _, line in ipairs(original_lines) do
        local entry = pam_parser.parse_line(line)
        local is_target = entry
            and entry.kind == params.kind
            and entry.module == params.module
            and entry_has_args(entry.args, match_args)

        if is_target then
            if not inserted then
                new_lines[#new_lines + 1] = desired_line
                inserted = true
            end
        else
            local is_anchor = not inserted
                and entry
                and anchor_kind ~= nil
                and anchor_module ~= nil
                and entry.kind == anchor_kind
                and entry.module == anchor_module
                and entry_has_args(entry.args, anchor_args)

            if is_anchor then
                new_lines[#new_lines + 1] = desired_line
                inserted = true
            end

            new_lines[#new_lines + 1] = line
        end
    end

    if not inserted then
        new_lines[#new_lines + 1] = desired_line
    end

    if fsutil.lines_equal(original_lines, new_lines) then
        return true
    end

    return fsutil.write_lines_atomically_preserving_attrs(file_path, new_lines, 'pam.ensure_entry', _dependencies)
end

--- Add an option to matching PAM module lines if not already present.
-- params: { path, module, option, kind (optional) }
-- Matches lines where module appears in the given kind (default: any kind).
-- If the option is not present, appends it to the line.
function M.ensure_option(params)
    if not params or not is_safe_path(params.path) then
        return nil, "pam.ensure_option: requires a safe 'path' parameter"
    end
    if not is_safe_token(params.module) then
        return nil, string.format("pam.ensure_option: invalid module '%s'", tostring(params and params.module))
    end
    if not is_safe_token(params.option) then
        return nil, string.format("pam.ensure_option: invalid option '%s'", tostring(params and params.option))
    end

    local target_kind = params.kind
    if target_kind ~= nil and not VALID_KINDS[target_kind] then
        return nil, string.format("pam.ensure_option: invalid kind '%s'", tostring(target_kind))
    end

    local file_path = fsutil.resolve_symlink(params.path, _dependencies)

    local original_lines, read_err = fsutil.read_lines(file_path, 'pam.ensure_option', _dependencies, {
        missing_as_empty = true,
    })
    if not original_lines then
        return nil, read_err
    end

    local changed = false
    local new_lines = {}

    for _, line in ipairs(original_lines) do
        local entry = pam_parser.parse_line(line)
        local is_match = entry
            and entry.module == params.module
            and (target_kind == nil or entry.kind == target_kind)

        if is_match then
            -- Check if option is already present
            local has_option = false
            for _, arg in ipairs(entry.args or {}) do
                if arg == params.option then
                    has_option = true
                    break
                end
            end

            if not has_option then
                -- Append with a single separator, preserving the original
                -- line content (trailing whitespace trimmed first).
                local trimmed_line = line:gsub('%s+$', '')
                new_lines[#new_lines + 1] = trimmed_line .. ' ' .. params.option
                changed = true
            else
                new_lines[#new_lines + 1] = line
            end
        else
            new_lines[#new_lines + 1] = line
        end
    end

    if not changed then
        return true
    end

    return fsutil.write_lines_atomically_preserving_attrs(file_path, new_lines, 'pam.ensure_option', _dependencies)
end

--- Remove an option from matching PAM module lines if present.
-- params: { path, module, option (exact match) OR option_prefix (prefix match), kind (optional) }
-- When option_prefix is given, removes any arg starting with that prefix (e.g. "remember=" matches "remember=5").
-- Matches lines where module appears in the given kind (default: any kind).
function M.remove_option(params)
    if not params or not is_safe_path(params.path) then
        return nil, "pam.remove_option: requires a safe 'path' parameter"
    end
    if not is_safe_token(params.module) then
        return nil, string.format("pam.remove_option: invalid module '%s'", tostring(params and params.module))
    end

    local use_prefix = params.option_prefix ~= nil
    if use_prefix then
        if not is_safe_token(params.option_prefix) then
            return nil, string.format("pam.remove_option: invalid option_prefix '%s'", tostring(params.option_prefix))
        end
    else
        if not is_safe_token(params.option) then
            return nil, string.format("pam.remove_option: invalid option '%s'", tostring(params and params.option))
        end
    end

    local target_kind = params.kind
    if target_kind ~= nil and not VALID_KINDS[target_kind] then
        return nil, string.format("pam.remove_option: invalid kind '%s'", tostring(target_kind))
    end

    local file_path = fsutil.resolve_symlink(params.path, _dependencies)

    local original_lines, read_err = fsutil.read_lines(file_path, 'pam.remove_option', _dependencies, {
        missing_as_empty = true,
    })
    if not original_lines then
        return nil, read_err
    end

    local option_prefix = use_prefix and params.option_prefix or nil
    local option_exact = use_prefix and nil or params.option

    local changed = false
    local new_lines = {}

    for _, line in ipairs(original_lines) do
        local entry = pam_parser.parse_line(line)
        local is_match = entry
            and entry.module == params.module
            and (target_kind == nil or entry.kind == target_kind)

        if is_match then
            local filtered_args = {}
            for _, arg in ipairs(entry.args or {}) do
                local should_remove
                if option_prefix then
                    should_remove = arg:sub(1, #option_prefix) == option_prefix
                else
                    should_remove = arg == option_exact
                end
                if not should_remove then
                    filtered_args[#filtered_args + 1] = arg
                end
            end

            if #filtered_args ~= #(entry.args or {}) then
                -- Remove only the matched option token(s) from the raw line,
                -- preserving the original formatting and any in-line comment.
                local new_line = line
                for _, arg in ipairs(entry.args or {}) do
                    local should_remove
                    if option_prefix then
                        should_remove = arg:sub(1, #option_prefix) == option_prefix
                    else
                        should_remove = arg == option_exact
                    end
                    if should_remove then
                        new_line = new_line:gsub('%s' .. text.escape_lua_pattern(arg) .. '%s*', ' ', 1)
                    end
                end
                new_lines[#new_lines + 1] = new_line
                changed = true
            else
                new_lines[#new_lines + 1] = line
            end
        else
            new_lines[#new_lines + 1] = line
        end
    end

    if not changed then
        return true
    end

    return fsutil.write_lines_atomically_preserving_attrs(file_path, new_lines, 'pam.remove_option', _dependencies)
end

return M
