local lfs = require('lfs')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    lfs_attributes = lfs.attributes,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    fs_stat = function(path) return require('fs').stat(path) end,
    fs_chmod = function(path, mode) return require('fs').chmod(path, mode) end,
    fs_chown = function(path, uid, gid) return require('fs').chown(path, uid, gid) end,
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

local function trim(value)
    return tostring(value or ""):match("^%s*(.-)%s*$")
end

local function is_safe_path(path)
    return type(path) == "string" and path ~= "" and not path:find("[%c\n\r]")
end

local function is_safe_token(token)
    return type(token) == "string" and token ~= "" and not token:find("[%s%c]")
end

local function normalize_tokens(values, field_name)
    if values == nil then
        return {}
    end
    if type(values) ~= "table" then
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

local function parse_pam_line(line)
    local trimmed = trim(line)
    if trimmed == "" or trimmed:match("^#") then
        return nil
    end

    local kind, remainder = trimmed:match("^(%S+)%s+(.+)$")
    if not kind or not remainder then
        return nil
    end

    local control
    local module_name
    local args_text

    if remainder:sub(1, 1) == "[" then
        control, module_name, args_text = remainder:match("^(%b[])%s+(%S+)%s*(.*)$")
    else
        control, module_name, args_text = remainder:match("^(%S+)%s+(%S+)%s*(.*)$")
    end

    if not control or not module_name then
        return nil
    end

    local args = {}
    for token in tostring(args_text or ""):gmatch("%S+") do
        args[#args + 1] = token
    end

    return {
        kind = kind,
        control = control,
        module = module_name,
        args = args,
    }
end

local function entry_has_args(args, required_args)
    if type(required_args) ~= "table" or #required_args == 0 then
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

local function read_lines(path)
    local attr = _dependencies.lfs_attributes(path)
    if attr and attr.mode ~= "file" then
        return nil, string.format("pam.ensure_entry: path '%s' is a %s, not a file", path, tostring(attr.mode))
    end

    local file, err = _dependencies.io_open(path, "r")
    if not file then
        if attr then
            return nil, string.format("pam.ensure_entry: could not open '%s': %s", path, tostring(err))
        end
        return {}
    end

    local lines = {}
    for line in file:lines() do
        lines[#lines + 1] = line
    end
    file:close()
    return lines
end

local function lines_equal(left, right)
    if #left ~= #right then
        return false
    end

    for index = 1, #left do
        if left[index] ~= right[index] then
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
    if type(params.control) ~= "string" or params.control == "" or params.control:find("[%c\n\r]") then
        return nil, string.format("pam.ensure_entry: invalid control '%s'", tostring(params and params.control))
    end

    local args, args_err = normalize_tokens(params.args, "args")
    if not args then
        return nil, args_err
    end
    local match_args, match_err = normalize_tokens(params.match_args, "match_args")
    if not match_args then
        return nil, match_err
    end
    local anchor_args, anchor_err = normalize_tokens(params.anchor_args, "anchor_args")
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

    if fsutil.is_symlink(params.path, _dependencies) then
        return nil, string.format("pam.ensure_entry: refusing to overwrite symlink '%s'", params.path)
    end

    local desired_line = string.format("%s %s %s", params.kind, params.control, params.module)
    if #args > 0 then
        desired_line = desired_line .. " " .. table.concat(args, " ")
    end

    local original_lines, read_err = read_lines(params.path)
    if not original_lines then
        return nil, read_err
    end

    local new_lines = {}
    local inserted = false

    for _, line in ipairs(original_lines) do
        local entry = parse_pam_line(line)
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

    if lines_equal(original_lines, new_lines) then
        return true
    end

    return fsutil.write_lines_atomically_preserving_attrs(
        params.path,
        new_lines,
        "pam.ensure_entry",
        _dependencies
    )
end

return M
