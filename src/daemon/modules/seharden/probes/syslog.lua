local comparators = require('seharden.comparators')
local lfs = require('lfs')
local log = require('runtime.log')
local path_list = require('seharden.shared.path_list')
local text = require('seharden.shared.text')

local M = {}

local _default_dependencies = {
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
    path_list._test_set_dependencies({
        lfs_attributes = _dependencies.lfs_attributes,
        lfs_dir = _dependencies.lfs_dir,
    })
end

M._test_set_dependencies()

local function strip_inline_comment(line)
    local in_single_quote = false
    local in_double_quote = false

    for index = 1, #line do
        local char = line:sub(index, index)
        if char == "'" and not in_double_quote then
            in_single_quote = not in_single_quote
        elseif char == '"' and not in_single_quote then
            in_double_quote = not in_double_quote
        elseif char == "#" and not in_single_quote and not in_double_quote then
            return line:sub(1, index - 1)
        end
    end

    return line
end

local function expand_config_paths(paths)
    local files = path_list.expand_files(paths or {
        "/etc/rsyslog.conf",
        "/etc/rsyslog.d/*.conf",
    })
    table.sort(files)
    return files
end

local function parse_octal_mode(value)
    local digits = tostring(value or ""):match("^0?([0-7][0-7][0-7][0-7]?)$")
    if not digits then
        return nil
    end
    return tonumber(digits, 8)
end

local function parse_named_arg(line, name)
    local value = line:match(name .. '%s*=%s*"([^"]+)"')
        or line:match(name .. "%s*=%s*'([^']+)'")
        or line:match(name .. "%s*=%s*([^,%s%)]+)")
    return value and value:lower() or nil
end

local function inspect_line(line)
    local trimmed = text.trim(strip_inline_comment(line))
    local lower = trimmed:lower()
    if lower == "" then
        return {}
    end

    local evidence = {}
    local file_create_mode = lower:match("^%$filecreatemode%s+([^%s]+)")
    if file_create_mode then
        evidence.file_create_mode = file_create_mode
    end

    local module_load = parse_named_arg(lower, "load")
    if lower:match("^module%s*%(") and module_load == "imtcp" then
        evidence.remote_input = true
        evidence.remote_input_type = "module(load=\"imtcp\")"
    end

    local input_type = parse_named_arg(lower, "type")
    if lower:match("^input%s*%(") and input_type == "imtcp" then
        evidence.remote_input = true
        evidence.remote_input_type = "input(type=\"imtcp\")"
    end

    if lower:match("^%$modload%s+imtcp%s*$") then
        evidence.remote_input = true
        evidence.remote_input_type = "$ModLoad imtcp"
    elseif lower:match("^%$inputtcpserverrun%s+%S+") then
        evidence.remote_input = true
        evidence.remote_input_type = "$InputTCPServerRun"
    end

    return evidence
end

local function inspect_files(files, params)
    local file_create_mode_details = {}
    local file_create_mode_violation_count = 0
    local remote_input_details = {}

    local max_file_mode = parse_octal_mode(params.require_file_create_mode_max)

    for _, path in ipairs(files) do
        local file, err = _dependencies.io_open(path, "r")
        if not file then
            log.warn("Could not open rsyslog config '%s': %s", path, tostring(err))
            return nil, string.format("Could not open rsyslog config '%s': %s", path, tostring(err))
        end

        local line_number = 0
        for line in file:lines() do
            line_number = line_number + 1
            local evidence = inspect_line(line)

            if evidence.file_create_mode then
                local mode = parse_octal_mode(evidence.file_create_mode)
                local configured = max_file_mode ~= nil
                    and mode ~= nil
                    and comparators.mode_is_no_more_permissive(mode, max_file_mode)
                file_create_mode_details[#file_create_mode_details + 1] = {
                    path = path,
                    line = line_number,
                    value = evidence.file_create_mode,
                    mode = mode,
                    configured = configured,
                }
                if not configured then
                    file_create_mode_violation_count = file_create_mode_violation_count + 1
                end
            end

            if evidence.remote_input then
                remote_input_details[#remote_input_details + 1] = {
                    path = path,
                    line = line_number,
                    type = evidence.remote_input_type,
                }
            end
        end
        file:close()
    end

    return {
        file_create_mode_details = file_create_mode_details,
        file_create_mode_violation_count = file_create_mode_violation_count,
        remote_input_details = remote_input_details,
    }
end

function M.inspect_rsyslog_effective_config(params)
    params = params or {}
    local files = expand_config_paths(params.paths)

    if #files == 0 then
        return {
            available = false,
            error = "No rsyslog configuration files were available.",
            checked_count = 0,
            file_create_mode_found = false,
            file_create_mode_ok = false,
            file_create_mode_violation_count = 0,
            remote_input_enabled = false,
            remote_input_count = 0,
            all_configured = false,
            details = {},
        }
    end

    local evidence, err = inspect_files(files, params)
    if not evidence then
        return {
            available = false,
            error = err,
            checked_count = #files,
            file_create_mode_found = false,
            file_create_mode_ok = false,
            file_create_mode_violation_count = 0,
            remote_input_enabled = false,
            remote_input_count = 0,
            all_configured = false,
            details = {},
        }
    end

    local checks = {}
    local all_configured = true
    local file_create_mode_found = #evidence.file_create_mode_details > 0
    local file_create_mode_ok = true

    if params.require_file_create_mode_max ~= nil then
        file_create_mode_ok = file_create_mode_found
            and evidence.file_create_mode_violation_count == 0
        all_configured = all_configured and file_create_mode_ok
        checks[#checks + 1] = "file_create_mode"
    end

    local remote_input_enabled = #evidence.remote_input_details > 0
    if params.disallow_remote_input then
        all_configured = all_configured and not remote_input_enabled
        checks[#checks + 1] = "remote_input"
    end

    return {
        available = true,
        checked_count = #files,
        checks = checks,
        file_create_mode_found = file_create_mode_found,
        file_create_mode_ok = file_create_mode_ok,
        file_create_mode_violation_count = evidence.file_create_mode_violation_count,
        file_create_mode_details = evidence.file_create_mode_details,
        remote_input_enabled = remote_input_enabled,
        remote_input_count = #evidence.remote_input_details,
        remote_input_details = evidence.remote_input_details,
        all_configured = all_configured,
        details = files,
    }
end

return M
