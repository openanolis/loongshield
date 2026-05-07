local lfs = require('lfs')
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
    local in_quote = false
    for index = 1, #line do
        local char = line:sub(index, index)
        if char == '"' then
            in_quote = not in_quote
        elseif char == "#" and not in_quote then
            return line:sub(1, index - 1)
        end
    end
    return line
end

local function unquote(value)
    value = tostring(value or "")
    local first = value:sub(1, 1)
    local last = value:sub(-1)
    if #value >= 2 and ((first == '"' and last == '"') or (first == "'" and last == "'")) then
        return value:sub(2, -2)
    end
    return value
end

local function commandline_from_line(line)
    local trimmed = text.trim(strip_inline_comment(line))
    if trimmed == "" then
        return nil
    end

    local kernelopts = trimmed:match("^kernelopts=(.+)$")
    if kernelopts then
        return unquote(kernelopts)
    end

    local grub_cmdline = trimmed:match("^GRUB_CMDLINE_LINUX%s*=%s*(.+)$")
    if grub_cmdline then
        return unquote(grub_cmdline)
    end

    local linux_args = trimmed:match("^linux[%w_%-]*%s+%S+%s+(.+)$")
        or trimmed:match("^kernel%s+%S+%s+(.+)$")
    return linux_args
end

local function extract_numeric_parameter(commandline, name)
    for token in tostring(commandline or ""):gmatch("%S+") do
        local value = token:match("^" .. name:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1") .. "=(%d+)$")
        if value then
            return tonumber(value)
        end
    end
    return nil
end

local function inspect_file(path, name, min_value)
    local file, err = _dependencies.io_open(path, "r")
    if not file then
        return nil, string.format("Could not open boot configuration '%s': %s", path, tostring(err))
    end

    local details = {}
    for line in file:lines() do
        local commandline = commandline_from_line(line)
        if commandline then
            local value = extract_numeric_parameter(commandline, name)
            details[#details + 1] = {
                path = path,
                commandline = commandline,
                value = value,
                configured = value ~= nil and value >= min_value,
            }
        end
    end
    file:close()
    return details
end

local function collect_details(paths, name, min_value)
    local details = {}
    local files = path_list.expand_files(paths)
    table.sort(files)

    for _, path in ipairs(files) do
        local file_details, err = inspect_file(path, name, min_value)
        if not file_details then
            return nil, #files, err
        end
        for _, detail in ipairs(file_details) do
            details[#details + 1] = detail
        end
    end

    return details, #files, nil
end

local function summarize(details, checked_files)
    local violation_count = 0
    for _, detail in ipairs(details) do
        if not detail.configured then
            violation_count = violation_count + 1
        end
    end

    return {
        checked_files = checked_files,
        checked_count = #details,
        violation_count = violation_count,
        all_configured = #details > 0 and violation_count == 0,
        details = details,
    }
end

function M.inspect_kernel_parameter(params)
    params = params or {}
    if type(params.name) ~= "string" or params.name == "" then
        return nil, "Probe 'boot.inspect_kernel_parameter' requires a non-empty 'name' parameter."
    end

    local min_value = tonumber(params.numeric_min) or 0
    local boot_paths = params.boot_paths or {
        "/boot/grub2/grub.cfg",
        "/boot/grub2/grubenv",
        "/boot/efi/EFI/*/grub.cfg",
    }
    local default_paths = params.default_paths or { "/etc/default/grub" }

    local boot_details, boot_files, boot_err = collect_details(boot_paths, params.name, min_value)
    if not boot_details then
        return {
            available = false,
            error = boot_err,
            boot_configured = false,
            default_configured = false,
            all_configured = false,
            details = {},
        }
    end

    local default_details, default_files, default_err = collect_details(default_paths, params.name, min_value)
    if not default_details then
        return {
            available = false,
            error = default_err,
            boot_configured = false,
            default_configured = false,
            all_configured = false,
            details = {},
        }
    end

    local boot = summarize(boot_details, boot_files)
    local defaults = summarize(default_details, default_files)

    return {
        available = true,
        boot_configured = boot.all_configured,
        default_configured = defaults.all_configured,
        all_configured = boot.all_configured and defaults.all_configured,
        boot_checked_count = boot.checked_count,
        default_checked_count = defaults.checked_count,
        boot_checked_files = boot.checked_files,
        default_checked_files = defaults.checked_files,
        violation_count = boot.violation_count + defaults.violation_count,
        details = {
            boot = boot.details,
            defaults = defaults.details,
        },
    }
end

return M
