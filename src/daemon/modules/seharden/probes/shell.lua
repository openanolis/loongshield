local path_list = require('seharden.shared.path_list')
local umask_policy = require('seharden.umask_policy')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    expand_paths = function(paths)
        return path_list.expand_files(paths)
    end,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

local function expand_paths(paths)
    if type(paths) ~= "table" or #paths == 0 then
        return nil, "Probe requires a non-empty 'paths' list."
    end
    return _dependencies.expand_paths(paths)
end

local function line_unsets_tmout(line)
    for command in tostring(line or ""):gmatch("[^;|&]+") do
        if trim(command):match("^unset%s+TMOUT$") then
            return true
        end
    end

    return false
end

local function iter_file_lines(paths)
    local expanded, err = expand_paths(paths)
    if not expanded then
        return nil, err
    end

    local files = {}
    for _, path in ipairs(expanded) do
        local file = _dependencies.io_open(path, "r")
        if not file then
            return nil, string.format("Could not open shell profile file '%s' for reading.", path)
        end
        files[#files + 1] = { path = path, handle = file }
    end

    return files
end

function M.check_umask_value(params)
    if not params or params.value == nil then
        return nil, "Probe 'shell.check_umask_value' requires a 'value' parameter."
    end

    local baseline = umask_policy.parse_mask(params.baseline or "027")
    if not baseline then
        return nil, "Probe 'shell.check_umask_value' requires a valid octal 'baseline' parameter."
    end

    local classification = umask_policy.classify(params.value, baseline)
    return {
        compliant = classification == "compliant",
        value = tostring(params.value),
    }
end

function M.find_tmout_assignments(params)
    if not params then
        return nil, "Probe 'shell.find_tmout_assignments' requires parameters."
    end

    local max_value = tonumber(params.max_value) or 1800
    if max_value < 1 then
        return nil, "Probe 'shell.find_tmout_assignments' requires a positive 'max_value' parameter."
    end

    local files, err = iter_file_lines(params.paths)
    if not files then
        return nil, err
    end

    local details = {}
    local conflicts = {}

    for _, file_info in ipairs(files) do
        local line_number = 0
        for line in file_info.handle:lines() do
            line_number = line_number + 1
            local active = trim((line:gsub("%s+#.*$", "")))
            if active ~= "" and not active:match("^#") then
                if line_unsets_tmout(active) then
                    conflicts[#conflicts + 1] = {
                        path = file_info.path,
                        line = line_number,
                        value = "unset",
                    }
                end

                for value in active:gmatch("%f[%w]TMOUT=(%d+)") do
                    local numeric_value = tonumber(value)
                    local entry = {
                        path = file_info.path,
                        line = line_number,
                        value = numeric_value,
                    }
                    if numeric_value and numeric_value > 0 and numeric_value <= max_value then
                        details[#details + 1] = entry
                    else
                        conflicts[#conflicts + 1] = entry
                    end
                end
            end
        end
        file_info.handle:close()
    end

    return {
        count = #details,
        conflicting_count = #conflicts,
        details = details,
        conflicts = conflicts,
    }
end

function M.find_umask_commands(params)
    if not params then
        return nil, "Probe 'shell.find_umask_commands' requires parameters."
    end

    local baseline = umask_policy.parse_mask(params.baseline or "027")
    if not baseline then
        return nil, "Probe 'shell.find_umask_commands' requires a valid octal 'baseline' parameter."
    end

    local files, err = iter_file_lines(params.paths)
    if not files then
        return nil, err
    end

    local details = {}
    local conflicts = {}

    for _, file_info in ipairs(files) do
        local line_number = 0
        for line in file_info.handle:lines() do
            line_number = line_number + 1
            local active = trim((line:gsub("%s+#.*$", "")))
            if active ~= "" and not active:match("^#") then
                for value in active:gmatch("%f[%a]umask%s+([^%s;|&]+)") do
                    if value:sub(1, 1) ~= "-" then
                        local classification = umask_policy.classify(value, baseline)
                        local entry = {
                            path = file_info.path,
                            line = line_number,
                            value = value,
                        }

                        if classification == "compliant" then
                            details[#details + 1] = entry
                        elseif classification == "conflict" then
                            conflicts[#conflicts + 1] = entry
                        end
                    end
                end
            end
        end
        file_info.handle:close()
    end

    return {
        count = #details,
        conflicting_count = #conflicts,
        details = details,
        conflicts = conflicts,
    }
end

return M
