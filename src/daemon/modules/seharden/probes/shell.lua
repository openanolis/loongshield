local path_list = require('seharden.shared.path_list')
local shell_syntax = require('seharden.shared.shell_syntax')
local umask_policy = require('seharden.shared.umask_policy')
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

local function expand_paths(paths)
    if type(paths) ~= 'table' or #paths == 0 then
        return nil, "Probe requires a non-empty 'paths' list."
    end
    return _dependencies.expand_paths(paths)
end

local function iter_file_lines(paths)
    local expanded, err = expand_paths(paths)
    if not expanded then
        return nil, err
    end

    local files = {}
    for _, path in ipairs(expanded) do
        local file = _dependencies.io_open(path, 'r')
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

    local baseline = umask_policy.parse_mask(params.baseline or '027')
    if not baseline then
        return nil, "Probe 'shell.check_umask_value' requires a valid octal 'baseline' parameter."
    end

    local classification = umask_policy.classify(params.value, baseline)
    return {
        compliant = classification == 'compliant',
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
            local active = shell_syntax.strip_comment(line)
            if active ~= '' and not active:match('^#') then
                if shell_syntax.line_unsets_tmout(active) then
                    conflicts[#conflicts + 1] = {
                        path = file_info.path,
                        line = line_number,
                        value = 'unset',
                    }
                end

                for _, numeric_value in ipairs(shell_syntax.tmout_values_from_line(active)) do
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

function M.inspect_tmout(params)
    params = params or {}

    local max_value = tonumber(params.max_value) or 900
    if max_value < 1 then
        return nil, "Probe 'shell.inspect_tmout' requires a positive 'max_value' parameter."
    end

    local files, err = iter_file_lines(params.paths)
    if not files then
        return nil, err
    end

    local details = {}
    local compliant_files = {}
    local saw_tmout = false

    for _, file_info in ipairs(files) do
        local file_saw_tmout = false
        local file_has_good_value = false
        local file_has_readonly = false
        local file_has_export = false
        local line_number = 0

        for line in file_info.handle:lines() do
            line_number = line_number + 1
            local active = shell_syntax.strip_comment(line)
            if active ~= '' and not active:match('^#') and shell_syntax.line_mentions_tmout(active) then
                saw_tmout = true
                file_saw_tmout = true

                if shell_syntax.line_unsets_tmout(active) then
                    details[#details + 1] = {
                        path = file_info.path,
                        line = line_number,
                        reason = 'tmout_unset',
                    }
                end

                if shell_syntax.line_sets_tmout_readonly(active) then
                    file_has_readonly = true
                end
                if shell_syntax.line_sets_tmout_export(active) then
                    file_has_export = true
                end

                for _, value in ipairs(shell_syntax.tmout_values_from_line(active)) do
                    if value > 0 and value <= max_value then
                        file_has_good_value = true
                    else
                        details[#details + 1] = {
                            path = file_info.path,
                            line = line_number,
                            value = value,
                            reason = 'tmout_value_invalid',
                        }
                    end
                end
            end
        end
        file_info.handle:close()

        if file_saw_tmout then
            if not file_has_good_value then
                details[#details + 1] = { path = file_info.path, reason = 'tmout_value_missing' }
            end
            if not file_has_readonly then
                details[#details + 1] = { path = file_info.path, reason = 'tmout_readonly_missing' }
            end
            if not file_has_export then
                details[#details + 1] = { path = file_info.path, reason = 'tmout_export_missing' }
            end
            if file_has_good_value and file_has_readonly and file_has_export then
                compliant_files[#compliant_files + 1] = file_info.path
            end
        end
    end

    if not saw_tmout then
        details[#details + 1] = { reason = 'tmout_not_configured' }
    end

    return {
        configured = saw_tmout and #compliant_files > 0 and #details == 0,
        count = #details,
        compliant_file_count = #compliant_files,
        compliant_files = compliant_files,
        details = details,
    }
end

function M.find_umask_commands(params)
    if not params then
        return nil, "Probe 'shell.find_umask_commands' requires parameters."
    end

    local baseline = umask_policy.parse_mask(params.baseline or '027')
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
            local active = shell_syntax.strip_comment(line)
            if active ~= '' and not active:match('^#') then
                for value in active:gmatch('%f[%a]umask%s+([^%s;|&]+)') do
                    if value:sub(1, 1) ~= '-' then
                        local classification = umask_policy.classify(value, baseline)
                        local entry = {
                            path = file_info.path,
                            line = line_number,
                            value = value,
                        }

                        if classification == 'compliant' then
                            details[#details + 1] = entry
                        elseif classification == 'conflict' then
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
