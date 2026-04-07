local file_probe = require('seharden.probes.file')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    expand_paths = function(paths)
        local result, err = file_probe.list_paths({ paths = paths })
        if not result then
            return nil, err
        end

        local expanded = {}
        for _, item in ipairs(result.details or {}) do
            expanded[#expanded + 1] = item.path
        end
        return expanded
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

local function parse_octal(value)
    local text = trim(value)
    if text == "" or not text:match("^[0-7]+$") then
        return nil
    end
    return tonumber(text, 8)
end

local function has_bit(value, bit)
    return math.floor(value / bit) % 2 == 1
end

local function is_at_least_restrictive(actual, baseline)
    local bit = 1
    while bit <= 256 do
        if has_bit(baseline, bit) and not has_bit(actual, bit) then
            return false
        end
        bit = bit * 2
    end
    return true
end

local function parse_symbolic_permissions(value)
    local bits = 0

    for char in tostring(value or ""):gmatch(".") do
        if char == "r" then
            bits = bits + 4
        elseif char == "w" then
            bits = bits + 2
        elseif char == "x" then
            bits = bits + 1
        else
            return nil
        end
    end

    return bits
end

local function for_each_symbolic_target(who, callback)
    local applied = false

    if who == "" or who:find("a", 1, true) then
        for index = 1, 3 do
            callback(index)
        end
        return true
    end

    for index, class in ipairs({ "u", "g", "o" }) do
        if who:find(class, 1, true) then
            callback(index)
            applied = true
        end
    end

    return applied
end

local function apply_mask_digit_operation(current_digit, operator, permission_bits)
    if operator == "=" then
        return 7 - permission_bits
    end

    local next_digit = current_digit
    for _, bit in ipairs({ 4, 2, 1 }) do
        local includes_bit = permission_bits % (bit * 2) >= bit
        local has_bit = next_digit % (bit * 2) >= bit

        if includes_bit and operator == "+" and has_bit then
            next_digit = next_digit - bit
        elseif includes_bit and operator == "-" and not has_bit then
            next_digit = next_digit + bit
        end
    end

    return next_digit
end

local function split_umask_digits(mask)
    if type(mask) ~= "number" or mask < 0 then
        return nil
    end

    return {
        math.floor(mask / 64) % 8,
        math.floor(mask / 8) % 8,
        mask % 8,
    }
end

local function join_umask_digits(digits)
    return (digits[1] * 64) + (digits[2] * 8) + digits[3]
end

local function evaluate_symbolic_umask(value, base_mask)
    local text = trim(value)
    if text == "" or text:find("%s") then
        return nil
    end

    local digits = split_umask_digits(base_mask)
    if digits == nil then
        return nil
    end

    for clause in text:gmatch("[^,]+") do
        local who, operator, perms = clause:match("^([augo]*)([=+-])([rwx]*)$")
        if operator == nil then
            return nil
        end
        if perms == "" and operator ~= "=" then
            return nil
        end

        local permission_bits = parse_symbolic_permissions(perms)
        if permission_bits == nil then
            return nil
        end

        local ok = for_each_symbolic_target(who, function(index)
            digits[index] = apply_mask_digit_operation(digits[index], operator, permission_bits)
        end)
        if not ok then
            return nil
        end
    end

    return join_umask_digits(digits)
end

local function classify_umask_value(value, baseline)
    local octal_value = parse_octal(value)
    if octal_value ~= nil then
        return is_at_least_restrictive(octal_value, baseline) and "compliant" or "conflict"
    end

    local minimum_mask = evaluate_symbolic_umask(value, 0)
    if minimum_mask == nil then
        return nil
    end

    if is_at_least_restrictive(minimum_mask, baseline) then
        return "compliant"
    end

    local maximum_mask = evaluate_symbolic_umask(value, 63)
    if maximum_mask == nil then
        return nil
    end

    if not is_at_least_restrictive(maximum_mask, baseline) then
        return "conflict"
    end

    return "indeterminate"
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

    local baseline = parse_octal(params.baseline or "027")
    if not baseline then
        return nil, "Probe 'shell.check_umask_value' requires a valid octal 'baseline' parameter."
    end

    local classification = classify_umask_value(params.value, baseline)
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

    local baseline = parse_octal(params.baseline or "027")
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
                        local classification = classify_umask_value(value, baseline)
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
