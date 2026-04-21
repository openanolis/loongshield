local M = {}

local function trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

function M.parse_mask(value)
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
        local has_digit_bit = next_digit % (bit * 2) >= bit

        if includes_bit and operator == "+" and has_digit_bit then
            next_digit = next_digit - bit
        elseif includes_bit and operator == "-" and not has_digit_bit then
            next_digit = next_digit + bit
        end
    end

    return next_digit
end

local function split_mask_digits(mask)
    if type(mask) ~= "number" or mask < 0 then
        return nil
    end

    return {
        math.floor(mask / 64) % 8,
        math.floor(mask / 8) % 8,
        mask % 8,
    }
end

local function join_mask_digits(digits)
    return (digits[1] * 64) + (digits[2] * 8) + digits[3]
end

local function evaluate_symbolic_mask(value, base_mask)
    local text = trim(value)
    if text == "" or text:find("%s") then
        return nil
    end

    local digits = split_mask_digits(base_mask)
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

    return join_mask_digits(digits)
end

function M.classify(value, baseline)
    local octal_value = M.parse_mask(value)
    if octal_value ~= nil then
        return is_at_least_restrictive(octal_value, baseline) and "compliant" or "conflict"
    end

    local minimum_mask = evaluate_symbolic_mask(value, 0)
    if minimum_mask == nil then
        return nil
    end

    if is_at_least_restrictive(minimum_mask, baseline) then
        return "compliant"
    end

    local maximum_mask = evaluate_symbolic_mask(value, 63)
    if maximum_mask == nil then
        return nil
    end

    if not is_at_least_restrictive(maximum_mask, baseline) then
        return "conflict"
    end

    return "indeterminate"
end

return M
