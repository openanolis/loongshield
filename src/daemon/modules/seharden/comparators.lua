local M = {}

M.is_falsy = function(a) return a == false or a == nil end
M.is_truthy = function(a) return a ~= false and a ~= nil end
M.is_false = function(a) return a == false end
M.is_true = function(a) return a == true end

M.equals = function(a, e) return a == e end
M.is_not_equal_to = function(a, e) return a ~= e end

local function to_numbers(a, e)
    local num_a, num_e = tonumber(a), tonumber(e)
    if num_a == nil or num_e == nil then
        return nil, nil
    end
    return num_a, num_e
end

local function compare(a, e, operator)
    local num_a, num_e = to_numbers(a, e)
    if num_a == nil or num_e == nil then
        return false
    end
    if operator == ">" then
        return num_a > num_e
    elseif operator == ">=" then
        return num_a >= num_e
    elseif operator == "<" then
        return num_a < num_e
    elseif operator == "<=" then
        return num_a <= num_e
    end
    return false
end

local function split_permission_digits(mode)
    local numeric_mode = tonumber(mode)
    if numeric_mode == nil or numeric_mode < 0 then
        return nil
    end

    return {
        math.floor(numeric_mode / 512) % 8,
        math.floor(numeric_mode / 64) % 8,
        math.floor(numeric_mode / 8) % 8,
        numeric_mode % 8,
    }
end

local function digit_is_subset(actual_digit, expected_digit)
    for _, bit in ipairs({ 4, 2, 1 }) do
        local actual_has_bit = actual_digit % (bit * 2) >= bit
        local expected_has_bit = expected_digit % (bit * 2) >= bit
        if actual_has_bit and not expected_has_bit then
            return false
        end
    end

    return true
end

M.is_greater_than = function(a, e)
    return compare(a, e, ">")
end

M.is_greater_than_or_equal_to = function(a, e)
    return compare(a, e, ">=")
end

M.is_less_than = function(a, e)
    return compare(a, e, "<")
end

M.is_less_than_or_equal_to = function(a, e)
    return compare(a, e, "<=")
end

M.mode_is_no_more_permissive = function(actual_mode, expected_mode)
    local actual_digits = split_permission_digits(actual_mode)
    local expected_digits = split_permission_digits(expected_mode)

    if actual_digits == nil or expected_digits == nil then
        return false
    end

    for index = 1, 4 do
        if not digit_is_subset(actual_digits[index], expected_digits[index]) then
            return false
        end
    end

    return true
end

M.has_key = function(tbl, key)
    if type(tbl) ~= 'table' then return false end
    return tbl[key] ~= nil
end

M.has_line_matching = function(actual_lines, expected_logic_tree)
    if type(actual_lines) ~= 'table' then return false end

    local function evaluate(line, node)
        if node.all_of then
            for _, child in ipairs(node.all_of) do
                if not evaluate(line, child) then return false end
            end
            return true
        elseif node.any_of then
            for _, child in ipairs(node.any_of) do
                if evaluate(line, child) then return true end
            end
            return false
        elseif node.pattern then
            if type(line) == 'string' then
                return line:match(node.pattern)
            end
            return false
        end
        return false
    end

    for _, line in ipairs(actual_lines) do
        if evaluate(line, expected_logic_tree) then
            return true
        end
    end

    return false
end

function M.for_all(actual_list, evaluator_func)
    if type(actual_list) ~= 'table' then return false end

    for index, item in ipairs(actual_list) do
        local passed, err = evaluator_func(item)
        if not passed then
            return false, {
                index = index,
                item = item,
                reason = err,
            }
        end
    end

    return true
end

return M
