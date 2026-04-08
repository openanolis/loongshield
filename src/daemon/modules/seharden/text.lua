local M = {}

function M.trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

function M.glob_to_pattern(glob)
    glob = tostring(glob or "")

    local pattern = { "^" }
    local index = 1

    while index <= #glob do
        local char = glob:sub(index, index)

        if char == "*" then
            pattern[#pattern + 1] = ".*"
        elseif char == "?" then
            pattern[#pattern + 1] = "."
        elseif char == "[" then
            local class_end = glob:find("]", index + 1, true)
            if class_end then
                local class = glob:sub(index + 1, class_end - 1)
                if class:sub(1, 1) == "!" then
                    class = "^" .. class:sub(2)
                end
                pattern[#pattern + 1] = "[" .. class .. "]"
                index = class_end
            else
                pattern[#pattern + 1] = "%["
            end
        elseif char:match("[%^%$%(%)%%%.%+%-%/]") then
            pattern[#pattern + 1] = "%" .. char
        else
            pattern[#pattern + 1] = char
        end

        index = index + 1
    end

    pattern[#pattern + 1] = "$"
    return table.concat(pattern)
end

return M
