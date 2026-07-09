local M = {}

function M.parse(value)
    local ordered = {}
    local set = {}

    for option in tostring(value or ''):gmatch('[^,]+') do
        ordered[#ordered + 1] = option
        set[option] = true
    end

    return ordered, set
end

return M
