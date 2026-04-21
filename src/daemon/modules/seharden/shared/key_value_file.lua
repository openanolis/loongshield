local text = require('seharden.shared.text')

local M = {}

function M.strip_inline_comment(line)
    local in_quote = false

    for index = 1, #line do
        local char = line:sub(index, index)
        if char == '"' then
            in_quote = not in_quote
        elseif char == "#" and not in_quote then
            local previous = index > 1 and line:sub(index - 1, index - 1) or nil
            if previous == nil or previous:match("%s") then
                return line:sub(1, index - 1)
            end
        end
    end

    return line
end

function M.parse_handle(handle, opts)
    opts = opts or {}

    local values = {}
    for line in handle:lines() do
        local active = M.strip_inline_comment(line)
        local trimmed = text.trim(active)
        if trimmed ~= "" and not trimmed:match("^#") then
            local key, value = trimmed:match("^([^=%s]+)%s*=%s*(.-)%s*$")
            if not key then
                key, value = trimmed:match("^([%S]+)%s+(.-)%s*$")
            end

            if key and value then
                value = value:gsub('^"', ''):gsub('"$', '')
                if opts.normalize_values == "lower" then
                    value = value:lower()
                end
                values[key] = value
            end
        end
    end

    return values
end

return M
