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

local function parse_assignment(trimmed, opts)
    local key, value = trimmed:match("^([^=%s]+)%s*=%s*(.-)%s*$")
    if not key and opts.allow_whitespace_assignment ~= false then
        key, value = trimmed:match("^([%S]+)%s+(.-)%s*$")
    end
    return key, value
end

local function normalize_value(value, opts)
    value = value:gsub('^"', ''):gsub('"$', '')
    if opts.normalize_values == "lower" then
        value = value:lower()
    end
    return value
end

function M.parse_line(line, opts)
    opts = opts or {}

    local active = M.strip_inline_comment(line)
    local trimmed = text.trim(active)
    if trimmed == "" or trimmed:match("^#") then
        return nil
    end

    if trimmed:match("^%[[^%]]+%]$") then
        return { section = trimmed:match("^%[([^%]]+)%]$") }
    end

    local key, value = parse_assignment(trimmed, opts)
    if not key or value == nil then
        return nil
    end

    if opts.normalize_key then
        key = opts.normalize_key(key)
    end

    return {
        key = key,
        value = normalize_value(value, opts),
    }
end

function M.parse_entries(handle, opts)
    opts = opts or {}

    local entries = {}
    local current_section
    for line in handle:lines() do
        local parsed = M.parse_line(line, opts)
        if parsed and parsed.section and parsed.key == nil then
            current_section = parsed.section
        elseif parsed and (opts.section == nil or current_section == opts.section) then
            parsed.section = current_section
            entries[#entries + 1] = parsed
        end
    end

    return entries
end

function M.parse_handle(handle, opts)
    local values = {}
    for _, entry in ipairs(M.parse_entries(handle, opts)) do
        values[entry.key] = entry.value
    end
    return values
end

return M
