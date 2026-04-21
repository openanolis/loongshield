local text = require('seharden.shared.text')
local M = {}

function M.parse_line(line)
    local trimmed = text.trim(line)
    if trimmed == "" or trimmed:match("^#") then
        return nil
    end

    local kind, remainder = trimmed:match("^(%S+)%s+(.+)$")
    if not kind or not remainder then
        return nil
    end

    local control
    local module_name
    local args_text

    if remainder:sub(1, 1) == "[" then
        control, module_name, args_text = remainder:match("^(%b[])%s+(%S+)%s*(.*)$")
    else
        control, module_name, args_text = remainder:match("^(%S+)%s+(%S+)%s*(.*)$")
    end

    if not control or not module_name then
        return nil
    end

    local args = {}
    for token in tostring(args_text or ""):gmatch("%S+") do
        args[#args + 1] = token
    end

    return {
        kind = kind,
        control = control,
        module = module_name,
        args = args,
    }
end

return M
