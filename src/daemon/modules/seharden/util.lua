local lfs = require('lfs')
local lyaml = require('lyaml')

local function read_file_content(path)
    local attr, err = lfs.attributes(path)
    if not attr then
        return nil, err or "File not found"
    end

    if attr.mode ~= "file" then
        return nil, string.format("Path is a %s, not a file", attr.mode)
    end

    local f, open_err = io.open(path, "r")
    if not f then
        return nil, open_err
    end

    local content, read_err = f:read("*a")
    f:close()

    if not content then
        return nil, read_err
    end

    return content
end

local function serialize_for_log(value)
    if type(value) == 'table' then
        return lyaml.dump({ value }):match("---(.-)\n%.%.%.\n$") or tostring(value)
    end
    if value == nil then return "nil" end
    return "'" .. tostring(value) .. "'"
end

return {
    read_file_content = read_file_content,
    serialize_for_log = serialize_for_log
}
