local log = { _version = "0.2.0" }
local unistd = require("posix.unistd")

log.usecolor = true
log.outfile = nil
log.level = "info"

local modes = {
    { name = "trace", color = "\27[34m", },
    { name = "debug", color = "\27[36m", },
    { name = "info",  color = "\27[32m", },
    { name = "warn",  color = "\27[33m", },
    { name = "error", color = "\27[31m", },
    { name = "fatal", color = "\27[35m", },
}

local levels = {}
for i, v in ipairs(modes) do
    levels[v.name] = i
end

local styles = {
    reset = "\27[0m",
    bold = "\27[1m",
    dim = "\27[2m",
    red = "\27[31m",
    green = "\27[32m",
    yellow = "\27[33m",
    blue = "\27[34m",
    cyan = "\27[36m",
}

local function normalize_source(source)
    return tostring(source):gsub('^%[string "(.-)"%]$', '%1')
end

function log.colors_enabled()
    if not log.usecolor then
        return false
    end

    if os.getenv("NO_COLOR") then
        return false
    end

    local term = os.getenv("TERM")
    if term == nil or term == "" or term == "dumb" then
        return false
    end

    local ok, is_tty = pcall(unistd.isatty, 1)
    return ok and is_tty or false
end

function log.style(text, ...)
    local content = tostring(text)
    if not log.colors_enabled() then
        return content
    end

    local prefix = {}
    for i = 1, select("#", ...) do
        local style = styles[select(i, ...)]
        if style then
            prefix[#prefix + 1] = style
        end
    end

    if #prefix == 0 then
        return content
    end

    return table.concat(prefix) .. content .. styles.reset
end

function log.setLevel(newLevel)
    if newLevel and levels[newLevel:lower()] then
        log.level = newLevel:lower()
        log.debug("Log level set to '%s'", log.level)
    else
        log.warn("Attempted to set invalid log level: '%s'", tostring(newLevel))
    end
end

for i, mode in ipairs(modes) do
    local nameupper = mode.name:upper()

    log[mode.name] = function(fmt, ...)
        if i < levels[log.level] then
            return
        end

        local msg
        if select('#', ...) > 0 then
            msg = string.format(fmt, ...)
        else
            msg = tostring(fmt)
        end

        local info = debug.getinfo(2, "Sl")
        local lineinfo = normalize_source(info.short_src) .. ":" .. info.currentline

        print(string.format("%s[%-6s%s]%s %s: %s",
            log.colors_enabled() and mode.color or "",
            nameupper,
            os.date("%H:%M:%S"),
            log.colors_enabled() and "\27[0m" or "",
            lineinfo,
            msg))

        if log.outfile then
            local fp = io.open(log.outfile, "a")
            if fp then
                local str = string.format("[%-6s%s] %s: %s\n",
                    nameupper, os.date(), lineinfo, msg)
                fp:write(str)
                fp:close()
            end
        end
    end
end

return log
