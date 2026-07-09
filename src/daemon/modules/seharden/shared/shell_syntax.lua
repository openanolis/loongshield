local M = {}

function M.trim(value)
    return (tostring(value or ''):match('^%s*(.-)%s*$'))
end

function M.strip_comment(line)
    return M.trim((tostring(line or ''):gsub('%s+#.*$', '')))
end

function M.line_unsets_tmout(line)
    for command in tostring(line or ''):gmatch('[^;|&]+') do
        if M.trim(command):match('^unset%s+TMOUT$') then
            return true
        end
    end

    return false
end

function M.line_sets_tmout_readonly(active)
    return active:match('^%s*typeset%s+%-xr%s+TMOUT=%d+%s*$') ~= nil
        or active:match('%f[%a]readonly%s+[^;|&]*%f[%w]TMOUT%f[%W]') ~= nil
end

function M.line_sets_tmout_export(active)
    return active:match('^%s*typeset%s+%-xr%s+TMOUT=%d+%s*$') ~= nil
        or active:match('%f[%a]export%s+[^;|&]*%f[%w]TMOUT%f[%W]') ~= nil
end

function M.tmout_values_from_line(active)
    local values = {}
    for value in tostring(active or ''):gmatch('%f[%w]TMOUT=(%d+)') do
        values[#values + 1] = tonumber(value)
    end
    return values
end

function M.line_mentions_tmout(active)
    return tostring(active or ''):match('%f[%w]TMOUT%f[%W]') ~= nil
end

return M
