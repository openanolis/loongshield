local errno = require("errno")

local M = {
    name = "deny_tmp_marker",
    author = "LoongShield",
    description = "Deny access to /tmp/loongshield-lua-lsm-deny.",
    license = "MIT",
    version = 1,
}

function M.file_open(file)
    local path = file:path()
    if path == "/tmp/loongshield-lua-lsm-deny" then
        return false, errno.EPERM
    end
    return true
end

return M
