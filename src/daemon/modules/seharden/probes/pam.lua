local common = require('seharden.pam_common')
local faillock = require('seharden.pam.faillock')
local password_history = require('seharden.pam.password_history')
local pwquality = require('seharden.pam.pwquality')
local wheel = require('seharden.pam.wheel')
local M = {}

function M._test_set_dependencies(deps)
    common._test_set_dependencies(deps)
end

M._test_set_dependencies()

function M.check_password_history(params)
    return password_history.check(params)
end

function M.inspect_pwquality(params)
    return pwquality.inspect(params)
end

function M.inspect_faillock(params)
    return faillock.inspect(params)
end

function M.inspect_wheel(params)
    return wheel.inspect(params)
end

return M
