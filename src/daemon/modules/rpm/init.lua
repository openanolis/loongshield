#!/usr/bin/env luajit

local cli = require('rpm.cli')

return {
    init = function() return true end,
    exit = function() return true end,
    run = cli.run,
    setstatus = function() return true end
}
