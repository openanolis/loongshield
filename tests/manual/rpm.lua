#!/usr/bin/env luajit

local rpm = require('lrpm')

--[[
local confdir = rpm.configdir()

local macrofiles = {
    confdir .. '/macros',
    confdir .. '/macros.d/macros.*',
    confdir .. '/platform/%{_target}/macros',
    confdir .. '/fileattrs/*.attr',
    confdir .. '/redhat/macros',
    '/etc/rpm/macros.*',
    '/etc/rpm/macros',
    '/etc/rpm/%{_target}/macros',
    '~/.rpmmacros'
}

local mf = rpm.getpath(table.concat(macrofiles, ':'))
rpm.initmacros(mf)
print('mf: ', mf)
--]]

rpm.pushmacro('_dbpath', '/var/lib/rpm')
local dbpath = rpm.getpath('%{_dbpath}')
print('dbpath: ', dbpath)

local ts = rpm.tscreate()
ts:rootdir('/')
print('ts: ', ts, ts:rootdir())

local num = 0
for package in ts:packages() do
    local name = package:name()
    local version = package:version()
    local release = package:release()
    local vendor = package:vendor()
    local license = package:license()
    local url = package:url()
    local s = string.format('%-20s  %-20s  %-20s  %-20s  %-20s  %-20s',
        name, version, url, release, vendor, license)
    print(s)
    num = num + 1

    for file in package:files() do
        local index = file:index()
        local name = file:name()
        local size = file:size()
        local s = string.format('  %4d  %4d K  %s',
            index, size / 1024, name)
        print(s)
    end
end

print(string.format('%d packages.', num))
