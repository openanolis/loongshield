#!/usr/bin/env luajit

local mount = require('mount')

print('version: ', mount.version())

local features = mount.features()
print('features: ', table.concat(features, ','))

print()

local ctx = mount.new_context()
local mtab = ctx:get_mtab()
for fs in mtab:fs() do
    local s = string.format('%s on %s type %s (%s)',
        fs:source(), fs:target(),
        fs:fstype(), fs:options())
    print(s)
end
