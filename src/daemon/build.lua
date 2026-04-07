#!/usr/bin/env luajit

package.path = 'modules/?.lua'

local ramfs = require('runtime.ramfs')


local r = ramfs.mkramfs('modules/runtime/ramfs.lua', 'bin_ramfs_luac.h')
assert(r)

local dirs = {
    {
        path = 'modules',
        level = 1
    }
}
local r = ramfs.mkinitrd('bin_initrd_tar.h', dirs)
assert(r)
