#!/usr/bin/env luajit

local capability = require('capability')

local file = ...

local cap = capability.get_proc()
local iab = capability.iab_get_proc()
print('proc: ', cap)
print('proc: ', iab)

local cap = capability.get_proc(1)
local iab = capability.iab_get_proc(1)
print('1: ', cap)
print('1: ', iab)

local uid = cap:nsowner()
print('nsowner: ', uid)

local res = cap:flag('effective', 'cap_chown')
print('set_flag: ', res)

local res = cap:set_file(file)
print('set_file: ', res)
