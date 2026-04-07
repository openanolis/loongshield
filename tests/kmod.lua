#!/usr/bin/env luajit

local kmod = require("kmod")

local cmd, file = ...

local ctx = kmod.ctx_new()

local function lsmod()
    print("Module                  Size  Used by");
    for mod in ctx:modules_from_loaded() do
        local s = string.format("%-19s %d  %d",
            mod:name(), mod:size(), mod:refcnt())
        local holders = {}
        for hmod in mod:holders() do
            table.insert(holders, hmod:name())
        end
        print(s .. ' ' .. table.concat(holders, ','))
    end
end

local function modinfo(path)
    local mod, errno, err = ctx:module_from_path(path)
    if not mod then
        print("errno = ", errno, err)
        return
    end
    print(string.format("filename:       %s", mod:path()))
    for k, v in mod:infos() do
        local len = string.len(k)
        local s
        if k == 'sig_key' or k == 'signature' then
            local lines = {}
            local line = {}
            for i = 1, string.len(v) do
                table.insert(line, string.format("%02X", string.byte(v, i)))
                if i % 20 == 0 then
                    table.insert(lines, table.concat(line, ':'))
                    line = {}
                end
            end
            if next(line) then
                table.insert(lines, table.concat(line, ':'))
            end
            s = table.concat(lines, ":\n\t\t")
        else
            s = v
        end
        local str = string.format("%s:%s%s", k, string.rep(" ", 15 - len), s)
        print(str)
    end
end

local function insmod(path)
    local mod, errno, err = ctx:module_from_path(path)
    if not mod then
        print("errno = ", errno, err)
        return
    end
    local result, errno, err = mod:insert()
    if not result then
        print("errno = ", errno, err)
    end
end

local function rmmod(path)
    local mod, errno, err = ctx:module_from_path(path)
    if not mod then
        mod, errno, err = ctx:module_from_name(path)
    end
    if not mod then
        print("errno = ", errno, err)
        return
    end
    local result, errno, err = mod:remove()
    if not result then
        print("errno = ", errno, err)
    end
end

local function config_show()
    for k in ctx:config_blacklists() do
        print("blacklist: ", k)
    end

    for k, v in ctx:config_install_commands() do
        print("install_command: ", k, v)
    end

    for k, v in ctx:config_remove_commands() do
        print("remove_command: ", k, v)
    end

    for k, v in ctx:config_aliases() do
        print("alias: ", k, v)
    end

    for k, v in ctx:config_options() do
        print("option: ", k, v)
    end

    for k, v in ctx:config_softdeps() do
        print("softdep: ", k, v)
    end
end


cmd = cmd or "lsmod"

if cmd == "lsmod" then
    lsmod()
elseif cmd == "modinfo" then
    modinfo(file or "soundcore.ko")
elseif cmd == "depmod" then
    -- TODO
elseif cmd == "insmod" then
    insmod(file)
elseif cmd == "rmmod" then
    rmmod(file)
elseif cmd == "modprobe" then
    local result = ctx:load_resources()
    print("load_resources: ", result)
    config_show()
else
    print("unsupported cmd:", cmd)
end
