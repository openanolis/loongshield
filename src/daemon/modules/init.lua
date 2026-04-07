#!/usr/bin/env luajit

local log = require('runtime.log')

local argv, envp = ...
assert(type(argv) == 'table')
assert(type(envp) == 'table')

local commands = {
    seharden = require('seharden'),
    rpm = require('rpm')
}

local function print_version()
    local version = require('runtime.version')
    local banner = [[
 ___       ________  ________  ________   ________  ________  ___  ___  ___  _______   ___       ________
|\  \     |\   __  \|\   __  \|\   ___  \|\   ____\|\   ____\|\  \|\  \|\  \|\  ___ \ |\  \     |\   ___ \
\ \  \    \ \  \|\  \ \  \|\  \ \  \\ \  \ \  \___|\ \  \___|\ \  \\\  \ \  \ \   __/|\ \  \    \ \  \_|\ \
 \ \  \    \ \  \\\  \ \  \\\  \ \  \\ \  \ \  \  __\ \_____  \ \   __  \ \  \ \  \_|/_\ \  \    \ \  \ \\ \
  \ \  \____\ \  \\\  \ \  \\\  \ \  \\ \  \ \  \|\  \|____|\  \ \  \ \  \ \  \ \  \_|\ \ \  \____\ \  \_\\ \
   \ \_______\ \_______\ \_______\ \__\\ \__\ \_______\____\_\  \ \__\ \__\ \__\ \_______\ \_______\ \_______\
    \|_______|\|_______|\|_______|\|__| \|__|\|_______|\_________\|__|\|__|\|__|\|_______|\|_______|\|_______|
                                                      \|_________|
]]
    local green = "\27[32m"
    local reset = "\27[0m"
    print(green .. banner .. reset)
    print(string.format("loongshield %s  commit %s", version.version, version.commit))
end

local function print_usage()
    print("Usage: loongshield <subcommand> [options]")
    print("")
    print("Subcommands:")
    print("  version       Show loongshield version information")
    print("  seharden      OS Security benchmarks & hardening")
    print("  rpm           RPM package SBOM verification")
    print("")
    print("For help on a specific subcommand: loongshield <subcommand> --help")
end

if #argv < 2 then
    print_usage()
    return 1
end

local subcommand = argv[2]

if subcommand == "--help" or subcommand == "-h" then
    print_usage()
    return 0
end

if subcommand == "version" then
    print_version()
    return 0
end

local cmd_module = commands[subcommand]
if not cmd_module then
    log.error("Unknown subcommand: '" .. subcommand .. "'")
    print_usage()
    return 1
end

local sub_argv = {}
for i = 3, #argv do
    sub_argv[#sub_argv + 1] = argv[i]
end

local success, result = pcall(function()
    if type(cmd_module.run) == 'function' then
        return cmd_module.run(sub_argv, envp)
    else
        log.error(string.format("Module '%s' does not have a run() function.", subcommand))
        return 1
    end
end)


if not success then
    log.error(string.format("Runtime error in '%s': %s", subcommand, tostring(result)))
    return 1
else
    return result or 0
end
