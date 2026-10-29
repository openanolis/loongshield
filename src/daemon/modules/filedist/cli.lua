local luv = require('luv')
local log = require('runtime.log')
local distribute = require('filedist.distribute')

local M = {}

local USAGE = [[
Usage: loongshield filedist <command> [options]

File Distribution

Commands:
  server --dir <path>    Serve regular files from a directory
  pull <url>             Pull one file or a whole file index

Options:
  --dir <path>           server: directory to serve; pull: output directory
  --host <address>       Listen address for server (default 0.0.0.0)
  --port <number>        Listen port for server (default 8443)
  --cert <path>          server: TLS certificate PEM
  --key <path>           server: TLS private key PEM
  --ca <path>            pull: trusted CA certificate PEM
  --log-level <level>    Set log level (trace, debug, info, warn, error)
  -h, --help             Show this help message

The server distributes regular files over TLS only. Symlinks and path
traversal are rejected. Pulled files are not parsed or executed by LoongShield.
]]

local function print_usage()
    print(USAGE)
end

local function parse_args(argv)
    local opts = {}
    local positionals = {}

    local i = 1
    while i <= #argv do
        local arg = argv[i]
        local key, value = arg:match('^%-%-([%w%-]+)=(.+)$')

        if
            key == 'dir'
            or key == 'host'
            or key == 'port'
            or key == 'cert'
            or key == 'key'
            or key == 'ca'
            or key == 'log-level'
        then
            opts[key == 'log-level' and 'log_level' or key] = value
        elseif
            arg == '--dir'
            or arg == '--host'
            or arg == '--port'
            or arg == '--cert'
            or arg == '--key'
            or arg == '--ca'
            or arg == '--log-level'
        then
            if i >= #argv then
                return nil, string.format("Option '%s' requires a value.", arg)
            end
            if arg == '--log-level' then
                opts.log_level = argv[i + 1]
            elseif arg == '--dir' then
                opts.dir = argv[i + 1]
            elseif arg == '--host' then
                opts.host = argv[i + 1]
            elseif arg == '--cert' then
                opts.cert = argv[i + 1]
            elseif arg == '--key' then
                opts.key = argv[i + 1]
            elseif arg == '--ca' then
                opts.ca = argv[i + 1]
            else
                opts.port = argv[i + 1]
            end
            i = i + 1
        elseif arg == '--help' or arg == '-h' then
            opts.help = true
        elseif arg:match('^%-') then
            return nil, 'Unknown option: ' .. arg
        else
            positionals[#positionals + 1] = arg
        end
        i = i + 1
    end

    opts.command = positionals[1]
    opts.args = {}
    for i = 2, #positionals do
        opts.args[#opts.args + 1] = positionals[i]
    end
    return opts
end

local function serve_files(opts)
    if type(opts.dir) ~= 'string' or opts.dir == '' then
        log.error('server requires --dir <file-directory>')
        return 1
    end

    local port
    if opts.port == nil then
        port = 8443
    else
        port = tonumber(opts.port)
        if not port or port < 1 or port > 65535 or port % 1 ~= 0 then
            log.error("invalid server port: '%s'", tostring(opts.port))
            return 1
        end
    end

    local ok, err = distribute.serve({
        dir = opts.dir,
        host = opts.host,
        port = port,
        certificate = opts.cert,
        key = opts.key,
        file_filter = function()
            return true
        end,
        on_ready = function(host, ready_port, dir)
            print(string.format('Serving files from %s on %s:%d', dir, host, ready_port))
            print('Pull with: loongshield filedist pull https://' .. host .. ':' .. tostring(ready_port) .. '/')
            io.stdout:flush()
        end,
    })
    if not ok then
        log.error('Failed to start file server: %s', tostring(err))
        return 1
    end
    return ok
end

local function pull_files(url, opts)
    if type(url) ~= 'string' or url == '' then
        log.error('pull requires a file server URL')
        return 1
    end
    if url:sub(1, 8):lower() ~= 'https://' then
        log.error('file distribution requires an HTTPS URL')
        return 1
    end
    if type(opts.ca) ~= 'string' or opts.ca == '' then
        log.error('pull requires --ca <trusted-ca-pem>')
        return 1
    end

    local result
    local co = coroutine.create(function()
        local ok, count, pull_err = pcall(distribute.pull, url, {
            output_dir = opts.dir,
            ca_file = opts.ca,
            file_filter = function()
                return true
            end,
        })
        if ok and type(count) == 'number' then
            result = count
        elseif ok then
            result = { nil, tostring(pull_err) }
        else
            result = { nil, 'pull failed: ' .. tostring(count) }
        end
    end)
    coroutine.resume(co)
    luv.run()

    if type(result) ~= 'number' then
        log.error('Failed to pull files: %s', tostring(result and result[2] or result))
        return 1
    end

    local output_dir = opts.dir or '/var/lib/loongshield/filedist'
    if url:sub(-1) == '/' then
        print(string.format('Pulled %d files from %s into %s', result, url, output_dir))
    else
        print(string.format('Pulled %s into %s', url, output_dir))
    end
    return 0
end

function M.run(argv)
    local opts, err = parse_args(argv or {})
    if not opts then
        log.error(err)
        print('')
        print_usage()
        return 1
    end

    if opts.log_level then
        log.setLevel(opts.log_level)
    end

    if opts.help or not opts.command then
        print_usage()
        return opts.help and 0 or 1
    end

    if opts.command == 'server' then
        return serve_files(opts)
    elseif opts.command == 'pull' then
        return pull_files(opts.args[1], opts)
    else
        log.error("Unknown filedist command: '%s'", tostring(opts.command))
        print('')
        print_usage()
        return 1
    end
end

return M
