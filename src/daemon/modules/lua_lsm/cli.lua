local cjson = require('cjson.safe')
local log = require('runtime.log')
local integrity = require('lua_lsm.integrity')
local policy = require('lua_lsm.policy')
local readiness = require('lua_lsm.readiness')
local securityfs = require('lua_lsm.securityfs')

local M = {}

local USAGE = [[
Usage: loongshield lua-lsm <command> [options]

Lua-LSM Policy Manager

Commands:
  status                 Show kernel readiness, trusted keys, and loaded modules
  import-key <pub.pem>   Import an SM2 public key into the trust store
  load <policy|manifest> Verify, validate, and load a policy or policy manifest
  unload <name>          Unload a Lua-LSM policy by module name
  sign <policy.lua>      Sign a policy in place with an SM2 key (SM3 digest)

Options:
  --root <path>          Override Lua-LSM securityfs root
  --config <path>        Override kernel config path for status
  --key <path>           SM2 private key used by sign
  --appraise <mode>      Policy appraisal: off | log | enforce (default off)
  --trust-dir <path>     Override trusted public key directory
  --json                 Machine-readable status output
  --no-validate          Skip userspace policy metadata validation before load
  --log-level <level>    Set log level (trace, debug, info, warn, error)
  -h, --help             Show this help message

Environment:
  LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT       Default: /sys/kernel/security/lua
  LOONGSHIELD_LUA_LSM_SECURITYFS_MOUNT      Default: parent of securityfs root
  LOONGSHIELD_LUA_LSM_CONFIG_FILE           Kernel config used by doctor
  LOONGSHIELD_LUA_LSM_ASSUME_CAP_MAC_ADMIN  Test-only capability bypass
  LOONGSHIELD_LUA_LSM_PUBKEY_DIR            Default: /var/lib/loongshield/lua-lsm/pubkeys
  LOONGSHIELD_LUA_LSM_APPRAISE              Default: off

Exit Codes:
  0 - Command completed successfully
  1 - CLI error, readiness failure, missing ABI file, or kernel write failure
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

        if key == 'root' then
            opts.root = value
        elseif key == 'config' then
            opts.config_file = value
        elseif key == 'key' then
            opts.key_path = value
        elseif key == 'appraise' then
            opts.appraise = value
        elseif key == 'trust-dir' then
            opts.trust_dir = value
        elseif key == 'log-level' then
            opts.log_level = value
        elseif
            arg == '--root'
            or arg == '--config'
            or arg == '--key'
            or arg == '--appraise'
            or arg == '--trust-dir'
            or arg == '--log-level'
        then
            if i >= #argv then
                return nil, string.format("Option '%s' requires a value.", arg)
            end
            if arg == '--root' then
                opts.root = argv[i + 1]
            elseif arg == '--config' then
                opts.config_file = argv[i + 1]
            elseif arg == '--key' then
                opts.key_path = argv[i + 1]
            elseif arg == '--appraise' then
                opts.appraise = argv[i + 1]
            elseif arg == '--trust-dir' then
                opts.trust_dir = argv[i + 1]
            else
                opts.log_level = argv[i + 1]
            end
            i = i + 1
        elseif arg == '--no-validate' then
            opts.no_validate = true
        elseif arg == '--json' then
            opts.json = true
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
    for j = 2, #positionals do
        opts.args[#opts.args + 1] = positionals[j]
    end
    return opts
end

local function yn(value)
    return value and 'yes' or 'no'
end

local function collect_status(opts)
    local doctor = readiness.doctor(opts)
    local status = securityfs.status(opts)
    local keys = integrity.list_keys(opts)

    local report = {
        securityfs = {
            root = status.root,
            mount = status.securityfs_mount,
            available = status.available,
            version = status.version,
        },
        kernel = doctor.checks,
        ready = doctor.ready,
        trusted_keys = keys or {},
        loaded_modules = status.modules,
        experimental = true,
    }

    return report
end

local function print_status(opts)
    local report = collect_status(opts)
    local status = report.securityfs

    print('Lua-LSM status')
    print('  securityfs root: ' .. status.root)
    print('  securityfs mount: ' .. status.mount)
    print('  available: ' .. yn(status.available))
    if status.version then
        print('  version: ' .. status.version)
    else
        print('  version: unavailable')
    end

    print('  kernel readiness:')
    for _, item in ipairs(report.kernel) do
        local prefix
        if item.ok == true then
            prefix = 'OK'
        elseif item.required then
            prefix = 'FAIL'
        else
            prefix = 'WARN'
        end
        print(string.format('    [%s] %s: %s', prefix, item.label, tostring(item.detail or '')))
    end

    if #report.trusted_keys == 0 then
        print('  trusted keys: 0')
    else
        local ids = {}
        for _, key in ipairs(report.trusted_keys) do
            ids[#ids + 1] = key.id
        end
        print('  trusted keys: ' .. tostring(#report.trusted_keys) .. ' (' .. table.concat(ids, ', ') .. ')')
    end

    print('  loaded modules: ' .. tostring(#report.loaded_modules))
    print('  experimental: yes')

    return report.ready and 0 or 1
end

local function print_status_json(opts)
    local report = collect_status(opts)
    local encoded, err = cjson.encode(report)
    if not encoded then
        log.error('Failed to encode Lua-LSM status: %s', tostring(err))
        return 1
    end
    print(encoded)

    return report.ready and 0 or 1
end

local function appraise_policy(source, signature, opts)
    local mode, mode_err = integrity.appraise_mode(opts)
    if not mode then
        log.error('%s', tostring(mode_err))
        return nil
    end

    if mode == 'off' then
        log.info('Lua-LSM policy appraisal is off')
        return true
    end

    local ok, err, key_id = integrity.verify_policy(source, signature, opts)
    if ok then
        log.info("Verified Lua-LSM policy signature with trusted key '%s'", tostring(key_id))
        return true
    end

    if mode == 'log' then
        log.warn('Lua-LSM policy signature verification failed (log mode): %s', tostring(err))
        return true
    end

    log.error('Lua-LSM policy signature verification failed: %s', tostring(err))
    return false
end

local function load_policy_file(path, opts)
    if type(path) ~= 'string' or path == '' then
        log.error('load requires a policy file path')
        return 1
    end

    local file, file_err = io.open(path, 'rb')
    if not file then
        log.error('Failed to open Lua-LSM policy: %s', tostring(file_err))
        return 1
    end

    local content = file:read('*a') or ''
    file:close()

    local source, signature, split_err = integrity.read_policy(content)
    if not source then
        log.error('%s', tostring(split_err))
        return 1
    end

    local appraised = appraise_policy(source, signature, opts)
    if appraised == nil then
        return 1
    end
    if not appraised then
        return 1
    end

    local metadata
    if not opts.no_validate then
        local err
        metadata, err = policy.validate_source(source, path)
        if not metadata then
            log.error('Policy validation failed: %s', tostring(err))
            return 1
        end

        local loaded, loaded_err = securityfs.is_loaded(metadata.name, opts)
        if loaded == true then
            log.error("Lua-LSM policy '%s' is already loaded", metadata.name)
            return 1
        elseif loaded == nil then
            log.warn('Could not check currently loaded Lua-LSM modules: %s', tostring(loaded_err))
        end

        log.info("Validated Lua-LSM policy '%s' version %s", metadata.name, tostring(metadata.version))
    end

    log.warn('Lua-LSM support is experimental; loading only the explicitly requested local policy.')
    local ok, err = securityfs.load_source(source, opts)
    if not ok then
        log.error('Failed to load Lua-LSM policy: %s', tostring(err))
        return 1
    end

    print('Loaded Lua-LSM policy: ' .. path)
    return 0
end

local function dirname(path)
    local normalized = path:gsub('/+$', '')
    local parent = normalized:match('^(.*)/[^/]+$')
    if parent == nil or parent == '' then
        return '.'
    end
    return parent
end

local function load_manifest(path, opts)
    local manifest, err = policy.load_manifest(path)
    if not manifest then
        log.error('Failed to load Lua-LSM manifest: %s', tostring(err))
        return 1
    end

    local entries = {}
    for _, entry in ipairs(manifest.policies) do
        if entry.enabled ~= false then
            entries[#entries + 1] = entry
        end
    end

    table.sort(entries, function(a, b)
        local order_a = a.order or math.huge
        local order_b = b.order or math.huge
        if order_a == order_b then
            return tostring(a.name) < tostring(b.name)
        end
        return order_a < order_b
    end)

    if #entries == 0 then
        print('No enabled Lua-LSM policies in manifest: ' .. path)
        return 0
    end

    local base = dirname(path)
    for _, entry in ipairs(entries) do
        local policy_path = entry.file
        if not policy_path:match('^/') then
            policy_path = base .. '/' .. policy_path
        end

        log.info("Loading Lua-LSM policy '%s' from manifest", tostring(entry.name))
        local code = load_policy_file(policy_path, opts)
        if code ~= 0 then
            log.error("Manifest load aborted at policy '%s'", tostring(entry.name))
            return code
        end
    end

    print(string.format('Loaded %d Lua-LSM policies from manifest: %s', #entries, path))
    return 0
end

local function load_policy(path, opts)
    if type(path) ~= 'string' or path == '' then
        log.error('load requires a policy or manifest path')
        return 1
    end

    if path:match('%.ya?ml$') then
        return load_manifest(path, opts)
    end
    return load_policy_file(path, opts)
end

local function sign_policy(path, opts)
    if type(path) ~= 'string' or path == '' then
        log.error('sign requires a policy file path')
        return 1
    end
    if type(opts.key_path) ~= 'string' or opts.key_path == '' then
        log.error('sign requires --key <sm2-private.pem>')
        return 1
    end

    local signed_path, err = integrity.sign_file(path, opts.key_path, opts)
    if not signed_path then
        log.error('Failed to sign Lua-LSM policy: %s', tostring(err))
        return 1
    end

    print('Signed Lua-LSM policy (signature embedded): ' .. signed_path)
    return 0
end

local function import_key(path, opts)
    if type(path) ~= 'string' or path == '' then
        log.error('import-key requires a public key path')
        return 1
    end

    local id, err = integrity.import_key(path, opts)
    if not id then
        log.error('Failed to import Lua-LSM public key: %s', tostring(err))
        return 1
    end

    print('Imported Lua-LSM public key: ' .. id)
    return 0
end

local function unload_policy(name, opts)
    if type(name) ~= 'string' or name == '' then
        log.error('unload requires a module name')
        return 1
    end

    local ok, err = securityfs.unload(name, opts)
    if not ok then
        log.error('Failed to unload Lua-LSM policy: %s', tostring(err))
        return 1
    end

    print('Unloaded Lua-LSM policy: ' .. name)
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

    if opts.command == 'status' then
        if opts.json then
            return print_status_json(opts)
        end
        return print_status(opts)
    elseif opts.command == 'import-key' then
        return import_key(opts.args[1], opts)
    elseif opts.command == 'load' then
        return load_policy(opts.args[1], opts)
    elseif opts.command == 'sign' then
        return sign_policy(opts.args[1], opts)
    elseif opts.command == 'unload' then
        return unload_policy(opts.args[1], opts)
    else
        log.error("Unknown lua-lsm command: '%s'", tostring(opts.command))
        print('')
        print_usage()
        return 1
    end
end

return M
