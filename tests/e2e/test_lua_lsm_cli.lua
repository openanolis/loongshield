local EXIT_MARKER = '__LOONGSHIELD_LUA_LSM_CLI_EXIT__:'

local BIN = os.getenv('LOONGSHIELD_E2E_BIN') or os.getenv('LOONGSHIELD_BIN') or 'build/src/daemon/loongshield'

local PRIV_PEM = [[
-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIKbp83WDypEh9kqF
7JoFS/6Yc+vGFSSY2FFHq8WsvJnIoUQDQgAEnhq16xNbKDc0exyU+sSr2g1ZrzvD
CcWN7YVvpcL/nsdewUAAnuqPolzPviEU0fyiY+XfE9s/GAF43YGMRK4Bhg==
-----END PRIVATE KEY-----
]]

local PUB_PEM = [[
-----BEGIN PUBLIC KEY-----
MFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABJ4atesTWyg3NHsclPrEq9oNWa87
wwnFje2Fb6XC/57HXsFAAJ7qj6Jcz74hFNH8omPl3xPbPxgBeN2BjESuAYY=
-----END PUBLIC KEY-----
]]

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function write_file(path, content)
    local file = assert(io.open(path, 'wb'), 'Failed to open for write: ' .. path)
    file:write(content)
    file:close()
end

local function read_file(path)
    local file = assert(io.open(path, 'rb'), 'Failed to open for read: ' .. path)
    local content = file:read('*a')
    file:close()
    return content
end

local function run_loongshield(args, env)
    local parts = {}
    for key, value in pairs(env or {}) do
        parts[#parts + 1] = key .. '=' .. shell_escape(value)
    end
    parts[#parts + 1] = shell_escape(BIN)
    for _, arg in ipairs(args) do
        parts[#parts + 1] = shell_escape(arg)
    end

    local cmd = table.concat(parts, ' ') .. " 2>&1; code=$?; printf '\\n" .. EXIT_MARKER .. '%s\\n\' "$code"'
    local pipe = assert(io.popen(cmd, 'r'), 'Failed to run loongshield')
    local output = pipe:read('*a') or ''
    pipe:close()

    local code = tonumber(output:match(EXIT_MARKER .. '(%d+)\n?$'))
    output = output:gsub('\n?' .. EXIT_MARKER .. '%d+\n?$', '')
    assert(code ~= nil, 'Failed to parse exit code from output:\n' .. output)
    return code, output
end

local function make_fixture()
    local base = os.getenv('TMPDIR') or '/tmp'
    local cmd = 'mktemp -d ' .. shell_escape(base .. '/loongshield_lua_lsm_cli.XXXXXX')
    local pipe = assert(io.popen(cmd, 'r'))
    local root = (pipe:read('*l') or ''):gsub('%s+$', '')
    assert(pipe:close() and root ~= '', 'Failed to create temp dir')

    local lua_root = root .. '/security/lua'
    local trust_dir = root .. '/trust'
    assert(os.execute('mkdir -p ' .. shell_escape(lua_root)))
    assert(os.execute('mkdir -p ' .. shell_escape(trust_dir)))

    write_file(lua_root .. '/version', '1\n')
    write_file(lua_root .. '/register', '')
    write_file(lua_root .. '/unregister', '')
    write_file(
        lua_root .. '/modules',
        [[
modules for lua-lsm
name                 license      size nlsm nload shdict kvnode author
------------------------------------------------------------------------------------------
]]
    )
    write_file(root .. '/sm2.key', PRIV_PEM)
    write_file(root .. '/sm2.pub', PUB_PEM)
    write_file(
        root .. '/policy.lua',
        [[
local errno = require("errno")

return {
    name = "cli_demo",
    author = "LoongShield",
    description = "cli demo policy",
    license = "MIT",
    version = 1,
    file_open = function(file)
        return true, errno.EPERM
    end,
}
]]
    )

    local env = {
        LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT = lua_root,
        LOONGSHIELD_LUA_LSM_PUBKEY_DIR = trust_dir,
        LOONGSHIELD_LUA_LSM_ASSUME_CAP_MAC_ADMIN = '1',
        LOG_LEVEL = 'info',
    }

    return {
        root = root,
        lua_root = lua_root,
        trust_dir = trust_dir,
        policy = root .. '/policy.lua',
        priv = root .. '/sm2.key',
        pub = root .. '/sm2.pub',
        env = env,
    }
end

local function cleanup(fixture)
    if fixture then
        os.execute('rm -rf ' .. shell_escape(fixture.root))
    end
end

function test_lua_lsm_cli_import_key_and_list()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        local code, output =
            run_loongshield({ 'lua-lsm', 'import-key', fixture.pub, '--trust-dir', fixture.trust_dir }, fixture.env)
        assert(code == 0, 'import-key failed:\n' .. output)
        assert(
            output:match('Imported Lua%-LSM public key: (%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x)'),
            'Expected key id in output:\n' .. output
        )

        code, output = run_loongshield({ 'lua-lsm', 'keys', '--trust-dir', fixture.trust_dir }, fixture.env)
        assert(code == 0, 'keys failed:\n' .. output)
        assert(output:match('^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n$'), 'Expected exactly one key id:\n' .. output)
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end

function test_lua_lsm_cli_signs_and_loads_verified_policy()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        local code, output = run_loongshield({ 'lua-lsm', 'import-key', fixture.pub }, fixture.env)
        assert(code == 0, 'import-key failed:\n' .. output)

        code, output = run_loongshield({ 'lua-lsm', 'sign', fixture.policy, '--key', fixture.priv }, fixture.env)
        assert(code == 0, 'sign failed:\n' .. output)
        assert(output:find('signature embedded', 1, true), 'Expected embedded signature note:\n' .. output)

        local signed = read_file(fixture.policy)
        assert(signed:find('cli_demo', 1, true), 'Expected policy source to remain in file')

        -- Verification requires an explicit appraisal mode.
        code, output = run_loongshield({ 'lua-lsm', 'load', fixture.policy, '--appraise', 'enforce' }, fixture.env)
        assert(code == 0, 'Verified load failed:\n' .. output)
        assert(output:find('Verified Lua-LSM policy signature', 1, true), 'Expected verification log line:\n' .. output)

        -- The kernel must receive the clean source without the signature trailer.
        local register = read_file(fixture.lua_root .. '/register')
        assert(register:find('cli_demo', 1, true), 'Expected policy source in register')
        assert(register:find('LULSM', 1, true) == nil, 'Expected signature trailer to be stripped')
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end

function test_lua_lsm_cli_rejects_tampered_policy_with_explicit_enforce()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        local code, output = run_loongshield({ 'lua-lsm', 'import-key', fixture.pub }, fixture.env)
        assert(code == 0, 'import-key failed:\n' .. output)

        code, output = run_loongshield({ 'lua-lsm', 'sign', fixture.policy, '--key', fixture.priv }, fixture.env)
        assert(code == 0, 'sign failed:\n' .. output)

        -- Tamper with the embedded source, keeping the trailer intact.
        local signed = read_file(fixture.policy)
        write_file(fixture.policy, signed:gsub('cli_demo', 'tampered_demo'))

        code, output = run_loongshield({ 'lua-lsm', 'load', fixture.policy, '--appraise', 'enforce' }, fixture.env)
        assert(code == 1, 'Expected tampered policy load to fail:\n' .. output)
        assert(
            output:find('signature verification failed', 1, true),
            'Expected verification failure in output:\n' .. output
        )
        assert(
            read_file(fixture.lua_root .. '/register') == '',
            'Expected register to stay untouched after failed verification'
        )
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end

function test_lua_lsm_cli_explicit_enforce_rejects_unsigned_policy()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        local code, output = run_loongshield({ 'lua-lsm', 'import-key', fixture.pub }, fixture.env)
        assert(code == 0, 'import-key failed:\n' .. output)

        code, output = run_loongshield({ 'lua-lsm', 'load', fixture.policy, '--appraise', 'enforce' }, fixture.env)
        assert(code == 1, 'Expected unsigned policy load to fail in enforce mode:\n' .. output)
        assert(output:find('policy is not signed', 1, true), 'Expected not-signed error in output:\n' .. output)
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end

function test_lua_lsm_cli_default_mode_skips_verification()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        local code, output = run_loongshield({ 'lua-lsm', 'load', fixture.policy }, fixture.env)
        assert(code == 0, 'Expected unsigned policy to load by default:\n' .. output)
        assert(output:find('appraisal is off', 1, true), 'Expected appraisal-off log line:\n' .. output)
        assert(
            read_file(fixture.lua_root .. '/register'):find('cli_demo', 1, true),
            'Expected policy source written to register'
        )
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end

function test_lua_lsm_cli_appraise_log_allows_failed_verification()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        local code, output = run_loongshield({ 'lua-lsm', 'import-key', fixture.pub }, fixture.env)
        assert(code == 0, 'import-key failed:\n' .. output)

        code, output = run_loongshield({ 'lua-lsm', 'sign', fixture.policy, '--key', fixture.priv }, fixture.env)
        assert(code == 0, 'sign failed:\n' .. output)

        local signed = read_file(fixture.policy)
        write_file(fixture.policy, signed:gsub('cli_demo', 'tampered_demo'))

        code, output = run_loongshield({ 'lua-lsm', 'load', fixture.policy, '--appraise', 'log' }, fixture.env)
        assert(code == 0, 'Expected tampered policy to load with appraise=log:\n' .. output)
        assert(output:find('log mode', 1, true), 'Expected log-mode warning:\n' .. output)
        assert(read_file(fixture.lua_root .. '/register') ~= '', 'Expected policy source written to register')
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end
