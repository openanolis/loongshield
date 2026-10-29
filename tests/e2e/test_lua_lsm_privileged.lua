local BIN = os.getenv('LOONGSHIELD_E2E_BIN') or os.getenv('LOONGSHIELD_BIN') or 'build/src/daemon/loongshield'
local ENABLED = os.getenv('LOONGSHIELD_LUA_LSM_PRIVILEGED') == '1'
local TARGET = '/tmp/loongshield-lua-lsm-deny'
local POLICY = 'profiles/lua-lsm/deny_tmp_marker.lua'
local EXIT_MARKER = '__LOONGSHIELD_LUA_LSM_E2E_EXIT__:'

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

local function run_command(cmd)
    local pipe = assert(io.popen(cmd .. " 2>&1; code=$?; printf '\\n" .. EXIT_MARKER .. '%s\\n\' "$code"', 'r'))
    local output = pipe:read('*a') or ''
    pipe:close()

    local code = tonumber(output:match(EXIT_MARKER .. '(%d+)'))
    output = output:gsub('\n?' .. EXIT_MARKER .. '%d+\n?$', '')
    assert(code ~= nil, 'Failed to parse command exit code from output:\n' .. output)
    return code, output
end

local function run_loongshield(args)
    local parts = { shell_escape(BIN) }
    for _, arg in ipairs(args) do
        parts[#parts + 1] = shell_escape(arg)
    end
    return run_command(table.concat(parts, ' '))
end

function test_lua_lsm_privileged_vm_policy_load_enforce_unload()
    if not ENABLED then
        print('skipping privileged Lua-LSM e2e; set LOONGSHIELD_LUA_LSM_PRIVILEGED=1 to enable')
        return
    end

    local status_code, status_output = run_loongshield({ 'lua-lsm', 'status' })
    assert(status_code == 0, 'Lua-LSM status must pass before privileged e2e:\n' .. status_output)

    local key_dir = os.getenv('TMPDIR') or '/tmp'
    local key_root = key_dir .. '/loongshield_lua_lsm_vm.' .. tostring(os.time())
    local priv = key_root .. '.key'
    local pub = key_root .. '.pub'
    local signed_policy = key_root .. '.lua'

    local priv_file = assert(io.open(priv, 'w'), 'Failed to write SM2 private key')
    priv_file:write(PRIV_PEM)
    priv_file:close()

    local pub_file = assert(io.open(pub, 'w'), 'Failed to write SM2 public key')
    pub_file:write(PUB_PEM)
    pub_file:close()

    local source_file = assert(io.open(POLICY, 'r'), 'Failed to read bundled policy')
    local source = source_file:read('*a')
    source_file:close()

    local policy_file = assert(io.open(signed_policy, 'w'), 'Failed to copy policy')
    policy_file:write(source)
    policy_file:close()

    local import_code, import_output = run_loongshield({ 'lua-lsm', 'import-key', pub })
    assert(import_code == 0, 'Failed to import verification key:\n' .. import_output)

    local sign_code, sign_output = run_loongshield({ 'lua-lsm', 'sign', signed_policy, '--key', priv })
    assert(sign_code == 0, 'Failed to sign policy:\n' .. sign_output)

    local setup_code, setup_output = run_command("printf 'deny target\\n' > " .. shell_escape(TARGET))
    assert(setup_code == 0, 'Failed to create deny target:\n' .. setup_output)

    local load_code, load_output = run_loongshield({ 'lua-lsm', 'load', signed_policy, '--appraise', 'enforce' })
    assert(load_code == 0, 'Failed to load policy:\n' .. load_output)

    local denied_code = run_command('cat ' .. shell_escape(TARGET) .. ' >/dev/null')
    assert(denied_code ~= 0, 'Expected Lua-LSM policy to deny reading ' .. TARGET)

    local unload_code, unload_output = run_loongshield({ 'lua-lsm', 'unload', 'deny_tmp_marker' })
    assert(unload_code == 0, 'Failed to unload policy:\n' .. unload_output)

    local allowed_code, allowed_output = run_command('cat ' .. shell_escape(TARGET) .. ' >/dev/null')
    assert(allowed_code == 0, 'Expected access after policy unload:\n' .. allowed_output)

    os.remove(priv)
    os.remove(pub)
    os.remove(signed_policy)
    os.remove(TARGET)
end
