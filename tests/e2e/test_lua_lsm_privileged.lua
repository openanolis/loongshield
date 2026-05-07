local BIN = os.getenv("LOONGSHIELD_E2E_BIN") or os.getenv("LOONGSHIELD_BIN") or "build/src/daemon/loongshield"
local ENABLED = os.getenv("LOONGSHIELD_LUA_LSM_PRIVILEGED") == "1"
local TARGET = "/tmp/loongshield-lua-lsm-deny"
local POLICY = "profiles/lua-lsm/deny_tmp_marker.lua"
local EXIT_MARKER = "__LOONGSHIELD_LUA_LSM_E2E_EXIT__:"

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function run_command(cmd)
    local pipe = assert(io.popen(cmd .. " 2>&1; code=$?; printf '\\n" .. EXIT_MARKER .. "%s\\n' \"$code\"", "r"))
    local output = pipe:read("*a") or ""
    pipe:close()

    local code = tonumber(output:match(EXIT_MARKER .. "(%d+)"))
    output = output:gsub("\n?" .. EXIT_MARKER .. "%d+\n?$", "")
    assert(code ~= nil, "Failed to parse command exit code from output:\n" .. output)
    return code, output
end

local function run_loongshield(args)
    local parts = { shell_escape(BIN) }
    for _, arg in ipairs(args) do
        parts[#parts + 1] = shell_escape(arg)
    end
    return run_command(table.concat(parts, " "))
end

function test_lua_lsm_privileged_vm_policy_load_enforce_unload()
    if not ENABLED then
        print("skipping privileged Lua-LSM e2e; set LOONGSHIELD_LUA_LSM_PRIVILEGED=1 to enable")
        return
    end

    local doctor_code, doctor_output = run_loongshield({ "lua-lsm", "doctor" })
    assert(doctor_code == 0, "Lua-LSM doctor must pass before privileged e2e:\n" .. doctor_output)

    local setup_code, setup_output = run_command("printf 'deny target\\n' > " .. shell_escape(TARGET))
    assert(setup_code == 0, "Failed to create deny target:\n" .. setup_output)

    local load_code, load_output = run_loongshield({ "lua-lsm", "load", POLICY })
    assert(load_code == 0, "Failed to load policy:\n" .. load_output)

    local denied_code = run_command("cat " .. shell_escape(TARGET) .. " >/dev/null")
    assert(denied_code ~= 0, "Expected Lua-LSM policy to deny reading " .. TARGET)

    local unload_code, unload_output = run_loongshield({ "lua-lsm", "unload", "deny_tmp_marker" })
    assert(unload_code == 0, "Failed to unload policy:\n" .. unload_output)

    local allowed_code, allowed_output = run_command("cat " .. shell_escape(TARGET) .. " >/dev/null")
    assert(allowed_code == 0, "Expected access after policy unload:\n" .. allowed_output)

    os.remove(TARGET)
end
