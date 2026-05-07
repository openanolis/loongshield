local readiness = require("lua_lsm.readiness")
local securityfs = require("lua_lsm.securityfs")

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function mkdir_p(path)
    os.execute("mkdir -p " .. shell_escape(path))
end

local function write_file(path, content)
    local file = assert(io.open(path, "wb"), "Failed to open for write: " .. path)
    file:write(content)
    file:close()
end

local function read_file(path)
    local file = assert(io.open(path, "rb"), "Failed to open for read: " .. path)
    local content = file:read("*a")
    file:close()
    return content
end

local function make_fixture()
    local root = "/tmp/loongshield_lua_lsm_" .. tostring(os.time()) .. "_" .. tostring(math.random(100000, 999999))
    local security_mount = root .. "/security"
    local lua_root = security_mount .. "/lua"
    local proc_root = root .. "/proc"
    local config_file = root .. "/kernel.config"

    os.execute("rm -rf " .. shell_escape(root))
    mkdir_p(lua_root)
    mkdir_p(proc_root)

    write_file(lua_root .. "/version", "1\n")
    write_file(lua_root .. "/register", "")
    write_file(lua_root .. "/unregister", "")
    write_file(lua_root .. "/modules", [[
modules for lua-lsm
name                 license      size nlsm nload shdict kvnode author
------------------------------------------------------------------------------------------
]])
    write_file(lua_root .. "/lsm_funcs", "stats for lua-lsm (ns)\n")
    write_file(lua_root .. "/stats", "lvm.nusage\t=            0\n")
    write_file(security_mount .. "/lsm", "landlock,lockdown,yama,lua,bpf\n")
    write_file(proc_root .. "/mounts", "securityfs " .. security_mount .. " securityfs rw 0 0\n")
    write_file(config_file, [[
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LUA=y
CONFIG_SECURITY_LUA_LSM=y
CONFIG_LSM="landlock,lockdown,yama,lua,bpf"
]])
    write_file(root .. "/policy.lua", [[
return {
  name = "integration_demo",
  author = "LoongShield",
  description = "integration policy",
  license = "MIT",
  version = 1,
  file_open = function()
    return true
  end,
}
]])

    return {
        root = root,
        security_mount = security_mount,
        lua_root = lua_root,
        proc_root = proc_root,
        config_file = config_file,
        policy = root .. "/policy.lua",
    }
end

local function cleanup(fixture)
    if fixture then
        os.execute("rm -rf " .. shell_escape(fixture.root))
    end
    securityfs._test_reset_dependencies()
    readiness._test_reset_dependencies()
end

function test_lua_lsm_integration_fake_securityfs_flow()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        local opts = {
            root = fixture.lua_root,
            securityfs_mount = fixture.security_mount,
            proc_root = fixture.proc_root,
            config_file = fixture.config_file,
            skip_cap_check = true,
        }

        local doctor = readiness.doctor(opts)
        assert(doctor.ready == true, "Expected fake kernel readiness checks to pass")

        local status = securityfs.status(opts)
        assert(status.available == true, "Expected Lua-LSM status to be available")
        assert(status.version == "1", "Expected Lua-LSM version")

        local modules = securityfs.list_modules(opts)
        assert(#modules == 0, "Expected no loaded modules")

        local loaded, load_err = securityfs.load_file(fixture.policy, opts)
        assert(loaded == true, tostring(load_err))
        assert(read_file(fixture.lua_root .. "/register"):find("integration_demo", 1, true), "Expected register write")

        local unloaded, unload_err = securityfs.unload("integration_demo", opts)
        assert(unloaded == true, tostring(unload_err))
        assert(read_file(fixture.lua_root .. "/unregister") == "integration_demo\n", "Expected unregister write")

        local hooks = securityfs.hooks(opts)
        assert(hooks:find("stats for lua-lsm", 1, true), "Expected hooks output")

        local stats = securityfs.stats(opts)
        assert(stats:find("lvm.nusage", 1, true), "Expected stats output")
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end

function test_lua_lsm_integration_doctor_reports_missing_config_lua()
    local fixture = make_fixture()
    local ok, err = pcall(function()
        write_file(fixture.config_file, [[
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
# CONFIG_LUA is not set
CONFIG_SECURITY_LUA_LSM=y
CONFIG_LSM="landlock,lua,bpf"
]])

        local doctor = readiness.doctor({
            root = fixture.lua_root,
            securityfs_mount = fixture.security_mount,
            proc_root = fixture.proc_root,
            config_file = fixture.config_file,
        })

        assert(doctor.ready == false, "Expected missing CONFIG_LUA to fail readiness")
        local found = false
        for _, item in ipairs(doctor.checks) do
            if item.id == "config_lua" and item.ok == false then
                found = true
                break
            end
        end
        assert(found, "Expected config_lua failure")
    end)
    cleanup(fixture)
    if not ok then
        error(err, 0)
    end
end
