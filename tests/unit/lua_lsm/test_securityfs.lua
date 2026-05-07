local securityfs = require("lua_lsm.securityfs")

local function assert_contains(haystack, needle)
    assert(tostring(haystack):find(needle, 1, true), "Expected text to contain: " .. needle)
end

local function with_securityfs_deps(overrides, fn)
    securityfs._test_set_dependencies(overrides)
    local ok, err = pcall(fn)
    securityfs._test_reset_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_lua_lsm_securityfs_parse_modules()
    local raw = [[
modules for lua-lsm
name                 license      size nlsm nload shdict kvnode author
------------------------------------------------------------------------------------------
demo                 MIT           128    1     2      0      0 LoongShield
]]

    local modules = securityfs.parse_modules(raw)
    assert(#modules == 1, "Expected one parsed module")
    assert(modules[1].name == "demo", "Expected module name")
    assert(modules[1].license == "MIT", "Expected module license")
    assert(modules[1].size == 128, "Expected numeric size")
    assert(modules[1].nlsm == 1, "Expected hook count")
end

function test_lua_lsm_securityfs_load_and_unload_write_expected_files()
    local writes = {}

    with_securityfs_deps({
        getenv = function(name)
            if name == "LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT" then
                return "/fake/security/lua"
            end
            return nil
        end,
        io_open = function(path, mode)
            if mode == "wb" then
                return {
                    write = function(_, content)
                        writes[path] = content
                        return true
                    end,
                    close = function() end,
                }
            end
            return nil, "not found"
        end,
    }, function()
        local ok, err = securityfs.load_source("return {}", { skip_cap_check = true })
        assert(ok == true, tostring(err))
        assert(writes["/fake/security/lua/register"] == "return {}", "Expected register write")

        ok, err = securityfs.unload("demo", { skip_cap_check = true })
        assert(ok == true, tostring(err))
        assert(writes["/fake/security/lua/unregister"] == "demo\n", "Expected unregister write")
    end)
end

function test_lua_lsm_securityfs_capability_check_rejects_missing_cap_mac_admin()
    with_securityfs_deps({
        getenv = function()
            return nil
        end,
        require = function(name)
            if name == "capability" then
                return {
                    get_proc = function()
                        return {
                            flag = function()
                                return false
                            end,
                        }
                    end,
                }
            end
            return require(name)
        end,
    }, function()
        local ok, err = securityfs.load_source("return {}", { root = "/fake/security/lua" })
        assert(ok == nil, "Expected load to fail")
        assert_contains(err, "CAP_MAC_ADMIN required")
    end)
end

function test_lua_lsm_securityfs_is_loaded_detects_duplicate_module()
    local modules = [[
modules for lua-lsm
name                 license      size nlsm nload shdict kvnode author
------------------------------------------------------------------------------------------
demo                 MIT           128    1     2      0      0 LoongShield
]]

    with_securityfs_deps({
        io_open = function(path, mode)
            if path == "/fake/security/lua/modules" and mode == "rb" then
                return {
                    read = function()
                        return modules
                    end,
                    close = function() end,
                }
            end
            return nil, "not found"
        end,
    }, function()
        local loaded = securityfs.is_loaded("demo", { root = "/fake/security/lua" })
        assert(loaded == true, "Expected duplicate module to be detected")

        loaded = securityfs.is_loaded("other", { root = "/fake/security/lua" })
        assert(loaded == false, "Expected missing module to be false")
    end)
end
