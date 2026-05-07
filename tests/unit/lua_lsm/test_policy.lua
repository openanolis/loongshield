local policy = require("lua_lsm.policy")

local function assert_contains(haystack, needle)
    assert(tostring(haystack):find(needle, 1, true), "Expected text to contain: " .. needle)
end

function test_lua_lsm_policy_validates_required_metadata()
    local source = [[
local errno = require("errno")
return {
  name = "demo",
  author = "LoongShield",
  description = "demo policy",
  license = "MIT",
  version = 1,
  file_open = function(file)
    return true, errno.EPERM
  end,
}
]]

    local metadata, err = policy.validate_source(source, "demo.lua")
    assert(metadata ~= nil, tostring(err))
    assert(metadata.name == "demo", "Expected policy name")
    assert(metadata.version == 1, "Expected policy version")
end

function test_lua_lsm_policy_rejects_invalid_metadata()
    local source = [[
return {
  name = "bad",
  author = "LoongShield",
  description = "bad policy",
  license = "MIT",
}
]]

    local metadata, err = policy.validate_source(source, "bad.lua")
    assert(metadata == nil, "Expected invalid policy to fail")
    assert_contains(err, "version")
end

function test_lua_lsm_policy_rejects_known_unsupported_hooks()
    local source = [[
return {
  name = "bad_hook",
  author = "LoongShield",
  description = "bad policy",
  license = "MIT",
  version = 1,
  getprocattr = function()
    return true
  end,
}
]]

    local metadata, err = policy.validate_source(source, "bad_hook.lua")
    assert(metadata == nil, "Expected unsupported hook to fail")
    assert_contains(err, "unsupported Lua-LSM hook")
end

function test_lua_lsm_policy_loads_manifest()
    local files = {
        ["/fake/manifest.yml"] = [[
version: "1"
policies:
  - name: demo
    file: demo.lua
    enabled: false
    order: 10
]],
    }

    policy._test_set_dependencies({
        io_open = function(path)
            local content = files[path]
            if not content then
                return nil, "not found"
            end
            return {
                read = function()
                    return content
                end,
                close = function() end,
            }
        end,
        require = function(name)
            if name == "lyaml" then
                return {
                    load = function()
                        return {
                            version = "1",
                            policies = {
                                {
                                    name = "demo",
                                    file = "demo.lua",
                                    enabled = false,
                                    order = 10,
                                },
                            },
                        }
                    end,
                }
            end
            return require(name)
        end,
    })

    local manifest, err = policy.load_manifest("/fake/manifest.yml")
    policy._test_reset_dependencies()
    assert(manifest ~= nil, tostring(err))
    assert(manifest.policies[1].name == "demo", "Expected manifest policy")
end
