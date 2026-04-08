local Mocks = {}
local saved_loader

local function setup(mock_probe_result)
    Mocks.result = mock_probe_result
    saved_loader = package.loaded["seharden.loader"]
    package.loaded["seharden.loader"] = {
        get_probe = function()
            return function()
                -- Return a shallow copy so each call gets a distinct table;
                -- setmetatable in meta.map mutates the returned table, which
                -- would corrupt shared state if the same reference is reused.
                local copy = {}
                for k, v in pairs(Mocks.result) do copy[k] = v end
                return copy
            end
        end
    }
    package.loaded["seharden.probes.meta"] = nil
end

local function teardown()
    package.loaded["seharden.loader"] = saved_loader
end

function test_map_applies_probe_to_each_item()
    setup({ ok = true })
    local ok, err = pcall(function()
        local meta_probe = require('seharden.probes.meta')
        local result = meta_probe.map({
            source_probe = "users",
            apply_func = "file.find_pattern",
            params_template = { path = "%{item.path}" }
        }, {
            users = {
                { user = "a", path = "/home/a/.netrc" },
                { user = "b", path = "/home/b/.netrc" }
            }
        })

        assert(#result == 2, "Expected two results")
        assert(result[1].user == "a", "Expected merged item field user=a")
        assert(result[2].user == "b", "Expected merged item field user=b")
        assert(result[1].ok == true, "Expected probe result to be merged")
    end)
    teardown()
    if not ok then error(err, 0) end
end

function test_map_handles_missing_source()
    local meta_probe = require('seharden.probes.meta')
    local result, err = meta_probe.map({
        source_probe = "missing",
        apply_func = "file.find_pattern",
        params_template = { path = "%{item.path}" }
    }, {
        users = {}
    })
    assert(result == nil, "Expected nil result when source missing")
    assert(err:match("did not return a list"), "Expected error for missing list")
end

function test_map_propagates_inner_probe_nil_error()
    saved_loader = package.loaded["seharden.loader"]
    package.loaded["seharden.loader"] = {
        get_probe = function()
            return function()
                return nil, "inner failure"
            end
        end
    }
    package.loaded["seharden.probes.meta"] = nil

    local meta_probe = require('seharden.probes.meta')
    local result, err = meta_probe.map({
        source_probe = "users",
        apply_func = "file.find_pattern",
        params_template = { path = "%{item.path}" }
    }, {
        users = {
            { path = "/home/a/.netrc" }
        }
    })

    teardown()
    assert(result == nil, "Expected meta.map to fail when inner probe returns nil,error")
    assert(err:match("inner failure"), "Expected inner probe error to be preserved")
end

function test_map_accepts_wrapped_probe_results_using_details_list()
    setup({ ok = true })
    local ok, err = pcall(function()
        local meta_probe = require('seharden.probes.meta')
        local result = meta_probe.map({
            source_probe = "ssh_host_keys",
            apply_func = "permissions.get_attributes",
            params_template = { path = "%{item.path}" }
        }, {
            ssh_host_keys = {
                count = 2,
                details = {
                    { path = "/etc/ssh/ssh_host_rsa_key" },
                    { path = "/etc/ssh/ssh_host_ed25519_key" }
                }
            }
        })

        assert(#result == 2, "Expected meta.map to iterate wrapped details lists")
        assert(result[1].path == "/etc/ssh/ssh_host_rsa_key", "Expected first wrapped item path to be preserved")
    end)
    teardown()
    if not ok then error(err, 0) end
end
