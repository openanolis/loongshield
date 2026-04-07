local permissions_probe = require('seharden.probes.permissions')

local Mocks = {}

local function setup(stat_result)
    Mocks.stat_result = stat_result
    local function fake_stat(path)
        return Mocks.stat_result
    end
    permissions_probe._test_set_dependencies({
        fs_stat = fake_stat
    })
end

local function make_attr(uid, gid, mode)
    return {
        uid = function() return uid end,
        gid = function() return gid end,
        mode = function() return mode end
    }
end

function test_permissions_get_attributes_success()
    setup(make_attr(0, 0, 0644))
    local result = permissions_probe.get_attributes({ path = "/etc/motd" })
    assert(result.exists == true, "Expected exists=true for present files")
    assert(result.uid == 0, "Expected uid 0")
    assert(result.gid == 0, "Expected gid 0")
    assert(result.mode == 0644, "Expected mode 0644")
end

function test_permissions_get_attributes_missing_file()
    setup(nil)
    local result, err = permissions_probe.get_attributes({ path = "/does/not/exist" })
    assert(err == nil, "Expected missing files to be reported in-band")
    assert(result ~= nil, "Expected structured result when file missing")
    assert(result.exists == false, "Expected exists=false when file missing")
end

function test_permissions_get_attributes_requires_path()
    local result, err = permissions_probe.get_attributes(nil)
    assert(result == nil, "Expected nil result when path is missing")
    assert(err:match("requires a 'path' parameter"), "Expected missing path error")
end
