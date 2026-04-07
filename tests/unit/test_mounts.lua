local mounts_probe = require('seharden.probes.mounts')

local function make_iter(items)
    local i = 0
    return function()
        i = i + 1
        return items[i]
    end
end

local function make_fs(target, source, fstype, options)
    return {
        target = function() return target end,
        source = function() return source end,
        fstype = function() return fstype end,
        options = function() return options end
    }
end

local function make_ctx(fs_items)
    local mtab = {
        fs = function() return make_iter(fs_items) end
    }
    return {
        get_mtab = function() return mtab end
    }
end

function test_get_mount_info_found()
    mounts_probe._test_set_dependencies({
        mount_new_context = function()
            return make_ctx({
                make_fs("/tmp", "tmpfs", "tmpfs", "rw,nosuid,nodev"),
            })
        end
    })

    local result = mounts_probe.get_mount_info({ path = "/tmp" })
    assert(result.exists == true, "Expected mount to exist")
    assert(result.fstype == "tmpfs", "Expected tmpfs fstype")
    assert(result.options.nosuid == true, "Expected nosuid option")
end

function test_get_mount_info_missing()
    mounts_probe._test_set_dependencies({
        mount_new_context = function()
            return make_ctx({})
        end
    })

    local result = mounts_probe.get_mount_info({ path = "/var" })
    assert(result.exists == false, "Expected mount to be missing")
end

function test_get_mount_info_missing_param()
    local result, err = mounts_probe.get_mount_info({})
    assert(result == nil, "Expected nil result for missing param")
    assert(err:match("requires a 'path' parameter"), "Expected missing param error")
end

function test_get_mount_info_missing_param_nil()
    local result, err = mounts_probe.get_mount_info(nil)
    assert(result == nil, "Expected nil result for nil params")
    assert(err:match("requires a 'path' parameter"), "Expected missing param error")
end

function test_get_mount_info_reads_fresh_mount_table_each_call()
    local calls = 0

    mounts_probe._test_set_dependencies({
        mount_new_context = function()
            calls = calls + 1
            if calls == 1 then
                return make_ctx({
                    make_fs("/tmp", "tmpfs", "tmpfs", "rw,nosuid,nodev"),
                })
            end
            return make_ctx({})
        end
    })

    local first = mounts_probe.get_mount_info({ path = "/tmp" })
    local second = mounts_probe.get_mount_info({ path = "/tmp" })

    assert(first.exists == true, "Expected first call to find mount")
    assert(second.exists == false, "Expected second call to reflect updated mount table")
    assert(calls == 2, "Expected mount table to be reloaded on each call")
end
