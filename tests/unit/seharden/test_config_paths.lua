local config_paths = require('seharden.shared.config_paths')

local function with_dependencies(deps, fn)
    config_paths._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    config_paths._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_first_existing_file_uses_directory_precedence()
    with_dependencies({
        lfs_attributes = function(path, attr)
            local files = {
                ["/run/systemd/journald.conf"] = true,
                ["/usr/lib/systemd/journald.conf"] = true,
            }
            local mode = files[path] and "file" or nil
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
    }, function()
        local path = config_paths.first_existing_file({
            "/etc/systemd",
            "/run/systemd",
            "/usr/lib/systemd",
        }, "journald.conf")

        assert(path == "/run/systemd/journald.conf",
            "Expected first existing file to respect directory precedence")
    end)
end

function test_sorted_unique_files_masks_same_name_lower_priority_files()
    local files = {
        ["/etc/systemd/journald.conf.d/20-default.conf"] = true,
        ["/run/systemd/journald.conf.d/30-runtime.conf"] = true,
        ["/usr/lib/systemd/journald.conf.d/20-default.conf"] = true,
        ["/usr/lib/systemd/journald.conf.d/10-base.conf"] = true,
    }
    local dirs = {
        ["/etc/systemd/journald.conf.d"] = { ".", "..", "20-default.conf", "40-directory.conf" },
        ["/run/systemd/journald.conf.d"] = { ".", "..", "30-runtime.conf" },
        ["/usr/lib/systemd/journald.conf.d"] = { ".", "..", "20-default.conf", "10-base.conf" },
        ["/etc/systemd/journald.conf.d/40-directory.conf"] = { ".", ".." },
    }

    with_dependencies({
        lfs_attributes = function(path, attr)
            local mode
            if files[path] then
                mode = "file"
            elseif dirs[path] then
                mode = "directory"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function(path)
            local entries = assert(dirs[path], "Unexpected directory: " .. tostring(path))
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
    }, function()
        local files = config_paths.sorted_unique_files({
            "/etc/systemd",
            "/run/systemd",
            "/usr/lib/systemd",
        }, "journald.conf.d", "%.conf$")

        assert(#files == 3, "Expected unique drop-ins by basename")
        assert(files[1] == "/usr/lib/systemd/journald.conf.d/10-base.conf",
            "Expected files to be returned in lexical basename order")
        assert(files[2] == "/etc/systemd/journald.conf.d/20-default.conf",
            "Expected higher-priority same-name drop-in to mask lower-priority file")
        assert(files[3] == "/run/systemd/journald.conf.d/30-runtime.conf",
            "Expected later lexical drop-in to be preserved")
    end)
end
