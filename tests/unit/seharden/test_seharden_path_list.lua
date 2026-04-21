local path_list = require('seharden.shared.path_list')

local function with_dependencies(deps, fn)
    path_list._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    path_list._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_expand_files_returns_glob_matches_once()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/ssh" then
                return { mode = "directory" }
            end
            if path == "/etc/ssh/ssh_host_rsa_key"
                or path == "/etc/ssh/ssh_host_rsa_key.pub"
                or path == "/etc/ssh/ssh_host_ed25519_key.pub" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/ssh", "Expected helper to enumerate the target directory")
            local entries = {
                ".",
                "..",
                "ssh_host_rsa_key",
                "ssh_host_rsa_key.pub",
                "ssh_host_ed25519_key.pub",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
    }, function()
        local result = path_list.expand_files({
            "/etc/ssh/ssh_host_*_key.pub",
            "/etc/ssh/ssh_host_rsa_key.pub",
        })

        assert(#result == 2, "Expected duplicate matches to be returned only once")
        assert(result[1]:match("%.pub$") and result[2]:match("%.pub$"),
            "Expected helper to keep only files that match the requested glob")
    end)
end

function test_expand_files_skips_missing_paths_and_directories()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/profile" then
                return { mode = "file" }
            end
            if path == "/etc/profile.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            error("Expected non-glob paths to avoid directory enumeration")
        end,
    }, function()
        local result = path_list.expand_files({
            "/etc/profile",
            "/etc/profile.d",
            "/missing",
            "",
        })

        assert(#result == 1, "Expected helper to ignore missing paths and directories")
        assert(result[1] == "/etc/profile", "Expected existing regular files to be preserved")
    end)
end
