local file_probe = require('seharden.probes.file')

local function with_dependencies(deps, fn)
    file_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    file_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_find_pattern_surfaces_open_failures()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/tmp/unreadable.conf" then
                return { mode = "file" }
            end
            return nil
        end,
        io_open = function(path, mode)
            assert(path == "/tmp/unreadable.conf", "Expected find_pattern to open the target file")
            assert(mode == "r", "Expected find_pattern to open files read-only")
            return nil, "permission denied"
        end,
    }, function()
        local result, err = file_probe.find_pattern({
            paths = { "/tmp/unreadable.conf" },
            pattern = "needle"
        })

        assert(result == nil, "Expected unreadable file to fail the probe")
        assert(err:find("/tmp/unreadable.conf", 1, true), "Expected error to mention the unreadable path")
    end)
end

function test_find_pattern_surfaces_grep_failures()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/tmp/grep-target.conf" then
                return { mode = "file" }
            end
            return nil
        end,
        os_execute = function(cmd)
            return nil, "exit", 2
        end,
    }, function()
        local result, err = file_probe.find_pattern({
            paths = { "/tmp/grep-target.conf" },
            pattern = "(bad|pattern"
        })

        assert(result == nil, "Expected grep execution failure to fail the probe")
        assert(err:find("/tmp/grep%-target%.conf"), "Expected grep failure to mention the target path")
    end)
end

function test_list_paths_returns_expanded_matches()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/ssh" then
                return { mode = "directory" }
            end
            if path == "/etc/ssh/ssh_host_rsa_key"
                or path == "/etc/ssh/ssh_host_ed25519_key" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/ssh", "Expected list_paths to enumerate the target directory")
            local entries = {
                ".",
                "..",
                "ssh_host_rsa_key",
                "ssh_host_ed25519_key",
                "sshd_config",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
    }, function()
        local result = file_probe.list_paths({
            paths = { "/etc/ssh/ssh_host_*_key" }
        })

        assert(result.count == 2, "Expected two matching host key files")
        assert(result.details[1].path == "/etc/ssh/ssh_host_rsa_key"
            or result.details[2].path == "/etc/ssh/ssh_host_rsa_key",
            "Expected list_paths to include ssh_host_rsa_key")
    end)
end

function test_list_paths_matches_only_public_key_globs()
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
            assert(path == "/etc/ssh", "Expected list_paths to enumerate the target directory")
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
        local result = file_probe.list_paths({
            paths = { "/etc/ssh/ssh_host_*_key.pub" }
        })

        assert(result.count == 2, "Expected only public host key files to match the .pub glob")
        for _, detail in ipairs(result.details) do
            assert(detail.path:match("%.pub$"), "Expected public key glob results to end with .pub")
        end
    end)
end
