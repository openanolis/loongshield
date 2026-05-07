local boot_probe = require('seharden.probes.boot')

local function with_dependencies(deps, fn)
    boot_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    boot_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

local function handle_for(content)
    return {
        lines = function()
            local lines = {}
            for line in (content .. "\n"):gmatch("(.-)\n") do
                lines[#lines + 1] = line
            end
            local index = 0
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function() end,
    }
end

function test_inspect_kernel_parameter_requires_boot_and_default_grub_values()
    local files = {
        ["/boot/grub2/grub.cfg"] = "linux /vmlinuz quiet audit_backlog_limit=8192\n",
        ["/etc/default/grub"] = 'GRUB_CMDLINE_LINUX="quiet audit_backlog_limit=8192"\n',
    }

    with_dependencies({
        lfs_attributes = function(path)
            if files[path] then
                return { mode = "file" }
            end
            return nil
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only boot config access")
            return handle_for(assert(files[path], "Unexpected path: " .. tostring(path)))
        end,
    }, function()
        local result = boot_probe.inspect_kernel_parameter({
            name = "audit_backlog_limit",
            numeric_min = 8192,
            boot_paths = { "/boot/grub2/grub.cfg" },
            default_paths = { "/etc/default/grub" },
        })

        assert(result.available == true, "Expected boot evidence to be available")
        assert(result.boot_configured == true, "Expected boot entries to pass")
        assert(result.default_configured == true, "Expected /etc/default/grub to pass")
        assert(result.all_configured == true, "Expected aggregate pass")
    end)
end

function test_inspect_kernel_parameter_rejects_missing_or_small_values()
    local files = {
        ["/boot/grub2/grub.cfg"] = table.concat({
            "linux /vmlinuz quiet audit_backlog_limit=8192",
            "linux /vmlinuz-rescue quiet audit_backlog_limit=64",
        }, "\n"),
        ["/etc/default/grub"] = 'GRUB_CMDLINE_LINUX="quiet"\n',
    }

    with_dependencies({
        lfs_attributes = function(path)
            if files[path] then
                return { mode = "file" }
            end
            return nil
        end,
        io_open = function(path)
            return handle_for(assert(files[path], "Unexpected path: " .. tostring(path)))
        end,
    }, function()
        local result = boot_probe.inspect_kernel_parameter({
            name = "audit_backlog_limit",
            numeric_min = 8192,
            boot_paths = { "/boot/grub2/grub.cfg" },
            default_paths = { "/etc/default/grub" },
        })

        assert(result.boot_configured == false, "Expected undersized kernel entry to fail")
        assert(result.default_configured == false, "Expected missing default grub parameter to fail")
        assert(result.violation_count == 2, "Expected both violations to be counted")
        assert(result.all_configured == false, "Expected aggregate failure")
    end)
end

function test_inspect_kernel_parameter_fails_when_evidence_missing()
    with_dependencies({
        lfs_attributes = function()
            return nil
        end,
    }, function()
        local result = boot_probe.inspect_kernel_parameter({
            name = "audit_backlog_limit",
            numeric_min = 8192,
            boot_paths = { "/boot/grub2/grub.cfg" },
            default_paths = { "/etc/default/grub" },
        })

        assert(result.available == true, "Expected missing files to be reported in-band")
        assert(result.boot_configured == false, "Expected missing boot entries to fail")
        assert(result.default_configured == false, "Expected missing default grub to fail")
        assert(result.all_configured == false, "Expected missing evidence not to pass")
    end)
end
