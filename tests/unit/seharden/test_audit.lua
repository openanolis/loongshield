local audit_probe = require('seharden.probes.audit')

local function make_reader(lines)
    local index = 0
    return {
        lines = function()
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function()
            return true
        end
    }
end

local function with_dependencies(deps, fn)
    audit_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    audit_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_find_watch_rule_accepts_key_formats_and_permission_order()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/privileged.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/tmp/rules.d", "Expected watch probe to enumerate the rules.d directory")
            local entries = {
                ".",
                "..",
                "privileged.rules",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected audit probe to open rule files read-only")
            if path == "/tmp/audit.rules" then
                return make_reader({
                    "-w /etc/passwd -p wa -k identity"
                })
            end
            if path == "/tmp/rules.d/privileged.rules" then
                return make_reader({
                    "-w /etc/sudoers.d/ -p aw -F key=scope"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local sudoers_result = audit_probe.find_watch_rule({
            path = "/etc/sudoers.d",
            permissions = "wa"
        })
        local passwd_result = audit_probe.find_watch_rule({
            path = "/etc/passwd",
            permissions = "wa"
        })

        assert(sudoers_result.found == true, "Expected /etc/sudoers.d watch rule to be found")
        assert(passwd_result.found == true, "Expected /etc/passwd watch rule to be found")
    end)
end

function test_find_watch_rule_accepts_syscall_style_path_and_dir_filters()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(path == "/tmp/audit.rules", "Expected syscall-style watch probe to open the configured audit.rules file")
            assert(mode == "r", "Expected audit probe to open rule files read-only")
            return make_reader({
                "-a always,exit -F path=/etc/passwd -F perm=wa -F key=identity",
                "-a exit,always -F dir=/etc/sudoers.d/ -F perm=aw -k scope",
            })
        end
    }, function()
        local sudoers_result = audit_probe.find_watch_rule({
            path = "/etc/sudoers.d",
            permissions = "wa"
        })
        local passwd_result = audit_probe.find_watch_rule({
            path = "/etc/passwd",
            permissions = "wa"
        })

        assert(sudoers_result.found == true, "Expected syscall-style directory watch rule to be found")
        assert(passwd_result.found == true, "Expected syscall-style file watch rule to be found")
    end)
end

function test_find_watch_rule_accepts_recursive_parent_directory_watches()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/etc" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(path == "/tmp/audit.rules", "Expected watch probe to open the configured audit.rules file")
            assert(mode == "r", "Expected watch probe to open files read-only")
            return make_reader({
                "-w /etc -p wa -k identity",
                "-a always,exit -F dir=/etc -F perm=wa -F key=identity",
            })
        end
    }, function()
        local passwd_result = audit_probe.find_watch_rule({
            path = "/etc/passwd",
            permissions = "wa"
        })
        local sudoers_result = audit_probe.find_watch_rule({
            path = "/etc/sudoers.d",
            permissions = "wa"
        })

        assert(passwd_result.found == true, "Expected recursive /etc watch to cover /etc/passwd")
        assert(sudoers_result.found == true, "Expected recursive /etc watch to cover /etc/sudoers.d")
    end)
end

function test_find_watch_rule_requires_path_boundary_for_parent_directory_matches()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/etc/pass" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function()
            return make_reader({
                "-w /etc/pass -p wa -k identity",
            })
        end
    }, function()
        local result = audit_probe.find_watch_rule({
            path = "/etc/passwd",
            permissions = "wa"
        })

        assert(result.found == false, "Expected non-boundary directory prefixes not to match watched paths")
    end)
end

function test_find_syscall_rule_aggregates_required_syscalls()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(path == "/tmp/audit.rules", "Expected syscall probe to open the configured audit.rules file")
            assert(mode == "r", "Expected syscall probe to open files read-only")
            return make_reader({
                "-a always,exit -F arch=b64 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete",
                "-a always,exit -F arch=b64 -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
                "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=-1 -k delete",
                "-a exit,always -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=500 -F auid!=-1 -k delete",
            })
        end
    }, function()
        local result = audit_probe.find_syscall_rule({
            syscalls = { "unlink", "unlinkat", "rename", "renameat", "rmdir" },
            auid_min = 1000
        })

        assert(result.count == 0, "Expected required delete syscalls to be aggregated across matching rules")
    end)
end

function test_find_syscall_rule_does_not_mix_syscalls_across_arches()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function()
            return make_reader({
                "-a always,exit -F arch=b64 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete",
                "-a exit,always -F arch=b32 -S rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k delete",
            })
        end
    }, function()
        local result = audit_probe.find_syscall_rule({
            syscalls = { "unlink", "unlinkat", "rename", "renameat", "rmdir" },
            auid_min = 1000
        })

        assert(result.count == 5, "Expected missing syscalls when coverage is split across different audit arches")
    end)
end

function test_find_syscall_rule_reports_missing_required_syscalls()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function()
            return make_reader({
                "-a always,exit -F arch=b64 -S unlink -F auid>=1500 -F auid!=unset -k delete",
                "-a always,exit -F arch=b64 -S rename -F auid>=1000 -k delete",
            })
        end
    }, function()
        local result = audit_probe.find_syscall_rule({
            syscalls = { "unlink", "rename" },
            auid_min = 1000
        })

        assert(result.count == 2, "Expected non-compliant rules to leave both required syscalls missing")
        assert(result.details[1] == "rename" or result.details[2] == "rename",
            "Expected missing syscall details to be preserved")
    end)
end

function test_find_syscall_rule_requires_explicit_biarch_coverage_when_requested()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function()
            return make_reader({
                "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2,rmdir -F auid>=1000 -F auid!=-1 -k delete",
            })
        end
    }, function()
        local result = audit_probe.find_syscall_rule({
            syscalls = { "unlink", "unlinkat", "rename", "renameat", "renameat2", "rmdir" },
            auid_min = 1000,
            required_arches = { "b64", "b32" },
        })

        assert(result.count == 6, "Expected missing syscall count when required b32 rules are absent")
    end)
end

function test_find_syscall_rule_allows_single_required_arch_to_use_unqualified_rules()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/audit.rules" then
                return { mode = "file" }
            end
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = {
                ".",
                "..",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function()
            return make_reader({
                "-a always,exit -S unlink,unlinkat,rename,renameat,renameat2,rmdir -F auid>=1000 -F auid!=-1 -k delete",
            })
        end
    }, function()
        local result = audit_probe.find_syscall_rule({
            syscalls = { "unlink", "unlinkat", "rename", "renameat", "renameat2", "rmdir" },
            auid_min = 1000,
            required_arches = { "b64" },
        })

        assert(result.count == 0, "Expected unqualified rules to satisfy a single required arch")
    end)
end
