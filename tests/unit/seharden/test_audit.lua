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

function test_inspect_rule_coverage_requires_watch_in_persistent_and_loaded_sources()
    with_dependencies({
        audit_rules_path = "/tmp/audit.rules",
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/scope.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = { ".", "..", "scope.rules" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path)
            if path == "/etc/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            if path == "/tmp/rules.d/scope.rules" then
                return make_reader({ "-w /etc/sudoers -p wa -k scope" })
            end
            error("Unexpected path: " .. tostring(path))
        end,
        io_popen = function()
            return make_reader({ "-w /etc/sudoers -p wa -k scope" })
        end,
    }, function()
        local result = audit_probe.inspect_rule_coverage({
            requirements = {
                { name = "sudoers", type = "watch", path = "/etc/sudoers", permissions = "wa", key = "scope" },
            },
        })

        assert(result.available == true, "Expected both persistent and loaded audit evidence to be available")
        assert(result.violation_count == 0, "Expected watch rule to be present in both sources")
        assert(result.all_configured == true, "Expected complete source coverage to pass")
    end)
end

function test_inspect_rule_coverage_reports_missing_loaded_source()
    with_dependencies({
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/scope.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = { ".", "..", "scope.rules" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path)
            if path == "/etc/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            if path == "/tmp/rules.d/scope.rules" then
                return make_reader({ "-w /etc/sudoers -p wa -k scope" })
            end
            error("Unexpected path: " .. tostring(path))
        end,
        io_popen = function()
            return nil
        end,
    }, function()
        local result = audit_probe.inspect_rule_coverage({
            requirements = {
                { name = "sudoers", type = "watch", path = "/etc/sudoers", permissions = "wa", key = "scope" },
            },
        })

        assert(result.available == false, "Expected unavailable loaded rules to be explicit")
        assert(result.all_configured == false, "Expected missing loaded evidence to fail")
        assert(result.violation_count == 1, "Expected requirement to fail when a source is unavailable")
    end)
end

function test_inspect_rule_coverage_supports_comparisons_and_auid_unset_without_auid_min()
    local rule = "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -k user_emulation"

    with_dependencies({
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/user.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = { ".", "..", "user.rules" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path)
            if path == "/etc/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            if path == "/tmp/rules.d/user.rules" then
                return make_reader({ rule })
            end
            error("Unexpected path: " .. tostring(path))
        end,
        io_popen = function()
            return make_reader({ rule })
        end,
    }, function()
        local result = audit_probe.inspect_rule_coverage({
            required_arches = { "b64" },
            requirements = {
                {
                    name = "user_emulation",
                    type = "syscall",
                    syscalls = { "execve" },
                    comparisons_any = { "euid!=uid" },
                    auid_min = false,
                    key = "user_emulation",
                },
            },
        })

        assert(result.all_configured == true,
            "Expected uid/euid comparison and auid!=unset to satisfy user emulation coverage")
    end)
end

function test_inspect_rule_coverage_requires_each_exit_filter()
    with_dependencies({
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/access.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = { ".", "..", "access.rules" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path)
            if path == "/etc/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            if path == "/tmp/rules.d/access.rules" then
                return make_reader({
                    "-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
                    "-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access",
                })
            end
            error("Unexpected path: " .. tostring(path))
        end,
        io_popen = function()
            return make_reader({
                "-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access",
                "-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access",
            })
        end,
    }, function()
        local result = audit_probe.inspect_rule_coverage({
            required_arches = { "b64" },
            requirements = {
                {
                    name = "access",
                    type = "syscall",
                    syscalls = { "open", "openat" },
                    exits = { "EACCES", "EPERM" },
                    key = "access",
                },
            },
        })

        assert(result.all_configured == true, "Expected both unsuccessful access exit filters to pass")
    end)
end

function test_inspect_rule_coverage_path_exec_requires_auid_filters()
    with_dependencies({
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/path.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = { ".", "..", "path.rules" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path)
            if path == "/etc/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            if path == "/tmp/rules.d/path.rules" then
                return make_reader({ "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid!=unset -k perm_chng" })
            end
            error("Unexpected path: " .. tostring(path))
        end,
        io_popen = function()
            return make_reader({ "-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid!=-1 -F key=perm_chng" })
        end,
    }, function()
        local result = audit_probe.inspect_rule_coverage({
            requirements = {
                { name = "chcon", type = "path_exec", path = "/usr/bin/chcon", key = "perm_chng" },
            },
        })

        assert(result.all_configured == false, "Expected missing auid>=UID_MIN to fail path exec coverage")
        assert(result.violation_count == 1, "Expected the path exec requirement to be noncompliant")
    end)
end

function test_inspect_rule_coverage_checks_final_directive_value()
    with_dependencies({
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/final.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = { ".", "..", "final.rules" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path)
            if path == "/etc/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            if path == "/tmp/rules.d/final.rules" then
                return make_reader({ "-e 2", "-e 1" })
            end
            error("Unexpected path: " .. tostring(path))
        end,
    }, function()
        local result = audit_probe.inspect_rule_coverage({
            sources = { "persistent" },
            requirements = {
                { name = "immutable", type = "directive", directive = "-e", value = "2" },
            },
        })

        assert(result.all_configured == false, "Expected a later non-immutable directive to fail")
    end)
end

function test_inspect_privileged_command_coverage_builds_path_exec_requirements()
    local rule = "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged"

    with_dependencies({
        audit_rules_d_path = "/tmp/rules.d",
        lfs_attributes = function(path)
            if path == "/tmp/rules.d" then
                return { mode = "directory" }
            end
            if path == "/tmp/rules.d/privileged.rules" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            local entries = { ".", "..", "privileged.rules" }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path)
            if path == "/etc/login.defs" then
                return make_reader({ "UID_MIN 1000" })
            end
            if path == "/tmp/rules.d/privileged.rules" then
                return make_reader({ rule })
            end
            error("Unexpected path: " .. tostring(path))
        end,
        io_popen = function()
            return make_reader({ rule })
        end,
    }, function()
        local result = audit_probe.inspect_privileged_command_coverage({
            paths = { "/usr/bin/passwd" },
        })

        assert(result.checked_requirement_count == 1, "Expected one privileged command requirement")
        assert(result.all_configured == true, "Expected matching persistent and loaded privileged command rules")
    end)
end

--------------------------------------------------------------------------------
-- inspect_audit_log_files / inspect_audit_config_files
--------------------------------------------------------------------------------

local function make_fs_stat_attr(uid, gid, mode)
    return {
        uid = function() return uid end,
        gid = function() return gid end,
        mode = function() return mode end,
    }
end

function test_inspect_audit_log_files_returns_available_false_when_dir_missing()
    with_dependencies({
        lfs_dir = function()
            return nil
        end,
    }, function()
        local result = audit_probe.inspect_audit_log_files({ max_mode = tonumber('600', 8) })
        assert(result.available == false, 'Expected available=false when audit log dir does not exist')
        assert(result.count == 0, 'Expected count=0 when directory is inaccessible')
    end)
end

function test_inspect_audit_log_files_returns_available_true_with_empty_dir()
    with_dependencies({
        lfs_dir = function()
            local names = { '.', '..' }
            local i = 0
            return function()
                i = i + 1
                return names[i]
            end
        end,
        fs_stat = function()
            return nil
        end,
    }, function()
        local result = audit_probe.inspect_audit_log_files({ max_mode = tonumber('600', 8) })
        assert(result.available == true, 'Expected available=true when dir exists but is empty')
        assert(result.count == 0, 'Expected count=0 when no files present')
    end)
end

function test_inspect_audit_log_files_detects_non_compliant_files()
    with_dependencies({
        lfs_dir = function()
            local names = { '.', '..', 'audit.log' }
            local i = 0
            return function()
                i = i + 1
                return names[i]
            end
        end,
        fs_stat = function(path)
            if path == '/var/log/audit/audit.log' then
                return make_fs_stat_attr(1000, 0, tonumber('644', 8))
            end
            return nil
        end,
    }, function()
        local result = audit_probe.inspect_audit_log_files({ max_mode = tonumber('600', 8) })
        assert(result.available == true, 'Expected available=true when directory exists')
        assert(result.count == 1, 'Expected one non-compliant file')
        assert(result.details[1].path == '/var/log/audit/audit.log', 'Expected audit.log in details')
    end)
end

function test_inspect_audit_log_files_accepts_quoted_octal_string_mode()
    -- Profiles pass modes as quoted strings ("0600") because lyaml parses
    -- unquoted leading-zero integers as decimal; the probe must treat the
    -- string as octal.
    local file_mode = tonumber('644', 8)
    with_dependencies({
        lfs_dir = function()
            local names = { '.', '..', 'audit.log' }
            local i = 0
            return function()
                i = i + 1
                return names[i]
            end
        end,
        fs_stat = function(path)
            if path == '/var/log/audit/audit.log' then
                return make_fs_stat_attr(0, 0, file_mode)
            end
            return nil
        end,
    }, function()
        local result = audit_probe.inspect_audit_log_files({ max_mode = '0600' })
        assert(result.count == 1, 'Expected 0644 file to violate max_mode "0600"')
        assert(result.details[1].path == '/var/log/audit/audit.log', 'Expected audit.log in details')

        -- A 0600 file must be compliant under the same string parameter.
        file_mode = tonumber('600', 8)
        local result2 = audit_probe.inspect_audit_log_files({ max_mode = '0600' })
        assert(result2.count == 0, 'Expected 0600 file to be compliant under max_mode "0600"')
    end)
end

function test_inspect_audit_log_files_returns_available_false_when_lfs_dir_raises()
    with_dependencies({
        lfs_dir = function()
            error('cannot open /var/log/audit: No such file or directory')
        end,
    }, function()
        local result = audit_probe.inspect_audit_log_files({ max_mode = tonumber('600', 8) })
        assert(result.available == false, 'Expected available=false when lfs.dir raises')
        assert(result.count == 0, 'Expected count=0 when lfs.dir raises')
    end)
end

function test_inspect_audit_config_files_returns_available_false_when_dir_missing()
    with_dependencies({
        lfs_dir = function()
            return nil
        end,
    }, function()
        local result = audit_probe.inspect_audit_config_files({})
        assert(result.available == false, 'Expected available=false when audit config dir does not exist')
        assert(result.count == 0, 'Expected count=0 when directory is inaccessible')
    end)
end

function test_inspect_audit_config_files_returns_available_false_when_lfs_dir_raises()
    with_dependencies({
        lfs_dir = function()
            error('cannot open /etc/audit: No such file or directory')
        end,
    }, function()
        local result = audit_probe.inspect_audit_config_files({})
        assert(result.available == false, 'Expected available=false when lfs.dir raises')
        assert(result.count == 0, 'Expected count=0 when lfs.dir raises')
    end)
end

function test_inspect_audit_config_files_skips_directories()
    with_dependencies({
        lfs_dir = function()
            local names = { '.', '..', 'audit.rules', 'rules.d' }
            local i = 0
            return function()
                i = i + 1
                return names[i]
            end
        end,
        lfs_attributes = function(path)
            if path == '/etc/audit/rules.d' then
                return { mode = 'directory' }
            end
            return { mode = 'file' }
        end,
        fs_stat = function(path)
            if path == '/etc/audit/audit.rules' then
                return make_fs_stat_attr(0, 0, tonumber('644', 8))
            end
            if path == '/etc/audit/rules.d' then
                return make_fs_stat_attr(0, 0, tonumber('755', 8))
            end
            return nil
        end,
    }, function()
        local result = audit_probe.inspect_audit_config_files({ max_mode = '0640' })
        assert(result.count == 1, 'Expected only the rules file to be flagged, not the rules.d directory')
        assert(result.details[1].path == '/etc/audit/audit.rules', 'Expected audit.rules in details')
    end)
end
