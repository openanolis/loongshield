local shell_probe = require('seharden.probes.shell')

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
    shell_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    shell_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_find_tmout_assignments_accepts_stricter_values_and_reports_conflicts()
    with_dependencies({
        expand_paths = function(paths)
            return { "/etc/profile", "/etc/profile.d/hardening.sh" }
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected shell probe to open files read-only")
            if path == "/etc/profile" then
                return make_reader({
                    "   # TMOUT=0",
                    "export TMOUT=900",
                })
            end
            if path == "/etc/profile.d/hardening.sh" then
                return make_reader({
                    "TMOUT=0",
                    "unset TMOUT",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = shell_probe.find_tmout_assignments({
            paths = { "/etc/profile", "/etc/profile.d/*.sh" },
            max_value = 1800,
        })

        assert(result.count == 1, "Expected a stricter TMOUT assignment to be accepted")
        assert(result.conflicting_count == 2, "Expected explicit TMOUT weakening to be reported")
    end)
end

function test_check_umask_value_accepts_more_restrictive_masks()
    assert(shell_probe.check_umask_value({ value = "027", baseline = "027" }).compliant == true,
        "Expected baseline umask to be compliant")
    assert(shell_probe.check_umask_value({ value = "037", baseline = "027" }).compliant == true,
        "Expected stricter umask to be compliant")
    assert(shell_probe.check_umask_value({ value = "u=rwx,g=rx,o=", baseline = "027" }).compliant == true,
        "Expected symbolic umask equivalent to 027 to be compliant")
    assert(shell_probe.check_umask_value({ value = "g-w,o-rwx", baseline = "027" }).compliant == true,
        "Expected relative symbolic umask that guarantees 027-or-stricter to be compliant")
    assert(shell_probe.check_umask_value({ value = "o-rwx", baseline = "027" }).compliant == false,
        "Expected partially-relative symbolic umask with unknown group write state to stay non-compliant")
    assert(shell_probe.check_umask_value({ value = "022", baseline = "027" }).compliant == false,
        "Expected weaker umask to be rejected")
end

function test_find_umask_commands_ignores_comments_and_reports_conflicts()
    with_dependencies({
        expand_paths = function(paths)
            return { "/etc/profile" }
        end,
        io_open = function(path, mode)
            assert(path == "/etc/profile", "Expected shell probe to read the configured profile")
            assert(mode == "r", "Expected shell probe to open files read-only")
            return make_reader({
                "# umask 022",
                "umask 027",
                "umask 022",
            })
        end
    }, function()
        local result = shell_probe.find_umask_commands({
            paths = { "/etc/profile" },
            baseline = "027",
        })

        assert(result.count == 1, "Expected compliant umask commands to be collected")
        assert(result.conflicting_count == 1, "Expected weaker umask commands to be reported")
    end)
end

function test_find_umask_commands_accepts_symbolic_assignments()
    with_dependencies({
        expand_paths = function(paths)
            return { "/etc/profile" }
        end,
        io_open = function(path, mode)
            assert(path == "/etc/profile", "Expected shell probe to read the configured profile")
            assert(mode == "r", "Expected shell probe to open files read-only")
            return make_reader({
                "umask u=rwx,g=rx,o=",
                "umask u=rwx,g=rwx,o=rx",
            })
        end
    }, function()
        local result = shell_probe.find_umask_commands({
            paths = { "/etc/profile" },
            baseline = "027",
        })

        assert(result.count == 1, "Expected compliant symbolic umask assignments to be collected")
        assert(result.conflicting_count == 1, "Expected weaker symbolic umask assignments to be reported")
    end)
end

function test_find_umask_commands_classifies_relative_symbolic_assignments_conservatively()
    with_dependencies({
        expand_paths = function(paths)
            return { "/etc/profile" }
        end,
        io_open = function(path, mode)
            assert(path == "/etc/profile", "Expected shell probe to read the configured profile")
            assert(mode == "r", "Expected shell probe to open files read-only")
            return make_reader({
                "umask g-w,o-rwx",
                "umask g+w",
                "umask o-rwx",
            })
        end
    }, function()
        local result = shell_probe.find_umask_commands({
            paths = { "/etc/profile" },
            baseline = "027",
        })

        assert(result.count == 1, "Expected guaranteed-compliant relative symbolic umask assignments to be collected")
        assert(result.conflicting_count == 1, "Expected guaranteed-weakening relative symbolic umask assignments to be reported")
    end)
end
