local checksum = require('rpm.checksum')
local rpmdb = require('rpm.db')

local TMP_PATH = "/tmp/loongshield_checksum_test.txt"

local function make_popen_handle(output, ok, code)
    return {
        read = function()
            return output
        end,
        close = function()
            if ok then
                return true, "exit", 0
            end
            return nil, "exit", code or 1
        end
    }
end

function test_compute_file_sha256_success()
    local f = assert(io.open(TMP_PATH, "w"))
    f:write("hello")
    f:close()

    local hash, err = checksum.compute_file_sha256(TMP_PATH)
    assert(err == nil, "Did not expect error computing hash")
    assert(hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "Unexpected sha256 hash")

    os.remove(TMP_PATH)
end

function test_compute_file_sha256_missing_file()
    os.remove(TMP_PATH)
    local hash, err = checksum.compute_file_sha256(TMP_PATH)
    assert(hash == nil, "Expected nil hash for missing file")
    assert(err, "Expected error for missing file")
end

function test_get_rpm_files_preserves_spaces_in_paths_and_parses_flags()
    checksum._test_set_dependencies({
        lrpm = false,
        io_popen = function()
            return make_popen_handle(table.concat({
                "/usr/share/my file.txt\t10\tabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\t1",
                "/usr/share/doc/demo.txt\t20\t1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\t2",
                "/usr/bin/link\t0\t\t0",
            }, "\n"), true, 0)
        end
    })

    local files, err = checksum.get_rpm_files("demo")
    checksum._test_set_dependencies()

    assert(err == nil, "Did not expect RPM query parsing to fail")
    assert(files["/usr/share/my file.txt"] ~= nil, "Expected spaces in path to be preserved")
    assert(files["/usr/share/my file.txt"].size == 10, "Expected file size to be parsed")
    assert(files["/usr/share/my file.txt"].is_config == true, "Expected config flag to be parsed")
    assert(files["/usr/share/doc/demo.txt"].is_doc == true, "Expected doc flag to be parsed")
    assert(files["/usr/bin/link"] == nil, "Expected empty-digest entries to be skipped")
end

function test_get_rpm_files_handles_not_installed_packages()
    checksum._test_set_dependencies({
        lrpm = false,
        io_popen = function()
            return make_popen_handle("package demo is not installed\n", false, 1)
        end
    })

    local files, err = checksum.get_rpm_files("demo")
    checksum._test_set_dependencies()

    assert(files == nil, "Expected nil result for non-installed package")
    assert(err == "Package not installed: demo", "Expected not-installed error message")
end

function test_get_rpm_files_uses_lrpm_binding_when_available()
    rpmdb._test_set_dependencies({
        lfs_attributes = function()
            return "directory"
        end
    })

    checksum._test_set_dependencies({
        io_popen = function()
            error("shell fallback should not be used when lrpm binding succeeds")
        end,
        lrpm = {
            getpath = function()
                return "/mock/rpmdb"
            end,
            pushmacro = function()
                return true
            end,
            tscreate = function()
                return {
                    rootdir = function()
                        return true
                    end,
                    packages = function(_, name)
                        assert(name == "demo", "Expected package lookup to use indexed name query")
                        local returned = false
                        return function()
                            if returned then
                                return nil
                            end
                            returned = true
                            return {
                                files = function()
                                    local idx = 0
                                    local entries = {
                                        {
                                            name = function()
                                                return "/etc/demo.conf"
                                            end,
                                            size = function()
                                                return 10
                                            end,
                                            digest = function()
                                                return "ABCDEF"
                                            end,
                                            flags = function()
                                                return 1
                                            end,
                                        },
                                        {
                                            name = function()
                                                return "/usr/share/doc/demo.txt"
                                            end,
                                            size = function()
                                                return 20
                                            end,
                                            digest = function()
                                                return "1234"
                                            end,
                                            flags = function()
                                                return 2
                                            end,
                                        },
                                        {
                                            name = function()
                                                return "/usr/bin/link"
                                            end,
                                            size = function()
                                                return 0
                                            end,
                                            digest = function()
                                                return nil
                                            end,
                                            flags = function()
                                                return 0
                                            end,
                                        },
                                    }
                                    return function()
                                        idx = idx + 1
                                        return entries[idx]
                                    end
                                end,
                            }
                        end
                    end,
                }
            end,
        }
    })

    local files, err = checksum.get_rpm_files("demo")

    checksum._test_set_dependencies()
    rpmdb._test_set_dependencies()

    assert(err == nil, "Did not expect lrpm-backed query to fail")
    assert(files["/etc/demo.conf"] ~= nil, "Expected lrpm file list to include config file")
    assert(files["/etc/demo.conf"].checksum_rpm == "abcdef", "Expected digest to be normalized to lowercase")
    assert(files["/etc/demo.conf"].is_config == true, "Expected config flag to be parsed from binding")
    assert(files["/usr/share/doc/demo.txt"].is_doc == true, "Expected doc flag to be parsed from binding")
    assert(files["/usr/bin/link"] == nil, "Expected nil digests to be skipped")
end
