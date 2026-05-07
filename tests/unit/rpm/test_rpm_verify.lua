local function with_verify_stubs(opts, fn)
    local saved = {
        verify = package.loaded["rpm.verify"],
        db = package.loaded["rpm.db"],
        checksum = package.loaded["rpm.checksum"],
        sbom = package.loaded["rpm.sbom"],
        lrpm = package.loaded["lrpm"],
    }

    local pkg = {
        name = function() return "demo" end,
        version = function() return "1.0" end,
        release = function() return "1" end,
        arch = function() return "x86_64" end,
    }

    package.loaded["rpm.verify"] = nil
    package.loaded["lrpm"] = {}
    package.loaded["rpm.db"] = {
        create_ts = function()
            return {
                packages = function()
                    local yielded = false
                    return function()
                        if yielded then
                            return nil
                        end
                        yielded = true
                        return pkg
                    end
                end
            }
        end
    }
    package.loaded["rpm.sbom"] = {
        construct_url = function(template)
            return template
        end,
        fetch_and_parse = function()
            return opts.sbom_checksums
        end
    }
    package.loaded["rpm.checksum"] = {
        get_rpm_files = function()
            return opts.rpm_files
        end,
        compute_file_sha256 = function(path)
            local result = opts.disk_checksums[path]
            if result == false then
                return nil, "No such file or directory"
            end
            return result
        end
    }

    local ok, err = pcall(function()
        local verify = require("rpm.verify")
        fn(verify)
    end)

    package.loaded["rpm.verify"] = saved.verify
    package.loaded["rpm.db"] = saved.db
    package.loaded["rpm.checksum"] = saved.checksum
    package.loaded["rpm.sbom"] = saved.sbom
    package.loaded["lrpm"] = saved.lrpm

    if not ok then
        error(err, 0)
    end
end

local function verify_with(opts)
    local code
    with_verify_stubs(opts, function(verify)
        code = verify.verify_package("demo", {
            sbom_url_template = "http://example.invalid/demo.spdx.json",
            verify_config_files = false
        })
    end)
    return code
end

function test_verify_package_passes_when_every_file_matches()
    local code = verify_with({
        rpm_files = {
            ["/usr/bin/demo"] = { checksum_rpm = "abc", is_config = false }
        },
        sbom_checksums = {
            ["/usr/bin/demo"] = "abc"
        },
        disk_checksums = {
            ["/usr/bin/demo"] = "abc"
        }
    })

    assert(code == 0, "Expected matching package verification to pass")
end

function test_verify_package_fails_when_rpm_file_is_missing_from_sbom()
    local code = verify_with({
        rpm_files = {
            ["/usr/bin/demo"] = { checksum_rpm = "abc", is_config = false }
        },
        sbom_checksums = {},
        disk_checksums = {
            ["/usr/bin/demo"] = "abc"
        }
    })

    assert(code == 2, "Expected missing SBOM coverage to fail verification")
end

function test_verify_package_fails_when_rpm_file_is_missing_on_disk()
    local code = verify_with({
        rpm_files = {
            ["/usr/bin/demo"] = { checksum_rpm = "abc", is_config = false }
        },
        sbom_checksums = {
            ["/usr/bin/demo"] = "abc"
        },
        disk_checksums = {
            ["/usr/bin/demo"] = false
        }
    })

    assert(code == 2, "Expected missing package file to fail verification")
end
