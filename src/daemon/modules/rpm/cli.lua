local log = require('runtime.log')
local verify = require('rpm.verify')

local M = {}

local USAGE = [[
Usage: loongshield rpm [options]

RPM Package SBOM Verification

Options:
  -v, --verify <package>     Verify package against remote SBOM
  --sbom-url <template>      Custom SBOM URL template (overrides default service)
                             Template vars: {name}, {version}, {release}, {arch}, {name_first}
  --verify-config            Verify config files (user-modified files)
  --verbose                  Enable verbose output
  --log-level <level>        Set logging level (trace, debug, info, warn, error)
  -h, --help                 Show this help message

Default URL Template:
  OpenAnolis / Alibaba Cloud Linux SBOM service
  https://anas.openanolis.cn/api/data/SBOM/RPMs/{name_first}/{name}-{version}-{release}.{arch}.rpm.spdx.json

  For other RPM repositories, pass --sbom-url explicitly.

Exit Codes:
  0 - Verification successful (all files match SBOM)
  1 - Error (package not found, network error, parse error)
  2 - Verification failed (checksum mismatches found)

Examples:
  loongshield rpm --verify bash
  loongshield rpm -v glibc --verbose
  loongshield rpm --verify curl --sbom-url "http://localhost:8080/{name}.json"
  loongshield rpm --verify nginx --verify-config
]]

local function print_usage()
    print(USAGE)
end

-- Parse command-line arguments
local function parse_args(argv)
    local options = {
        package_name = nil,
        sbom_url_template = "https://anas.openanolis.cn/api/data/SBOM/RPMs/{name_first}/{name}-{version}-{release}.{arch}.rpm.spdx.json",
        verify_config_files = false,
        verbose = false,
        log_level = "info",
        timeout = 30000
    }

    local i = 1
    while i <= #argv do
        local arg = argv[i]

        if arg == "--help" or arg == "-h" then
            print_usage()
            os.exit(0)
        elseif arg == "--verify" or arg == "-v" then
            i = i + 1
            if i > #argv then
                log.error("Option %s requires a package name", arg)
                return nil, "Missing package name"
            end
            options.package_name = argv[i]
        elseif arg == "--sbom-url" then
            i = i + 1
            if i > #argv then
                log.error("Option --sbom-url requires a URL template")
                return nil, "Missing URL template"
            end
            options.sbom_url_template = argv[i]
        elseif arg == "--verify-config" then
            options.verify_config_files = true
        elseif arg == "--verbose" then
            options.verbose = true
            options.log_level = "debug"
        elseif arg == "--log-level" then
            i = i + 1
            if i > #argv then
                log.error("Option --log-level requires a level")
                return nil, "Missing log level"
            end
            options.log_level = argv[i]
        else
            log.error("Unknown option: %s", arg)
            return nil, string.format("Unknown option: %s", arg)
        end

        i = i + 1
    end

    return options, nil
end

-- Main CLI entry point
function M.run(argv, envp)
    -- Parse arguments
    local options, err = parse_args(argv)
    if not options then
        print_usage()
        return 1
    end

    -- Set log level
    log.setLevel(options.log_level)

    -- Check if package specified
    if not options.package_name then
        log.error("No package specified for verification")
        print("")
        print_usage()
        return 1
    end

    -- Run verification in coroutine (required for uvcurl)
    local uv = require('luv')

    local result = nil
    local co = coroutine.create(function()
        result = verify.verify_package(options.package_name, options)
    end)

    local ok, resume_result = coroutine.resume(co)
    if not ok then
        log.error("Verification failed: %s", tostring(resume_result))
        return 1
    end

    -- Run libuv event loop to process async operations
    uv.run()

    -- Return the result from verify_package
    return result or 1
end

return M
