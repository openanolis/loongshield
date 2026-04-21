local function capture_print_result(fn)
    local saved_print = _G.print
    local lines = {}

    _G.print = function(...)
        local parts = {}
        for i = 1, select("#", ...) do
            parts[#parts + 1] = tostring(select(i, ...))
        end
        lines[#lines + 1] = table.concat(parts, " ")
    end

    local ok, result = pcall(fn)
    _G.print = saved_print

    return ok, result, lines
end

local function with_stubbed_cli(stubs, fn)
    local saved_cli = package.loaded["rpm.cli"]
    local saved_verify = package.loaded["rpm.verify"]

    package.loaded["rpm.cli"] = nil
    package.loaded["rpm.verify"] = stubs.verify

    local ok, err = pcall(function()
        local cli = require("rpm.cli")
        fn(cli)
    end)

    package.loaded["rpm.cli"] = saved_cli
    package.loaded["rpm.verify"] = saved_verify

    if not ok then
        error(err, 2)
    end
end

function test_help_output_scopes_default_sbom_service()
    local saved_exit = os.exit

    os.exit = function(code)
        error({ __os_exit = true, code = code })
    end

    local ok, err = pcall(function()
        with_stubbed_cli({
            verify = {
                verify_package = function()
                    error("verify_package should not be called for --help")
                end,
            }
        }, function(cli)
            local run_ok, result, lines = capture_print_result(function()
                return cli.run({ "--help" })
            end)
            local output = table.concat(lines, "\n")

            assert(not run_ok, "Expected help flow to terminate via os.exit")
            assert(type(result) == "table" and result.__os_exit and result.code == 0,
                "Expected --help to call os.exit(0)")
            assert(output:find("OpenAnolis / Alibaba Cloud Linux SBOM service", 1, true),
                "Expected help output to describe the default SBOM service")
            assert(output:find("For other RPM repositories, pass --sbom-url explicitly.", 1, true),
                "Expected help output to explain how to override the default SBOM service")
        end)
    end)

    os.exit = saved_exit

    if not ok then
        error(err, 2)
    end
end
