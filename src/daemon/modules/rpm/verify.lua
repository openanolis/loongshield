local log = require('runtime.log')
local checksum = require('rpm.checksum')
local rpmdb = require('rpm.db')
local sbom = require('rpm.sbom')

local M = {}

-- Get package information (NVRA) from RPM database
local function get_package_info(package_name)
    log.debug("Getting package information for: %s", package_name)

    local rpm = require('lrpm')
    local ts = rpmdb.create_ts(rpm)

    local package_info = nil

    for pkg in ts:packages(package_name) do
        package_info = {
            name = pkg:name(),
            version = pkg:version(),
            release = pkg:release(),
            arch = pkg:arch()
        }
        break
    end

    if not package_info then
        return nil, string.format("Package not found: %s", package_name)
    end

    if not package_info.arch or package_info.arch == "" then
        return nil, "Failed to get package architecture"
    end

    log.info("Package: %s-%s-%s.%s", package_info.name, package_info.version,
        package_info.release, package_info.arch)

    return package_info, nil
end

-- Compare checksums and generate results
local function verify_checksums(rpm_files, sbom_checksums, config)
    local results = {
        total = 0,
        verified = 0,
        mismatches = 0,
        missing_in_sbom = 0,
        missing_on_disk = 0,
        skipped_config = 0,
        errors = 0,
        details = {}
    }

    log.info("Verifying package files...")

    for filepath, file_info in pairs(rpm_files) do
        results.total = results.total + 1

        -- Skip config files if configured
        if file_info.is_config and not config.verify_config_files then
            results.skipped_config = results.skipped_config + 1
            log.debug("Skipping config file: %s", filepath)
            goto continue
        end

        -- Check if file exists in SBOM
        local expected_checksum = sbom_checksums[filepath]
        if not expected_checksum then
            results.missing_in_sbom = results.missing_in_sbom + 1
            table.insert(results.details, {
                file = filepath,
                status = "missing_in_sbom"
            })
            log.warn("File not found in SBOM: %s", filepath)
            goto continue
        end

        -- Compute actual checksum
        local actual_checksum, err = checksum.compute_file_sha256(filepath)
        if not actual_checksum then
            if err and err:match("[Nn]o such file") then
                results.missing_on_disk = results.missing_on_disk + 1
                table.insert(results.details, {
                    file = filepath,
                    status = "missing_on_disk"
                })
                log.warn("File missing on disk: %s", filepath)
            else
                results.errors = results.errors + 1
                table.insert(results.details, {
                    file = filepath,
                    status = "error",
                    error = err
                })
                log.error("Failed to compute checksum for %s: %s", filepath, err or "unknown error")
            end
            goto continue
        end

        -- Compare checksums
        if actual_checksum == expected_checksum then
            results.verified = results.verified + 1
            log.debug("Verified: %s", filepath)
        else
            results.mismatches = results.mismatches + 1
            table.insert(results.details, {
                file = filepath,
                status = "mismatch",
                expected = expected_checksum,
                actual = actual_checksum
            })
            log.error("Checksum mismatch: %s", filepath)
            log.error("  Expected: %s", expected_checksum)
            log.error("  Actual:   %s", actual_checksum)
        end

        ::continue::
    end

    return results
end

-- Print verification summary
local function print_summary(package_info, results)
    print("")
    print("Summary:")
    print(string.format("  Package: %s-%s-%s.%s",
        package_info.name, package_info.version,
        package_info.release, package_info.arch))
    print(string.format("  Total files: %d", results.total))
    print(string.format("  Verified: %d", results.verified))

    if results.skipped_config > 0 then
        print(string.format("  Skipped: %d (config files)", results.skipped_config))
    end

    if results.missing_in_sbom > 0 then
        print(string.format("  Missing in SBOM: %d", results.missing_in_sbom))
    end

    if results.missing_on_disk > 0 then
        print(string.format("  Missing on disk: %d", results.missing_on_disk))
    end

    if results.errors > 0 then
        print(string.format("  Errors: %d", results.errors))
    end

    print(string.format("  Mismatches: %d", results.mismatches))

    if results.mismatches == 0 and results.errors == 0 then
        print("  Status: PASSED")
    else
        print("  Status: FAILED")
    end
    print("")
end

-- Main verification function
function M.verify_package(package_name, config)
    log.info("Starting verification for package: %s", package_name)

    -- Step 1: Get package information
    local package_info, err = get_package_info(package_name)
    if not package_info then
        log.error("%s", err)
        return 1
    end

    -- Step 2: Construct SBOM URL
    local url = sbom.construct_url(config.sbom_url_template, package_info)
    log.debug("SBOM URL: %s", url)

    -- Step 3: Download and parse SBOM
    local sbom_checksums, sbom_err = sbom.fetch_and_parse(url, config)
    if not sbom_checksums then
        log.error("Failed to fetch/parse SBOM: %s", sbom_err)
        return 1
    end

    -- Step 4: Get RPM file list
    local rpm_files, rpm_err = checksum.get_rpm_files(package_name)
    if not rpm_files then
        log.error("Failed to get RPM file list: %s", rpm_err)
        return 1
    end

    -- Step 5: Verify checksums
    local results = verify_checksums(rpm_files, sbom_checksums, config)

    -- Step 6: Print summary
    print_summary(package_info, results)

    -- Determine exit code
    if results.mismatches > 0 then
        return 2 -- Verification failed
    elseif results.errors > 0 then
        return 1 -- Errors occurred
    else
        return 0 -- Success
    end
end

return M
