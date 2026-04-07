local log = require('runtime.log')
local cjson = require('cjson.safe')

local M = {}

-- Construct SBOM URL from template and package info
-- Supported template variables:
--   {name} - package name
--   {version} - package version
--   {release} - package release
--   {arch} - package architecture
--   {name_first} - first letter of package name (for alphabetical organization)
function M.construct_url(template, package_info)
    local name_first = package_info.name:sub(1, 1):lower()

    local url = template
        :gsub("{name}", package_info.name)
        :gsub("{version}", package_info.version)
        :gsub("{release}", package_info.release)
        :gsub("{arch}", package_info.arch)
        :gsub("{name_first}", name_first)

    return url
end

-- Download SBOM from URL
-- Returns: sbom_body, error_message
function M.download_sbom(url, config)
    log.info("Downloading SBOM from: %s", url)

    local fetch = require('net.uvcurl').fetch

    -- Download SBOM (in coroutine context)
    local sbom_body, sbom_info, sbom_err = fetch(url, {
        verbose = config.verbose or false,
        timeout = config.timeout or 30000
    })

    if sbom_err then
        return nil, string.format("Network error: %s", sbom_err)
    end

    if not sbom_info or sbom_info.status ~= 200 then
        local status = sbom_info and sbom_info.status or "unknown"
        if status == 404 then
            return nil, string.format("SBOM not found (HTTP 404): %s", url)
        else
            return nil, string.format("HTTP error %s: %s", status, url)
        end
    end

    log.info("SBOM downloaded successfully (%d bytes)", #sbom_body)
    return sbom_body, nil
end

-- Parse SPDX JSON and extract file checksums
-- Returns: table of {filepath -> sha256_checksum}
function M.parse_spdx_json(sbom_json)
    log.debug("Parsing SPDX JSON")

    -- Check if response looks like JSON
    local trimmed = sbom_json:match("^%s*(.-)%s*$")
    if not (trimmed:sub(1, 1) == "{" or trimmed:sub(1, 1) == "[") then
        -- Not JSON, probably HTML error page
        local preview = sbom_json:sub(1, 200):gsub("\n", " ")
        return nil, string.format("Response is not JSON (got HTML/text). Preview: %s...", preview)
    end

    local sbom, parse_err = cjson.decode(sbom_json)
    if not sbom then
        return nil, string.format("Failed to parse SBOM JSON: %s", tostring(parse_err))
    end

    -- Validate SPDX structure
    if not sbom.spdxVersion then
        -- Check if this is an API error response
        if sbom.status and sbom.status.code then
            local code = tonumber(sbom.status.code)
            local message = sbom.status.message or ""
            if code == 404 then
                return nil, "SBOM not found (HTTP 404). This package may not have a published SBOM in the configured repository, or the URL template may not match that repository."
            else
                return nil, string.format("API error (code %d): %s", code, message)
            end
        end

        -- Small response might be an error message from API
        if #sbom_json < 200 then
            return nil, string.format("Invalid SBOM: missing spdxVersion field. API response: %s", sbom_json)
        else
            return nil, "Invalid SBOM: missing spdxVersion field"
        end
    end

    log.debug("SPDX version: %s", sbom.spdxVersion)

    if not sbom.files or type(sbom.files) ~= 'table' then
        return nil, "Invalid SBOM: missing or invalid 'files' array"
    end

    -- Extract file checksums into lookup table
    local file_checksums = {}
    local file_count = 0

    for _, file_entry in ipairs(sbom.files) do
        local filepath = file_entry.fileName

        if not filepath then
            log.warn("SBOM file entry missing fileName, skipping")
            goto continue
        end

        -- Normalize path (SPDX may use relative paths like "./usr/bin/ls")
        filepath = filepath:gsub("^%./", "/")
        if not filepath:match("^/") then
            filepath = "/" .. filepath
        end

        -- SPDX uses array of checksums with algorithm field
        local sha256_checksum = nil
        if file_entry.checksums and type(file_entry.checksums) == 'table' then
            for _, cksum in ipairs(file_entry.checksums) do
                if cksum.algorithm == "SHA256" then
                    sha256_checksum = cksum.checksumValue
                    break
                end
            end
        end

        if sha256_checksum then
            file_checksums[filepath] = sha256_checksum:lower()
            file_count = file_count + 1
        else
            log.warn("No SHA256 checksum found for file: %s", filepath)
        end

        ::continue::
    end

    log.info("Extracted %d file checksums from SBOM", file_count)
    return file_checksums, nil
end

-- Main function to fetch and parse SBOM
function M.fetch_and_parse(url, config)
    local sbom_body, err = M.download_sbom(url, config)
    if not sbom_body then
        return nil, err
    end

    local checksums, parse_err = M.parse_spdx_json(sbom_body)
    if not checksums then
        return nil, parse_err
    end

    return checksums, nil
end

return M
