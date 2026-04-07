local log = require('runtime.log')
local openssl = require('openssl')
local rpmdb = require('rpm.db')

local M = {}

local _dependencies = {
    io_popen = io.popen,
    lrpm = nil,
}

local FILE_FLAG_CONFIG = 1
local FILE_FLAG_DOC = 2
local ZERO_DIGESTS = {
    ["00000000000000000000000000000000"] = true,
    ["0000000000000000000000000000000000000000000000000000000000000000"] = true,
}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.io_popen = deps.io_popen or io.popen
    if deps.lrpm ~= nil then
        _dependencies.lrpm = deps.lrpm
    else
        _dependencies.lrpm = nil
    end
end

-- Parse tab-delimited rpm query output:
-- <path>\t<size>\t<digest>\t<fileflags>
local function parse_query_output(output)
    local files = {}
    local file_count = 0

    for line in output:gmatch("[^\r\n]+") do
        local path, size, digest, flags = line:match("^(.-)\t([0-9]+)\t([^\t]*)\t([0-9]+)$")
        if path and size and flags then
            local file_flags = tonumber(flags) or 0
            digest = digest:lower()
            if digest ~= "" and not ZERO_DIGESTS[digest] then
                files[path] = {
                    size = tonumber(size),
                    checksum_rpm = digest,
                    is_config = (file_flags % 2) == FILE_FLAG_CONFIG,
                    is_doc = (math.floor(file_flags / 2) % 2) == 1
                }
                file_count = file_count + 1
            end
        end
    end

    return files, file_count
end

local function parse_binding_files(pkg)
    local files = {}
    local file_count = 0

    for file in pkg:files() do
        local digest = file:digest()
        if digest then
            digest = digest:lower()
        end

        if digest and digest ~= "" and not ZERO_DIGESTS[digest] then
            local file_flags = file:flags() or 0
            files[file:name()] = {
                size = file:size(),
                checksum_rpm = digest,
                is_config = (file_flags % 2) == FILE_FLAG_CONFIG,
                is_doc = (math.floor(file_flags / 2) % 2) == 1
            }
            file_count = file_count + 1
        end
    end

    return files, file_count
end

local function get_rpm_files_from_binding(package_name, rpm)
    local ts = rpmdb.create_ts(rpm)

    for pkg in ts:packages(package_name) do
        local files, file_count = parse_binding_files(pkg)
        log.debug("Found %d files in package", file_count)
        return files
    end

    return nil, string.format("Package not installed: %s", package_name)
end

-- Get file list from RPM package via shell command
function M.get_rpm_files(package_name)
    log.debug("Getting file list for package: %s", package_name)

    local rpm = _dependencies.lrpm
    if rpm == nil then
        local ok, module = pcall(require, 'lrpm')
        if ok then
            rpm = module
        else
            rpm = false
        end
        _dependencies.lrpm = rpm
    end

    if rpm then
        local ok, files, err = pcall(get_rpm_files_from_binding, package_name, rpm)
        if ok then
            if files or err == string.format("Package not installed: %s", package_name) then
                return files, err
            end
            log.warn("lrpm file query failed, falling back to rpm CLI: %s", tostring(err))
        else
            log.warn("lrpm file query failed, falling back to rpm CLI: %s", tostring(files))
        end
    end

    -- Escape single quotes in package name
    local escaped_name = package_name:gsub("'", "'\\''")
    local cmd = string.format(
        "rpm -q --qf '[%%{FILENAMES}\\t%%{FILESIZES}\\t%%{FILEDIGESTS}\\t%%{FILEFLAGS}\\n]' '%s' 2>&1",
        escaped_name
    )

    local handle = _dependencies.io_popen(cmd)
    if not handle then
        return nil, "Failed to execute rpm command"
    end

    local output = handle:read("*a")
    local success, exit_reason, exit_code = handle:close()

    if not success then
        if output:match("not installed") or output:match("is not installed") then
            return nil, string.format("Package not installed: %s", package_name)
        end
        return nil, string.format("rpm command failed (exit code %s): %s",
            tostring(exit_code), output)
    end

    local files, file_count = parse_query_output(output)
    log.debug("Found %d files in package", file_count)

    return files
end

-- Compute SHA256 hash of a file
function M.compute_file_sha256(filepath)
    local f, err = io.open(filepath, "rb")
    if not f then
        return nil, err
    end

    local sha256 = openssl.digest.new("sha256")
    if not sha256 then
        f:close()
        return nil, "Failed to create SHA256 digest"
    end

    -- Read file in chunks to avoid loading large files into memory
    while true do
        local chunk = f:read(8192)
        if not chunk then break end
        sha256:update(chunk)
    end
    f:close()

    local hash = sha256:final()
    if not hash then
        return nil, "Failed to finalize hash"
    end

    -- Convert to lowercase hex string
    return hash:lower()
end

return M
