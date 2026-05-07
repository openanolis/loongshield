local M = {}

local deps = {
    io_open = io.open,
    require = require,
}

local REQUIRED_FIELDS = {
    { name = "name", type = "string" },
    { name = "author", type = "string" },
    { name = "description", type = "string" },
    { name = "license", type = "string" },
    { name = "version", type = "number" },
}

local UNSUPPORTED_HOOKS = {
    getprocattr = true,
    setprocattr = true,
    lsmprop_to_secctx = true,
}

local function read_file(path)
    local file, err = deps.io_open(path, "rb")
    if not file then
        return nil, err or ("failed to open " .. path)
    end

    local content = file:read("*a")
    file:close()
    return content or ""
end

local function sandbox_require(name)
    local known = {
        kernel = {},
        fs = {},
        net = {},
        errno = { EPERM = 1, EACCES = 13 },
        capability = {},
        signal = {},
    }
    if known[name] then
        return known[name]
    end
    error("unsupported Lua-LSM validation require: " .. tostring(name), 2)
end

local function sandbox_env()
    return {
        assert = assert,
        error = error,
        ipairs = ipairs,
        next = next,
        pairs = pairs,
        pcall = pcall,
        require = sandbox_require,
        select = select,
        tonumber = tonumber,
        tostring = tostring,
        type = type,
        unpack = unpack,
        math = math,
        string = string,
        table = table,
    }
end

local function validate_metadata(module)
    if type(module) ~= "table" then
        return nil, "policy chunk must return a table"
    end

    for _, field in ipairs(REQUIRED_FIELDS) do
        if type(module[field.name]) ~= field.type then
            return nil, string.format("policy field '%s' must be a %s", field.name, field.type)
        end
    end

    for name, value in pairs(module) do
        if UNSUPPORTED_HOOKS[name] then
            return nil, "policy uses unsupported Lua-LSM hook: " .. name
        end
        if name:match("^[%w_]+$") and type(value) ~= "function" then
            -- Metadata fields were already checked above; other non-function
            -- fields are allowed because policies may carry local constants.
        end
    end

    return {
        name = module.name,
        author = module.author,
        description = module.description,
        license = module.license,
        version = module.version,
    }
end

function M.validate_source(source, source_name)
    if type(source) ~= "string" or source == "" then
        return nil, "policy source is empty"
    end

    local chunk, err = loadstring(source, "=" .. tostring(source_name or "lua-lsm-policy"))
    if not chunk then
        return nil, err
    end

    setfenv(chunk, sandbox_env())
    local ok, module = pcall(chunk)
    if not ok then
        return nil, module
    end

    return validate_metadata(module)
end

function M.validate_file(path)
    local source, err = read_file(path)
    if not source then
        return nil, err
    end
    return M.validate_source(source, path)
end

local function validate_manifest_entry(entry, index)
    if type(entry) ~= "table" then
        return nil, string.format("manifest policy entry %d must be a table", index)
    end
    if type(entry.name) ~= "string" or entry.name == "" then
        return nil, string.format("manifest policy entry %d requires a name", index)
    end
    if type(entry.file) ~= "string" or entry.file == "" then
        return nil, string.format("manifest policy '%s' requires a file", entry.name)
    end
    if entry.enabled ~= nil and type(entry.enabled) ~= "boolean" then
        return nil, string.format("manifest policy '%s' enabled must be boolean", entry.name)
    end
    if entry.order ~= nil and type(entry.order) ~= "number" then
        return nil, string.format("manifest policy '%s' order must be number", entry.name)
    end
    if entry.checksum ~= nil and type(entry.checksum) ~= "string" then
        return nil, string.format("manifest policy '%s' checksum must be string", entry.name)
    end
    return true
end

function M.load_manifest(path)
    local content, err = read_file(path)
    if not content then
        return nil, err
    end

    local ok, lyaml = pcall(deps.require, "lyaml")
    if not ok then
        return nil, "lyaml is required to read Lua-LSM manifests"
    end

    local parsed_ok, manifest = pcall(lyaml.load, content)
    if not parsed_ok then
        return nil, manifest
    end

    if type(manifest) ~= "table" then
        return nil, "manifest must be a YAML map"
    end
    if type(manifest.policies) ~= "table" then
        return nil, "manifest requires a policies list"
    end

    for index, entry in ipairs(manifest.policies) do
        local valid, validate_err = validate_manifest_entry(entry, index)
        if not valid then
            return nil, validate_err
        end
    end

    return manifest
end

function M._test_set_dependencies(overrides)
    overrides = overrides or {}
    for key, value in pairs(overrides) do
        deps[key] = value
    end
end

function M._test_reset_dependencies()
    deps.io_open = io.open
    deps.require = require
end

return M
