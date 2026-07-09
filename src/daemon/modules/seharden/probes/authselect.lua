local pam_parser = require('seharden.parsers.pam')
local text = require('seharden.shared.text')

local M = {}

local default_dependencies = {
    io_open = io.open,
}

local dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(default_dependencies) do
        dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function read_lines(path)
    local file = dependencies.io_open(path, 'r')
    if not file then
        return nil
    end

    local lines = {}
    for line in file:lines() do
        lines[#lines + 1] = line
    end
    file:close()
    return lines
end

local function read_authselect_conf(path)
    local lines = read_lines(path)
    if not lines then
        return nil
    end

    local profile
    local features = {}
    for _, line in ipairs(lines) do
        local trimmed = text.trim(line)
        if trimmed ~= '' and not trimmed:match('^#') then
            if not profile then
                profile = trimmed
            else
                features[trimmed] = true
            end
        end
    end

    if not profile then
        return nil
    end
    return profile, features
end

local function profile_path_for(profile)
    if profile:match('^custom/') then
        return '/etc/authselect/' .. profile
    end
    if profile:match('^vendor/') then
        return '/usr/share/authselect/' .. profile
    end
    return '/usr/share/authselect/default/' .. profile
end

local function normalize_module_name(name)
    name = tostring(name or '')
    if name:match('^pam_.*%.so$') then
        return name
    end
    if name:match('^pam_') then
        return name .. '.so'
    end
    return 'pam_' .. name .. '.so'
end

local function load_template_entries(path)
    local lines = read_lines(path)
    if not lines then
        return nil
    end

    local entries = {}
    for _, line in ipairs(lines) do
        local entry = pam_parser.parse_line(line)
        if entry then
            entries[#entries + 1] = entry
        end
    end
    return entries
end

local function module_set(entries)
    local modules = {}
    for _, entry in ipairs(entries) do
        modules[entry.module] = true
    end
    return modules
end

local function normalize_modules(modules)
    local normalized = {}
    for _, module in ipairs(modules) do
        normalized[#normalized + 1] = normalize_module_name(module)
    end
    return normalized
end

function M.inspect_profile_modules(params)
    params = params or {}
    local modules = normalize_modules(params.modules or { 'pwquality', 'pwhistory', 'faillock', 'unix' })
    local files = params.files or { 'system-auth', 'password-auth' }
    local conf_path = params.authselect_conf or '/etc/authselect/authselect.conf'

    local profile, features = read_authselect_conf(conf_path)
    if not profile then
        return {
            available = false,
            profile = nil,
            profile_path = nil,
            features = {},
            missing_count = #modules * #files,
            details = {
                {
                    path = conf_path,
                    reason = 'authselect_conf_unreadable',
                },
            },
        }
    end

    local profile_path = profile_path_for(profile)
    local details = {}

    for _, file_name in ipairs(files) do
        local path = profile_path .. '/' .. file_name
        local entries = load_template_entries(path)
        if not entries then
            details[#details + 1] = {
                path = path,
                reason = 'profile_template_unreadable',
            }
        else
            local present_modules = module_set(entries)
            for _, module in ipairs(modules) do
                if not present_modules[module] then
                    details[#details + 1] = {
                        path = path,
                        reason = 'module_missing',
                        module = module,
                    }
                end
            end
        end
    end

    return {
        available = true,
        profile = profile,
        profile_path = profile_path,
        features = features,
        missing_count = #details,
        details = details,
    }
end

return M
