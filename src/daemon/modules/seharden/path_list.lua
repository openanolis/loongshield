local lfs = require('lfs')
local text = require('seharden.text')

local M = {}

local default_dependencies = {
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
}

local dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(default_dependencies) do
        dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function join_path(base, part)
    if base == "." then
        return part
    elseif base == "/" then
        return "/" .. part
    end
    return base .. "/" .. part
end

local function has_wildcard(value)
    return value:find("[%*%?%[]") ~= nil
end

local function path_mode(path)
    local attr = dependencies.lfs_attributes(path)
    return attr and attr.mode or nil
end

local function expand_glob_path(path_glob)
    local is_abs = path_glob:sub(1, 1) == "/"
    local parts = {}

    for part in path_glob:gmatch("[^/]+") do
        parts[#parts + 1] = part
    end

    local bases = { is_abs and "/" or "." }
    for _, part in ipairs(parts) do
        if part == "." then
            goto continue
        end

        if part == ".." then
            local new_bases = {}
            local seen = {}
            for _, base in ipairs(bases) do
                local parent
                if base == "/" then
                    parent = "/"
                else
                    parent = base:match("^(.*)/[^/]+$") or "."
                end
                if not seen[parent] then
                    new_bases[#new_bases + 1] = parent
                    seen[parent] = true
                end
            end
            bases = new_bases
            goto continue
        end

        if has_wildcard(part) then
            local pattern = text.glob_to_pattern(part)
            local new_bases = {}
            local seen = {}
            for _, base in ipairs(bases) do
                if path_mode(base) == "directory" then
                    for name in dependencies.lfs_dir(base) do
                        if name ~= "." and name ~= ".." and name:match(pattern) then
                            local full = join_path(base, name)
                            if not seen[full] then
                                new_bases[#new_bases + 1] = full
                                seen[full] = true
                            end
                        end
                    end
                end
            end
            bases = new_bases
        else
            local new_bases = {}
            local seen = {}
            for _, base in ipairs(bases) do
                local full = join_path(base, part)
                if not seen[full] then
                    new_bases[#new_bases + 1] = full
                    seen[full] = true
                end
            end
            bases = new_bases
        end

        ::continue::
    end

    return bases
end

function M.expand_files(path_specs)
    local expanded = {}
    local seen = {}

    for _, path_spec in ipairs(path_specs or {}) do
        if type(path_spec) == "string" and path_spec ~= "" then
            if not has_wildcard(path_spec) then
                if path_mode(path_spec) == "file" and not seen[path_spec] then
                    expanded[#expanded + 1] = path_spec
                    seen[path_spec] = true
                end
            else
                for _, path in ipairs(expand_glob_path(path_spec)) do
                    if path_mode(path) == "file" and not seen[path] then
                        expanded[#expanded + 1] = path
                        seen[path] = true
                    end
                end
            end
        end
    end

    return expanded
end

return M
