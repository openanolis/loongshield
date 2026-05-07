local lfs = require('lfs')

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

local function path_mode(path)
    return dependencies.lfs_attributes(path, "mode")
end

local function join_path(base, leaf)
    if not leaf or leaf == "" then
        return base
    end
    return base .. "/" .. leaf
end

function M.first_existing_file(base_dirs, filename)
    for _, dir in ipairs(base_dirs or {}) do
        local path = join_path(dir, filename)
        if path_mode(path) == "file" then
            return path
        end
    end
    return nil
end

-- Directories are ordered from highest to lowest precedence. Equal basenames
-- in higher-precedence directories mask lower-precedence files.
function M.sorted_unique_files(base_dirs, relative_dir, name_pattern)
    local selected = {}

    for _, base_dir in ipairs(base_dirs or {}) do
        local scan_dir = join_path(base_dir, relative_dir)
        if path_mode(scan_dir) == "directory" then
            local iter, dir_obj = dependencies.lfs_dir(scan_dir)
            if iter then
                for name in iter, dir_obj do
                    if name ~= "." and name ~= ".."
                        and (name_pattern == nil or name:match(name_pattern))
                        and selected[name] == nil then
                        local path = scan_dir .. "/" .. name
                        if path_mode(path) == "file" then
                            selected[name] = path
                        end
                    end
                end
            end
        end
    end

    local names = {}
    for name, _ in pairs(selected) do
        names[#names + 1] = name
    end
    table.sort(names)

    local files = {}
    for _, name in ipairs(names) do
        files[#files + 1] = selected[name]
    end
    return files
end

return M
