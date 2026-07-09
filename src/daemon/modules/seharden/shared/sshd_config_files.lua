local lfs = require('lfs')
local text = require('seharden.shared.text')

local M = {}

local function strip_comment(line)
    local comment_start = tostring(line or ''):find('#', 1, true)
    if comment_start then
        return line:sub(1, comment_start - 1)
    end
    return line
end

function M.parse_directive(line)
    local active = text.trim(strip_comment(line))
    return active:match('^(%S+)%s+(.+)$')
end

local function path_mode(path, deps)
    local attr = deps.lfs_attributes(path)
    return attr and attr.mode or nil
end

local function path_exists_as_file(path, deps)
    return path_mode(path, deps) == 'file'
end

local function join_path(base, part)
    if base == '.' then
        return part
    elseif base == '/' then
        return '/' .. part
    end
    return base .. '/' .. part
end

local function dirname(path)
    return path:match('^(.*)/[^/]+$') or '.'
end

local function basename(path)
    return path:match('([^/]+)$') or path
end

local function has_wildcard(value)
    return tostring(value or ''):find('[%*%?%[]') ~= nil
end

local function list_matching_paths(base, pattern, deps)
    if path_mode(base, deps) ~= 'directory' then
        return {}
    end

    local entries = {}
    for name in deps.lfs_dir(base) do
        if name ~= '.' and name ~= '..' and name:match(pattern) then
            entries[#entries + 1] = join_path(base, name)
        end
    end

    table.sort(entries)
    return entries
end

local function expand_glob_path(path_glob, deps)
    local is_abs = path_glob:sub(1, 1) == '/'
    local parts = {}
    for part in path_glob:gmatch('[^/]+') do
        parts[#parts + 1] = part
    end

    local bases = { is_abs and '/' or '.' }
    for _, part in ipairs(parts) do
        if part == '.' then
            goto continue
        end

        if part == '..' then
            local parents = {}
            local seen = {}
            for _, base in ipairs(bases) do
                local parent = base == '/' and '/' or dirname(base)
                if not seen[parent] then
                    parents[#parents + 1] = parent
                    seen[parent] = true
                end
            end
            bases = parents
            goto continue
        end

        local next_bases = {}
        local seen = {}
        if has_wildcard(part) then
            local pattern = text.glob_to_pattern(part)
            for _, base in ipairs(bases) do
                for _, full_path in ipairs(list_matching_paths(base, pattern, deps)) do
                    if not seen[full_path] then
                        next_bases[#next_bases + 1] = full_path
                        seen[full_path] = true
                    end
                end
            end
        else
            for _, base in ipairs(bases) do
                local full_path = join_path(base, part)
                if not seen[full_path] then
                    next_bases[#next_bases + 1] = full_path
                    seen[full_path] = true
                end
            end
        end

        bases = next_bases

        ::continue::
    end

    return bases
end

local function normalize_include_path(path, base_dir)
    if path:sub(1, 1) == '/' then
        return path
    end
    return (base_dir or '/etc/ssh') .. '/' .. path
end

local function expand_include_spec(spec, base_dir, deps)
    spec = normalize_include_path(spec, base_dir)
    local paths = {}

    if has_wildcard(spec) then
        for _, path in ipairs(expand_glob_path(spec, deps)) do
            if path_exists_as_file(path, deps) then
                paths[#paths + 1] = path
            end
        end
    elseif path_exists_as_file(spec, deps) then
        paths[#paths + 1] = spec
    end

    table.sort(paths)
    return paths
end

local function discover_include_files(path, base_dir, deps)
    local file = deps.io_open(path, 'r')
    if not file then
        return {}
    end

    local includes = {}
    for line in file:lines() do
        local directive, value = M.parse_directive(line)
        if directive and directive:lower() == 'include' then
            for spec in tostring(value or ''):gmatch('%S+') do
                for _, include_path in ipairs(expand_include_spec(spec, base_dir, deps)) do
                    includes[#includes + 1] = include_path
                end
            end
        end
    end
    file:close()
    return includes
end

local function append_unique(list, seen, path)
    if path and path ~= '' and not seen[path] then
        list[#list + 1] = path
        seen[path] = true
    end
end

function M.discover(params)
    params = params or {}
    local deps = {
        io_open = params.io_open or io.open,
        lfs_attributes = params.lfs_attributes or lfs.attributes,
        lfs_dir = params.lfs_dir or lfs.dir,
    }

    local main_path = params.path or '/etc/ssh/sshd_config'
    local base_dir = params.base_dir or '/etc/ssh'
    local include_dir = params.include_dir or '/etc/ssh/sshd_config.d'
    local queue = {}
    local queued = {}
    local files = {}
    local seen_files = {}

    append_unique(queue, queued, main_path)
    for _, path in ipairs(expand_include_spec(include_dir .. '/*.conf', base_dir, deps)) do
        if dirname(path) == include_dir and basename(path):match('%.conf$') then
            append_unique(queue, queued, path)
        end
    end

    local index = 1
    while index <= #queue do
        local path = queue[index]
        index = index + 1

        if path_exists_as_file(path, deps) then
            append_unique(files, seen_files, path)
            for _, include_path in ipairs(discover_include_files(path, base_dir, deps)) do
                append_unique(queue, queued, include_path)
            end
        end
    end

    if params.sort_result then
        table.sort(files)
    end
    return files
end

return M
