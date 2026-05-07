local lfs = require('lfs')
local log = require('runtime.log')
local path_list = require('seharden.shared.path_list')
local text = require('seharden.shared.text')

local M = {}

local _default_dependencies = {
    io_open = io.open,
    io_popen = io.popen,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
    path_list._test_set_dependencies({
        lfs_attributes = _dependencies.lfs_attributes,
        lfs_dir = _dependencies.lfs_dir,
    })
end

M._test_set_dependencies()

local BUILTIN_ATTRS = {
    p = true,
    i = true,
    n = true,
    u = true,
    g = true,
    s = true,
    b = true,
    m = true,
    a = true,
    c = true,
    acl = true,
    xattrs = true,
    sha512 = true,
    sha384 = true,
    sha256 = true,
    sha1 = true,
    md5 = true,
    rmd160 = true,
    tiger = true,
    whirlpool = true,
    ftype = true,
    selinux = true,
}

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function strip_inline_comment(line)
    local in_single_quote = false
    local in_double_quote = false

    for index = 1, #line do
        local char = line:sub(index, index)
        if char == "'" and not in_double_quote then
            in_single_quote = not in_single_quote
        elseif char == '"' and not in_single_quote then
            in_double_quote = not in_double_quote
        elseif char == "#" and not in_single_quote and not in_double_quote then
            local previous = index > 1 and line:sub(index - 1, index - 1) or nil
            if previous == nil or previous:match("%s") then
                return line:sub(1, index - 1)
            end
        end
    end

    return line
end

local function sorted_files(paths)
    local files = path_list.expand_files(paths)
    table.sort(files)
    return files
end

local function dirname(path)
    return tostring(path):match("^(.*)/[^/]+$") or "."
end

local function join_path(base, part)
    if tostring(part):sub(1, 1) == "/" then
        return part
    end
    if base == "/" then
        return "/" .. part
    end
    return tostring(base):gsub("/$", "") .. "/" .. tostring(part)
end

local function path_mode(path)
    local attr = _dependencies.lfs_attributes(path)
    return attr and attr.mode or nil
end

local function sorted_directory_files(path, name_pattern)
    local files = {}
    if path_mode(path) ~= "directory" then
        return files
    end

    local ok, iter, dir_obj = pcall(_dependencies.lfs_dir, path)
    if not ok or not iter then
        return nil, tostring(iter or dir_obj)
    end

    local names = {}
    for name in iter, dir_obj do
        if name ~= "." and name ~= ".." and (not name_pattern or name:match(name_pattern)) then
            names[#names + 1] = name
        end
    end
    table.sort(names)

    for _, name in ipairs(names) do
        local child = path .. "/" .. name
        if path_mode(child) == "file" then
            files[#files + 1] = child
        end
    end
    return files
end

local function normalize_include_args(line)
    local args = {}
    for value in tostring(line or ""):gmatch("%S+") do
        args[#args + 1] = value:gsub('^"', ''):gsub('"$', '')
    end
    return args
end

local function add_include_files(files, seen, current_path, include_args)
    if #include_args == 0 then
        return true
    end

    local include_path = join_path(dirname(current_path), include_args[1])
    local mode = path_mode(include_path)
    local candidates

    if include_path:find("[%*%?%[]") then
        candidates = sorted_files({ include_path })
    elseif mode == "directory" then
        candidates = sorted_directory_files(include_path, include_args[2])
        if not candidates then
            return nil, "Could not enumerate AIDE include directory '" .. include_path .. "'"
        end
    elseif mode == "file" then
        candidates = { include_path }
    else
        candidates = {}
    end

    for _, path in ipairs(candidates) do
        if not seen[path] then
            files[#files + 1] = path
            seen[path] = true
        end
    end
    return true
end

local function parse_config_files(initial_paths)
    local files = sorted_files(initial_paths)
    local seen = {}
    for _, path in ipairs(files) do
        seen[path] = true
    end

    local aliases = {}
    local rules = {}
    local index = 1

    while index <= #files do
        local path = files[index]
        local file, err = _dependencies.io_open(path, "r")
        if not file then
            log.warn("Could not open AIDE config '%s': %s", path, tostring(err))
            return nil, string.format("Could not open AIDE config '%s': %s", path, tostring(err))
        end

        for line in file:lines() do
            local trimmed = text.trim(strip_inline_comment(line))
            if trimmed ~= "" then
                local directive, rest = trimmed:match("^(@@[%w_]+)%s*(.*)$")
                if directive == "@@include" or directive == "@@x_include" then
                    local ok, include_err = add_include_files(files, seen, path, normalize_include_args(rest))
                    if not ok then
                        file:close()
                        return nil, include_err
                    end
                elseif not trimmed:match("^[!%-]") then
                    local alias, expr = trimmed:match("^([%w_]+)%s*=%s*(.+)$")
                    if alias then
                        aliases[alias] = text.trim(expr)
                    else
                        local selector, rule_expr = trimmed:match("^([^%s]+)%s+(.+)$")
                        if selector and rule_expr then
                            selector = selector:gsub("^=", ""):gsub("^%^", "")
                            rules[#rules + 1] = {
                                path_pattern = selector,
                                expr = text.trim(rule_expr),
                                source = path,
                            }
                        end
                    end
                end
            end
        end
        file:close()
        index = index + 1
    end

    return {
        aliases = aliases,
        files = files,
        rules = rules,
    }
end

local function split_attr_expr(expr)
    local items = {}
    local current_operator = "+"

    for op, token in tostring(expr or ""):gmatch("([+%-]?)([^+%-]+)") do
        token = text.trim(token)
        if token ~= "" then
            if op ~= "" then
                current_operator = op
            end
            items[#items + 1] = {
                op = current_operator,
                token = token,
            }
        end
    end

    return items
end

local function add_attrs_from_expr(expr, aliases, attrs, stack)
    stack = stack or {}
    for _, item in ipairs(split_attr_expr(expr)) do
        local token = item.token
        local expanded = nil

        if aliases[token] and not stack[token] then
            stack[token] = true
            expanded = {}
            add_attrs_from_expr(aliases[token], aliases, expanded, stack)
            stack[token] = nil
        elseif BUILTIN_ATTRS[token] then
            expanded = { [token] = true }
        end

        if expanded then
            for attr, _ in pairs(expanded) do
                if item.op == "-" then
                    attrs[attr] = nil
                else
                    attrs[attr] = true
                end
            end
        end
    end
end

local function resolved_attrs(expr, aliases)
    local attrs = {}
    add_attrs_from_expr(expr, aliases, attrs, {})
    return attrs
end

local function selector_matches_path(selector, path)
    if selector == path then
        return true
    end

    local ok, matched = pcall(function()
        return path:match(selector) ~= nil
    end)
    return ok and matched
end

local function missing_required_attrs(actual_attrs, required_attrs)
    local missing = {}
    for _, attr in ipairs(required_attrs or {}) do
        if not actual_attrs[attr] then
            missing[#missing + 1] = attr
        end
    end
    return missing
end

local function readlink_f(path)
    local mode = path_mode(path)
    if mode ~= "file" then
        return nil
    end

    local pipe = _dependencies.io_popen("readlink -f -- " .. shell_escape(path) .. " 2>/dev/null", "r")
    if not pipe then
        return path
    end
    local resolved = pipe:read("*l")
    pipe:close()
    if resolved and resolved ~= "" then
        return resolved
    end
    return path
end

local function resolve_required_paths(params)
    local paths = {}
    if type(params.required_paths) == "table" then
        for _, path in ipairs(params.required_paths) do
            paths[#paths + 1] = tostring(path)
        end
    end

    for _, tool in ipairs(params.required_tools or {}) do
        local candidates = {
            "/sbin/" .. tostring(tool),
            "/usr/sbin/" .. tostring(tool),
        }
        local resolved
        for _, candidate in ipairs(candidates) do
            resolved = readlink_f(candidate)
            if resolved then
                break
            end
        end
        if resolved then
            paths[#paths + 1] = resolved
        end
    end

    table.sort(paths)
    local deduped = {}
    local seen = {}
    for _, path in ipairs(paths) do
        if not seen[path] then
            deduped[#deduped + 1] = path
            seen[path] = true
        end
    end
    return deduped
end

function M.inspect_required_file_rules(params)
    params = params or {}
    local config_paths = params.config_paths or { "/etc/aide.conf", "/etc/aide.conf.d/*" }
    local required_attrs = params.required_attrs or {}
    local parsed, parse_err = parse_config_files(config_paths)

    if not parsed then
        return {
            available = false,
            error = parse_err,
            checked_count = 0,
            required_count = 0,
            compliant_count = 0,
            violation_count = 0,
            all_configured = false,
            details = {},
        }
    end

    if #parsed.files == 0 then
        return {
            available = false,
            error = "No AIDE configuration files were available.",
            checked_count = 0,
            required_count = 0,
            compliant_count = 0,
            violation_count = 0,
            all_configured = false,
            details = {},
        }
    end

    local required_paths = resolve_required_paths(params)
    local details = {}
    local compliant_count = 0
    local violation_count = 0

    for _, required_path in ipairs(required_paths) do
        local best
        for _, rule in ipairs(parsed.rules) do
            if selector_matches_path(rule.path_pattern, required_path) then
                local attrs = resolved_attrs(rule.expr, parsed.aliases)
                local missing = missing_required_attrs(attrs, required_attrs)
                if not best or #missing < #best.missing_attrs then
                    best = {
                        path = required_path,
                        configured = #missing == 0,
                        source = rule.source,
                        expr = rule.expr,
                        missing_attrs = missing,
                    }
                end
            end
        end

        if not best then
            best = {
                path = required_path,
                configured = false,
                missing_attrs = required_attrs,
            }
        end

        details[#details + 1] = best
        if best.configured then
            compliant_count = compliant_count + 1
        else
            violation_count = violation_count + 1
        end
    end

    return {
        available = true,
        checked_count = #parsed.files,
        required_count = #required_paths,
        compliant_count = compliant_count,
        violation_count = violation_count,
        all_configured = violation_count == 0,
        details = details,
    }
end

return M
