#!/usr/bin/env luajit

local lfs = require("lfs")
local archive = require("archive")

local sep = string.match(package.config, "[^\n]+")


local function luac(data, name)
    local chunk, err = loadstring(data, name)
    if not chunk then
        error('luac: ' .. err)
    end
    -- TODO: don't strip it for LuaJIT
    return string.dump(chunk, false)
end


local function strip_pathname(path, level)
    if not level or level == 0 then
        return path
    end
    while level > 0 do
        -- remove the first path dentry
        path = string.match(path, '.-/(.+)$')
        level = level - 1
    end
    -- strip '.lua' extension
    local name = string.match(path, '(.+)%.lua$')
    return name or path
end


local function tar_file(aw, file, level)
    local fd = assert(io.open(file, 'rb'))
    local data = fd:read('*a')
    fd:close()

    -- end with '.lua', compile it by luac
    local name = string.match(file, '(.+%.lua)$')
    if name then
        data = luac(data, name)
    end

    local pathname = strip_pathname(file, level)
    local entry = archive.entry({
        pathname = pathname,
        filetype = 'reg',
        perm = '0644',
        ctime = { 1704067200, 0 }, -- 2024.1.1
        atime = { 1704067200, 0 },
        mtime = { 1704067200, 0 },
        size = #data
    })
    aw:header(entry)
    aw:data(data)
    -- print(string.format("tar [%5d]: %s --> %s", #data, file, pathname))
end


local function tar_directory(aw, path, level)
    local total = 0
    for name in lfs.dir(path) do
        if name ~= '.' and name ~= '..' then
            local file = path .. sep .. name
            local attr = lfs.attributes(file)
            assert(type(attr) == 'table')

            if attr.mode == 'directory' then
                local pathname = strip_pathname(file, level)
                local entry = archive.entry({
                    pathname = pathname,
                    filetype = 'dir',
                    perm = '0755',
                    size = 0
                })
                entry:ctime(1704067200, 0)
                entry:atime(1704067200, 0)
                entry:mtime(1704067200, 0)
                aw:header(entry)
                -- print(string.format("tar       *: %s --> %s", file, pathname))
                local n = tar_directory(aw, file, level)
                total = total + n
            else
                tar_file(aw, file, level)
                total = total + 1
            end
        end
    end
    return total
end


local function tar(format, filter, dirs)
    local data = {}
    local total = 0

    local aw = archive.write({
        writer = function(aw, buffer)
            if not buffer then
                return
            end
            data[#data + 1] = buffer
            return #buffer
        end,
        format = format,
        filter = filter,
        bytes_in_last_block = 1,
        bytes_per_block = 100
    })

    for _, v in ipairs(dirs) do
        local attr = lfs.attributes(v.path)
        assert(type(attr) == 'table')

        if attr.mode == 'directory' then
            local n = tar_directory(aw, v.path, v.level)
            total = total + n
        else
            tar_file(aw, v.path, v.level)
            total = total + 1
        end
    end

    aw:free()

    if not next(data) then
        return nil, 'no more file'
    end
    local data = table.concat(data)
    return data, total
end


local function rootfs_dump(t, level)
    level = level or 0
    for k, v in pairs(t) do
        if type(v) == 'table' then
            local s = string.format('  %s%s',
                string.rep(' ', level * 2), k)
            -- print(s)
            rootfs_dump(v, level + 1)
        else
            local s = string.format('  %s%s  [%5d]',
                string.rep(' ', level * 2), k, #v)
            -- print(s)
        end
    end
end


local function untar(data)
    local function datasplit(data, length)
        local pos = 1
        return function(ar)
            local sub = string.sub(data, pos, pos + length - 1)
            if sub then
                pos = pos + #sub
                return sub
            end
        end
    end

    local function mkrootfs(rootfs, ar, header)
        local content = {}
        while true do
            local d, offset = ar:data()
            if not d then
                break
            end
            content[#content + 1] = d
        end
        local content = table.concat(content)
        assert(header:size() == string.len(content))

        local dir = rootfs
        local node = rootfs
        local name
        for s in string.gmatch(header:pathname(), '([^/\\]+)') do
            -- just simple ignore '.' and '..'
            if s ~= '.' and s ~= '..' then
                if not node[s] then
                    node[s] = {}
                end
                dir = node
                node = node[s]
                name = s
            end
        end
        if name then
            dir[name] = content
        end
    end

    local ar = archive.read({
        format = 'all',
        filter = 'all',
        reader = datasplit(data, 4096)
    })

    local rootfs = {}
    for header in ar:headers() do
        -- print('untar: ', header:pathname(), header:size())

        if header:filetype() == 'reg' then
            mkrootfs(rootfs, ar, header)
        end
    end
    rootfs_dump(rootfs)
    return rootfs
end

---------------------------------- mkinitrd -----------------------------------

local function xxd(data, fd, row)
    fd = fd or io.stdout
    row = row or 8
    fd:write(" ")
    for i = 1, string.len(data) do
        local c = string.byte(data, i)
        fd:write(string.format(" 0x%02x", c))
        if i == string.len(data) then
            break
        end
        fd:write(",")
        if i % row == 0 then
            fd:write("\n ")
        end
    end
end


local function mkinitrd(file, dirs)
    local data, total = tar('cpio', 'xz', dirs)
    if not data then
        error('mkinitrd: ' .. total)
    end

    local fd = assert(io.open(file, 'w+b'))
    xxd(data, fd)
    fd:close()

    local s = string.format('mkinitrd: size: %d KB, %d total files',
        #data / 1024, total)
    print(s)
    return true
end

local function mkramfs(file_ramfs, file_header)
    local fd = assert(io.open(file_ramfs, 'rb'))
    local data = fd:read('*a')
    fd:close()

    local name = string.match(file_ramfs, '(.+%.lua)$')
    data = luac(data, name or 'ramfs.lua')

    local fd = assert(io.open(file_header, 'w+b'))
    xxd(data, fd)
    fd:close()
    return true
end

--------------------------------- vfs runtime ---------------------------------

local function vfsread(vfs, path)
    local node = vfs
    for component in string.gmatch(path, '([^/\\]+)') do
        if type(node) ~= 'table' then return nil end
        node = node[component]
    end
    return node
end


local function vfsexec(chunk, path, ...)
    if type(chunk) ~= 'string' then
        error("VFS error: path '" .. path .. "' is a directory, not a file.", 2)
    end

    local func, err = load(chunk, "@" .. path)
    if not func then
        error(err, 2)
    end
    return func(...)
end


local function vfsrequire(vfs, path)
    path = path:gsub('%.', '/')

    if package.loaded[path] then
        return package.loaded[path]
    end

    local chunk = vfsread(vfs, path)
    if type(chunk) == 'string' then
        local result = vfsexec(chunk, path)
        package.loaded[path] = result or true
        return package.loaded[path]
    end

    local init_path = path .. '/init'
    chunk = vfsread(vfs, init_path)
    if type(chunk) == 'string' then
        local result = vfsexec(chunk, init_path)
        package.loaded[path] = result or true
        return package.loaded[path]
    end

    return nil
end

local function vfsinit(initrd, pathname, argv, envp)
    local vfsroot = untar(initrd)
    if not vfsroot or not next(vfsroot) then
        return nil, 'empty initrd'
    end

    local pure_require = require

    require = function(name)
        local result = vfsrequire(vfsroot, name)
        if result ~= nil then
            return result
        end

        return pure_require(name)
    end

    if pathname then
        local chunk = vfsread(vfsroot, pathname)
        if not chunk then
            error("VFS error: main script '" .. pathname .. "' not found.")
        end
        return vfsexec(chunk, pathname, argv, envp)
    end

    return true
end


return {
    -- for build
    mkinitrd = mkinitrd,
    mkramfs = mkramfs,

    -- for runtime
    init = vfsinit
}
