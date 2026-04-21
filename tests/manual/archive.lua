#!/usr/bin/env luajit

local lfs = require("lfs")
local archive = require("archive")

local sep = string.match(package.config, "[^\n]+")

local function tar_file(aw, file)
    local fd = assert(io.open(file, 'rb'))
    local data = fd:read('*a')
    fd:close()

    local entry = archive.entry({
        pathname = file,
        filetype = 'reg',
        mode = '0644',
        ctime = { 1000, 500 },
        atime = { 2000, 600 },
        mtime = { 3000, 700 },
        size = #data
    })
    aw:header(entry)
    aw:data(data)
end

local function tar_directory(aw, path)
    local total = 0
    for name in lfs.dir(path) do
        if name ~= '.' and name ~= '..' then
            local file = path .. sep .. name
            local attr = lfs.attributes(file)
            assert(type(attr) == 'table')

            if attr.mode == 'directory' then
                print("tar  [d]:", file)
                local entry = archive.entry({
                    pathname = file,
                    filetype = 'dir',
                    mode = '0755'
                })
                entry:ctime(1234500, 1234500)
                entry:atime(1234500, 1234500)
                entry:mtime(1234500, 1234500)
                aw:header(entry)
                local n = tar_directory(aw, file)
                total = total + n
            else
                print("tar     :", file)
                tar_file(aw, file)
                total = total + 1
            end
        end
    end
    return total
end

local function tar(format, filter, ...)
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

    for _, v in ipairs({...}) do
        local attr = lfs.attributes(v)
        assert(type(attr) == 'table')

        if attr.mode == 'directory' then
            local n = tar_directory(aw, v)
            total = total + n
        end
    end

    aw:free()

    local data = table.concat(data)
    return data, total
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

    local ar = archive.read({
        format = 'all',
        filter = 'all',
        reader = datasplit(data, 4096)
    })

    for header in ar:headers() do
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

        local s = string.format("%s %s:%s %d\t%s",
                                header:mode(), header:gname(), header:uname(),
                                header:size(), header:pathname())
        print(s)
    end
end

local file, src = ...

local data, total = tar("gnutar", "xz", src)
local fd = assert(io.open(file, 'w+b'))
fd:write(data)
fd:close()
print("total files: ", total)
print("size: ", #data)

print(string.rep('-', 80))

local fd = assert(io.open(file, 'rb'))
local data = fd:read('*a')
fd:close()

untar(data)
