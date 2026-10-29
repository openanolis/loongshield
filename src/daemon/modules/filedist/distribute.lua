local M = {}

local cjson = require('cjson.safe')
local lfs = require('lfs')
local luv = require('luv')
local uvcurl = require('net.uvcurl')

local function url_decode(value)
    return (value:gsub('%%(%x%x)', function(hex)
        return string.char(tonumber(hex, 16))
    end))
end

--- A safe, relative, server-controlled path: no absolute paths, no `..`
--- components, no backslash, no NUL, no empty or duplicate separators.
function M.is_safe_name(name)
    if type(name) ~= 'string' or name == '' then
        return false
    end
    if name:find('\\', 1, true) or name:find('\0', 1, true) then
        return false
    end
    if name:sub(1, 1) == '/' or name:sub(-1) == '/' then
        return false
    end
    if name:find('//', 1, true) then
        return false
    end

    for segment in name:gmatch('[^/]+') do
        if segment == '.' or segment == '..' then
            return false
        end
        if segment:find('%c') then
            return false
        end
    end
    return true
end

local function allowed_file(name, opts)
    local file_filter = opts and opts.file_filter
    if type(file_filter) ~= 'function' then
        return false
    end
    return file_filter(name) == true
end

--- Reject symlinks: `lfs.attributes` follows them, so use
--- `symlinkattributes` to classify every entry first.
local function entry_mode(path)
    local link_mode = lfs.symlinkattributes(path, 'mode')
    if link_mode == 'link' then
        return 'link'
    end
    return lfs.attributes(path, 'mode')
end

function M.list_files(dir, opts)
    local files = {}

    local function walk(path, prefix)
        for entry in lfs.dir(path) do
            if entry ~= '.' and entry ~= '..' then
                local full = path .. '/' .. entry
                local relative = prefix .. entry
                local mode = entry_mode(full)
                if mode == 'directory' then
                    walk(full, relative .. '/')
                elseif mode == 'file' and allowed_file(relative, opts) then
                    files[#files + 1] = {
                        name = relative,
                        size = lfs.attributes(full, 'size') or 0,
                    }
                end
            end
        end
    end

    walk(dir, '')
    table.sort(files, function(a, b)
        return a.name < b.name
    end)
    return files
end

local function respond(client, status, reason, body, content_type)
    local header = string.format(
        'HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n',
        status,
        reason,
        content_type,
        #body
    )
    client:write(header .. body, function()
        client:close()
    end)
end

--- Serve a directory over plain HTTP. GET / returns the file index as JSON;
--- GET /<name> returns one file selected by the caller's filter. Symlinks are
--- rejected. Runs until stopped.
function M.serve(opts)
    opts = opts or {}
    local dir = opts.dir
    local port = tonumber(opts.port) or 8080
    local host = opts.host or '0.0.0.0'

    if type(dir) ~= 'string' or dir == '' then
        return nil, 'server requires --dir <file-directory>'
    end
    if lfs.attributes(dir, 'mode') ~= 'directory' then
        return nil, 'file directory not found: ' .. dir
    end

    local server = luv.new_tcp()
    local ok, bind_err = server:bind(host, port)
    if not ok then
        return nil, 'failed to bind ' .. host .. ':' .. tostring(port) .. ': ' .. tostring(bind_err)
    end

    server:listen(128, function(listen_err)
        if listen_err then
            return
        end

        local client = luv.new_tcp()
        server:accept(client)
        client:read_start(function(read_err, chunk)
            if read_err or chunk == nil then
                client:close()
                return
            end

            client:read_stop()
            local path = tostring(chunk):match('^GET%s+(%S+)%s+HTTP')
            if not path then
                respond(client, 400, 'Bad Request', 'only HTTP GET is supported\n', 'text/plain')
                return
            end

            path = url_decode(path:match('^([^?]*)'))
            if path == '/' then
                local index = cjson.encode({ files = M.list_files(dir, opts) })
                respond(client, 200, 'OK', index, 'application/json')
                return
            end

            local name = path:sub(2)
            if not M.is_safe_name(name) then
                respond(client, 400, 'Bad Request', 'path traversal rejected\n', 'text/plain')
                return
            end
            if not allowed_file(name, opts) then
                respond(client, 404, 'Not Found', 'not a distributable file: ' .. name .. '\n', 'text/plain')
                return
            end

            local full = dir .. '/' .. name
            if entry_mode(full) ~= 'file' then
                respond(client, 404, 'Not Found', 'not found: ' .. name .. '\n', 'text/plain')
                return
            end

            local file = io.open(full, 'rb')
            if not file then
                respond(client, 500, 'Internal Server Error', 'failed to open: ' .. name .. '\n', 'text/plain')
                return
            end

            local body = file:read('*a') or ''
            file:close()
            respond(client, 200, 'OK', body, 'application/octet-stream')
        end)
    end)

    if opts.on_ready then
        opts.on_ready(host, port, dir)
    end

    luv.run()
    return 0
end

local function mkdir_p(path)
    local created = {}
    for segment in path:gmatch('[^/]+') do
        created[#created + 1] = segment
        local current = '/' .. table.concat(created, '/')
        if lfs.attributes(current, 'mode') == nil then
            local ok, err = lfs.mkdir(current)
            if not ok then
                return nil, tostring(err)
            end
        end
    end
    return true
end

local function normalize_dir(path)
    if path:sub(1, 1) ~= '/' then
        path = lfs.currentdir() .. '/' .. path
    end

    local parts = {}
    for segment in path:gmatch('[^/]+') do
        if segment == '.' then
            -- skip
        elseif segment == '..' then
            table.remove(parts)
        else
            parts[#parts + 1] = segment
        end
    end
    return '/' .. table.concat(parts, '/')
end

local function write_downloaded(path, body)
    local parent = path:match('^(.*)/[^/]+$')
    if parent and parent ~= '' then
        local ok, err = mkdir_p(parent)
        if not ok then
            return nil, 'failed to create directory ' .. parent .. ': ' .. tostring(err)
        end
    end

    local file, err = io.open(path, 'wb')
    if not file then
        return nil, tostring(err)
    end

    local ok, write_err = file:write(body)
    file:close()
    if not ok then
        return nil, tostring(write_err)
    end
    return true
end

local function http_get(url)
    local body, info = uvcurl.fetch(url)
    if not body then
        return nil, 'request failed: ' .. tostring(info and info.errno or 'unknown error')
    end
    if info.status ~= 200 then
        return nil, 'HTTP ' .. tostring(info.status) .. ' for ' .. url
    end
    return body
end

--- Validate a server-provided file index before anything is fetched or
--- written. Every entry must be a safe relative path and unique.
function M.validate_index(index, opts)
    if type(index) ~= 'table' or type(index.files) ~= 'table' then
        return nil, 'invalid file index: files must be a list'
    end

    local count = 0
    while index.files[count + 1] ~= nil do
        count = count + 1
    end

    for key in pairs(index.files) do
        if type(key) ~= 'number' or key < 1 or key > count or key % 1 ~= 0 then
            return nil, 'invalid file index: files must be a list'
        end
    end

    if count == 0 then
        return nil, 'invalid file index: empty file list'
    end

    local seen = {}
    for i = 1, count do
        local file = index.files[i]
        if type(file) ~= 'table' or not M.is_safe_name(file.name) then
            return nil, 'invalid file index entry ' .. i .. ': unsafe file name'
        end
        if not allowed_file(file.name, opts) then
            return nil, 'invalid file index entry ' .. i .. ': not a distributable file'
        end
        if seen[file.name] then
            return nil, 'invalid file index: duplicate file name ' .. file.name
        end
        seen[file.name] = true
    end

    return count
end

--- Pull one file, or a whole file directory when the URL ends with '/'.
--- Must run inside a coroutine with the libuv loop running.
function M.pull(url, opts)
    opts = opts or {}
    local output_dir = normalize_dir(opts.output_dir or '/var/lib/loongshield/filedist')

    if url:sub(-1) == '/' then
        local index_body, index_err = http_get(url)
        if not index_body then
            return nil, index_err
        end

        local decoded, decode_err = cjson.decode(index_body)
        if not decoded then
            return nil, 'invalid file index from ' .. url .. ': ' .. tostring(decode_err)
        end

        local count, validate_err = M.validate_index(decoded, opts)
        if not count then
            return nil, validate_err
        end

        for i = 1, count do
            local file = decoded.files[i]
            local body, fetch_err = http_get(url .. file.name)
            if not body then
                return nil, fetch_err
            end

            local ok, write_err = write_downloaded(output_dir .. '/' .. file.name, body)
            if not ok then
                return nil, write_err
            end
        end

        return count
    end

    local name = url:match('([^/?#]+)$')
    if not M.is_safe_name(name) then
        return nil, 'unsafe file name in pull URL: ' .. tostring(name)
    end
    if not allowed_file(name, opts) then
        return nil, 'not a distributable file: ' .. name
    end

    local body, fetch_err = http_get(url)
    if not body then
        return nil, fetch_err
    end

    local ok, write_err = write_downloaded(output_dir .. '/' .. name, body)
    if not ok then
        return nil, write_err
    end
    return 1
end

return M
