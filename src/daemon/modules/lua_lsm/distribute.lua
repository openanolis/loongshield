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

local function list_files(dir)
    local files = {}

    local function walk(path, prefix)
        for entry in lfs.dir(path) do
            if entry ~= '.' and entry ~= '..' then
                local full = path .. '/' .. entry
                local relative = prefix .. entry
                local mode = lfs.attributes(full, 'mode')
                if mode == 'directory' then
                    walk(full, relative .. '/')
                elseif mode == 'file' then
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

--- Serve a policy directory over plain HTTP. GET / returns the file index as
--- JSON; GET /<name> returns one file. Runs until the process is stopped.
function M.serve(opts)
    opts = opts or {}
    local dir = opts.dir
    local port = tonumber(opts.port) or 8080
    local host = opts.host or '0.0.0.0'

    if type(dir) ~= 'string' or dir == '' then
        return nil, 'server requires --dir <policy-directory>'
    end
    if lfs.attributes(dir, 'mode') ~= 'directory' then
        return nil, 'policy directory not found: ' .. dir
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
                local index = cjson.encode({ files = list_files(dir) })
                respond(client, 200, 'OK', index, 'application/json')
                return
            end

            local name = path:sub(2)
            if name == '' or name:find('%.%.') or name:find('\\') then
                respond(client, 400, 'Bad Request', 'path traversal rejected\n', 'text/plain')
                return
            end
            if name:match('%.key$') then
                respond(client, 403, 'Forbidden', 'refusing to serve private key: ' .. name .. '\n', 'text/plain')
                return
            end

            local full = dir .. '/' .. name
            if lfs.attributes(full, 'mode') ~= 'file' then
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

--- Pull one file, or a whole policy directory when the URL ends with '/'.
--- Must run inside a coroutine with the libuv loop running.
function M.pull(url, opts)
    opts = opts or {}
    local output_dir = opts.output_dir or '/etc/loongshield/lua-lsm'

    if url:sub(-1) == '/' then
        local index_body, index_err = http_get(url)
        if not index_body then
            return nil, index_err
        end

        local decoded, decode_err = cjson.decode(index_body)
        if not decoded or type(decoded.files) ~= 'table' then
            return nil, 'invalid policy index from ' .. url .. ': ' .. tostring(decode_err)
        end

        for _, file in ipairs(decoded.files) do
            local body, fetch_err = http_get(url .. file.name)
            if not body then
                return nil, fetch_err
            end

            local ok, write_err = write_downloaded(output_dir .. '/' .. file.name, body)
            if not ok then
                return nil, write_err
            end
        end

        return #decoded.files
    end

    local body, fetch_err = http_get(url)
    if not body then
        return nil, fetch_err
    end

    local name = url:match('([^/?#]+)$')
    local ok, write_err = write_downloaded(output_dir .. '/' .. name, body)
    if not ok then
        return nil, write_err
    end
    return 1
end

return M
