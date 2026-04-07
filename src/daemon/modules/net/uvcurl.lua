#!/usr/bin/env lua

local uv = require('luv')
local curl = require('lcurl.safe')

local function uvcurl_new()
    local m = curl.multi()
    local timer = uv.new_timer()
    local requests = {}
    local fdpoll = {}

    local function check_multi_info()
        while true do
            local easy, ok, err = m:info_read(true)
            if type(easy) == "number" then
                -- TODO: 0 there no informationals
                break
            end

            -- CURLMSG_DONE
            local req = requests[easy]
            local complete = req.delegate.oncomplete
            if complete then
                if ok then
                    local resp = true
                    if req.data then
                        resp = table.concat(req.data)
                    end
                    complete(easy, resp)
                else
                    complete(easy, nil, err)
                end
            end
            requests[easy] = nil
            easy:close()
        end
    end

    local function start_timer(ms)
        if ms <= 0 then
            ms = 1
        end
        timer:start(ms, 0, function()
            m:socket_action(curl.SOCKET_TIMEOUT, 0)
            check_multi_info()
        end)
    end

    local function handle_socket(easy, sockfd, action)
        local poll = fdpoll[sockfd]
        if not poll then
            poll = uv.new_socket_poll(sockfd)
            fdpoll[sockfd] = poll
        end

        local function curl_perform(status, events)
            timer:stop()
            local evt = 0
            if events == "r" then
                evt = curl.CSELECT_IN
            elseif events == "w" then
                evt = curl.CSELECT_OUT
            elseif events == "rw" then
                evt = curl.CSELECT_IN + curl.CSELECT_OUT
            end
            m:socket_action(sockfd, evt)
            check_multi_info()
        end

        if action == curl.POLL_IN then
            poll:start("r", curl_perform)
        elseif action == curl.POLL_OUT then
            poll:start("w", curl_perform)
        elseif action == curl.POLL_REMOVE then
            poll:stop()
            fdpoll[sockfd] = nil
        else
        end
    end

    m:setopt(curl.OPT_MULTI_SOCKETFUNCTION, handle_socket)
    m:setopt_timerfunction(start_timer)

    return function(url, opt, delegate)
        local req = {
            url = url,
            delegate = delegate
        }
        opt = opt or {}

        local easy, err = curl.easy()
        if not easy then
            return nil, err
        end

        if opt.resolve then
            -- 'example.com:80:127.0.0.1'
            local list = { opt.resolve }
            if type(opt.resolve) == 'table' then
                list = opt.resolve
            end
            easy:setopt(curl.OPT_RESOLVE, list)
        end

        if opt.verbose then
            easy:setopt(curl.OPT_VERBOSE, 1)
        end
        --easy:setopt(curl.OPT_HEADER, 1)
        easy:setopt(curl.OPT_TCP_KEEPALIVE, 1)

        easy:setopt_url(url)
        if string.sub(url, 1, 5) == 'https' then
            easy:setopt(curl.OPT_SSL_VERIFYPEER, 0)
            easy:setopt(curl.OPT_SSL_VERIFYHOST, 0)
        end

        if opt.method == 'POST' then
            if type(opt.body) == 'string' then
                easy:setopt_postfields(opt.body)
            else
                easy:setopt_httppost(opt.body)
            end
        end

        if opt.headers and next(opt.headers) then
            easy:setopt(curl.OPT_HTTPHEADER, opt.headers)
        end

        if opt.user_agent then
            easy:setopt(curl.OPT_USERAGENT, opt.user_agent)
        end
        if opt.timeout then
            easy:setopt(curl.OPT_TIMEOUT_MS, opt.timeout)
            easy:setopt(curl.OPT_CONNECTTIMEOUT_MS, opt.timeout)
        end
        if opt.accept_encoding then
            easy:setopt(curl.OPT_ACCEPT_ENCODING, opt.accept_encoding)
        end
        if opt.referrer then
            easy:setopt(curl.OPT_REFERER, opt.referrer)
        end
        if opt.share then
            easy:setopt_share(opt.share)
        end

        easy:setopt(curl.OPT_FOLLOWLOCATION, 1)
        if opt.file then
            easy:setopt_writefunction(opt.file)
        else
            req.data = {}
            easy:setopt_writefunction(function(ud, s)
                table.insert(ud, s)
                return true
            end, req.data)
        end

        m:add_handle(easy)
        requests[easy] = req
    end
end

local uvcurl = uvcurl_new()

local function fetch(url, option)
    local thread = coroutine.running()

    local function oncomplete(easy, resp, err)
        local info = {
            status          = easy:getinfo(curl.INFO_RESPONSE_CODE),
            connectcode     = easy:getinfo(curl.INFO_HTTP_CONNECTCODE),
            errno           = easy:getinfo(curl.INFO_OS_ERRNO),
            cookie          = easy:getinfo(curl.INFO_COOKIELIST),
            time_total      = easy:getinfo(curl.INFO_TOTAL_TIME),
            effective_url   = easy:getinfo(curl.INFO_EFFECTIVE_URL),
            redirect_count  = easy:getinfo(curl.INFO_REDIRECT_COUNT),
            time_namelookup = easy:getinfo(curl.INFO_NAMELOOKUP_TIME),
            speed_download  = easy:getinfo(curl.INFO_SPEED_DOWNLOAD)
        }
        assert(coroutine.resume(thread, resp, info, err))
    end

    uvcurl(url, option, {
        oncomplete = oncomplete
    })
    return coroutine.yield()
end

return {
    fetch = fetch
}
