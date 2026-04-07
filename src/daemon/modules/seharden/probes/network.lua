local log = require('runtime.log')

local M = {}

local _client = nil

local function load_nm()
    local ok, nm = pcall(require, 'nm')
    if not ok then
        return nil, tostring(nm)
    end

    return nm
end

local _default_dependencies = {
    client_new = function()
        local nm, err = load_nm()
        if not nm then
            return nil, err
        end
        return nm.client_new()
    end,
    io_popen = io.popen,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.client_new = deps.client_new or _default_dependencies.client_new
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
    _client = nil
end

M._test_set_dependencies()

local function _get_client()
    if _client then
        return _client
    end

    log.debug("Connecting to NetworkManager for the first time...")
    local client, err = _dependencies.client_new()
    if not client then
        log.error("Could not connect to NetworkManager: %s", tostring(err))
        return nil
    end

    _client = client
    return _client
end

function M.get_all_interface_ips()
    local client = _get_client()
    if not client then
        return nil
    end

    local interfaces = {}
    for device in client:get_devices() do
        local iface = device:get_iface()
        local ip = device:get_ip4_address()
        if iface and ip then
            interfaces[iface] = ip
        end
    end

    return interfaces
end

function M.get_wireless_radio_states()
    local client = _get_client()
    if not client then
        return { wifi_enabled = false, wwan_enabled = false }
    end

    local states = {
        wifi_enabled = client:wireless_enabled(),
        wwan_enabled = client:wwan_enabled()
    }

    return states
end

function M.find_listening_ports(params)
    if not params or type(params.ports) ~= "table" or #params.ports == 0 then
        return nil, "Probe 'network.find_listening_ports' requires a non-empty 'ports' list."
    end

    local wanted_ports = {}
    for i, port in ipairs(params.ports) do
        local num = tonumber(port)
        if not num or num < 1 or num > 65535 then
            return nil, string.format("Probe 'network.find_listening_ports' requires valid port numbers in ports[%d].", i)
        end
        wanted_ports[tostring(num)] = true
    end

    local handle = _dependencies.io_popen("ss -lntuH 2>/dev/null", "r")
    if not handle then
        return nil, "Failed to execute ss command."
    end

    local details = {}
    for line in handle:lines() do
        local fields = {}
        for token in line:gmatch("%S+") do
            fields[#fields + 1] = token
        end

        if #fields >= 5 then
            local proto = fields[1]
            local local_address = fields[5]
            local port = local_address and local_address:match(":([0-9]+)$")

            if port and wanted_ports[port] then
                details[#details + 1] = {
                    proto = proto,
                    local_address = local_address,
                    port = tonumber(port)
                }
            end
        end
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil, string.format("ss command failed with exit code: %s", tostring(code))
    end

    return {
        count = #details,
        details = details
    }
end

function M.disconnect()
    if _client then
        log.debug("Closing shared NetworkManager client.")
        _client:close()
        _client = nil
    end
end

return M
