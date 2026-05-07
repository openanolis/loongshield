local log = require('runtime.log')
local lfs = require('lfs')

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
    kmod_get_disable_state = function(params)
        return require('seharden.probes.kmod').get_disable_state(params)
    end,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.client_new = deps.client_new or _default_dependencies.client_new
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
    _dependencies.kmod_get_disable_state = deps.kmod_get_disable_state or _default_dependencies.kmod_get_disable_state
    _dependencies.lfs_attributes = deps.lfs_attributes or _default_dependencies.lfs_attributes
    _dependencies.lfs_dir = deps.lfs_dir or _default_dependencies.lfs_dir
    _client = nil
end

M._test_set_dependencies()

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function path_mode(path)
    local attr = _dependencies.lfs_attributes(path)
    return attr and attr.mode or nil
end

local function sorted_dir_entries(path)
    local entries = {}
    local ok, iter, dir_obj = pcall(_dependencies.lfs_dir, path)
    if not ok then
        return nil, tostring(iter)
    end
    if not iter then
        return nil, tostring(dir_obj or "directory unavailable")
    end

    for name in iter, dir_obj do
        if name ~= "." and name ~= ".." then
            entries[#entries + 1] = name
        end
    end
    table.sort(entries)
    return entries
end

local function trim(value)
    return tostring(value or ""):match("^%s*(.-)%s*$")
end

local function run_command_lines(cmd)
    local handle = _dependencies.io_popen(cmd, "r")
    if not handle then
        return nil, "Failed to execute command."
    end

    local lines = {}
    for line in handle:lines() do
        lines[#lines + 1] = line
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil, string.format("command failed with exit code: %s", tostring(code))
    end

    return lines
end

local function parse_local_port(local_address)
    if not local_address then
        return nil
    end
    if local_address:sub(-1) == "*" then
        return nil
    end
    return local_address:match(":([0-9]+)$")
end

local function local_address_host(local_address, port)
    local suffix = ":" .. tostring(port)
    local host = tostring(local_address or "")
    if host:sub(-#suffix) == suffix then
        host = host:sub(1, #host - #suffix)
    end
    return host:gsub("^%[", ""):gsub("%]$", "")
end

local function is_loopback_host(host)
    host = tostring(host or ""):lower()
    return host == "localhost"
        or host == "::1"
        or host == "0:0:0:0:0:0:0:1"
        or host:match("^127%.") ~= nil
end

local function mta_config_is_local_only(output)
    output = trim(output):lower()
    if output == "" then
        return true
    end

    local checked = 0
    for line in output:gmatch("[^\n]+") do
        local value = line:match("=%s*(.+)$") or line
        value = value:gsub("addr%s*=", "")
            :gsub("[\"']", "")
            :gsub("<", " ")

        for token in value:gmatch("[^,;%s]+") do
            token = trim(token):lower()
            if token ~= "" then
                checked = checked + 1
                if token == "all"
                    or token == "0.0.0.0"
                    or token == "::"
                    or token == "*"
                    or not is_loopback_host(token)
                        and token ~= "loopback-only" then
                    return false
                end
            end
        end
    end

    return checked > 0
end

local function read_mta_configs()
    local commands = {
        { name = "postfix", cmd = "postconf -n inet_interfaces 2>/dev/null" },
        { name = "exim", cmd = "exim -bP local_interfaces 2>/dev/null" },
        {
            name = "sendmail",
            cmd = "grep -i 'O DaemonPortOptions=' /etc/mail/sendmail.cf 2>/dev/null | grep -o 'Addr=[^,]*'",
        },
    }

    local command_errors = {}
    local configs = {}
    for _, command in ipairs(commands) do
        local lines = run_command_lines(command.cmd)
        if lines and #lines > 0 then
            local output = table.concat(lines, "\n")
            configs[#configs + 1] = {
                detected = true,
                source = command.name,
                output = output,
                local_only = mta_config_is_local_only(output),
            }
        end
        if not lines then
            command_errors[#command_errors + 1] = command.name
        end
    end

    return {
        detected = #configs > 0,
        configs = configs,
        command_errors = command_errors,
    }
end

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
        return {
            available = false,
            error = "Failed to execute ss command.",
            details = {}
        }
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
        return {
            available = false,
            error = string.format("ss command failed with exit code: %s", tostring(code)),
            details = {}
        }
    end

    return {
        available = true,
        count = #details,
        details = details
    }
end

function M.inspect_mta_local_only(params)
    params = params or {}
    local ports = params.ports or { 25, 465, 587 }
    local listening, err = M.find_listening_ports({ ports = ports })
    if not listening then
        return nil, err
    end

    if listening.available == false then
        return {
            available = false,
            local_only = false,
            error = listening.error,
            non_loopback_count = nil,
            details = {},
        }
    end

    local non_loopback = {}
    for _, detail in ipairs(listening.details or {}) do
        local port = detail.port or parse_local_port(detail.local_address)
        local host = local_address_host(detail.local_address, port)
        detail.host = host
        detail.loopback = is_loopback_host(host)
        if not detail.loopback then
            non_loopback[#non_loopback + 1] = detail
        end
    end

    local config = read_mta_configs()
    local config_local_only = true
    for _, config_detail in ipairs(config.configs or {}) do
        if config_detail.local_only ~= true then
            config_local_only = false
            break
        end
    end

    return {
        available = true,
        local_only = #non_loopback == 0 and config_local_only,
        non_loopback_count = #non_loopback,
        non_loopback_details = non_loopback,
        config_detected = config.detected,
        config_local_only = config_local_only,
        config_details = config.configs or {},
        command_errors = config.command_errors or {},
        details = listening.details or {},
    }
end

local function readlink_basename(path)
    local lines = run_command_lines("readlink -f " .. shell_escape(path) .. " 2>/dev/null")
    if not lines or #lines == 0 then
        return nil
    end
    return trim(lines[1]):match("([^/]+)$")
end

function M.inspect_wireless_modules(params)
    params = params or {}
    local sys_class_net = params.sys_class_net or "/sys/class/net"
    local details = {}
    local modules = {}
    local seen_modules = {}
    local unresolved_count = 0
    local invalid_count = 0

    local interfaces, dir_err = sorted_dir_entries(sys_class_net)
    if not interfaces then
        return {
            available = false,
            error = dir_err,
            wireless_present = false,
            module_count = 0,
            unresolved_count = 0,
            invalid_count = 0,
            disabled = false,
            details = details,
            module_details = {},
        }
    end

    for _, iface in ipairs(interfaces) do
        local iface_path = sys_class_net .. "/" .. iface
        if path_mode(iface_path .. "/wireless") == "directory" then
            local module_name = readlink_basename(iface_path .. "/device/driver/module")
            local detail = {
                interface = iface,
                wireless = true,
                module = module_name,
            }
            details[#details + 1] = detail

            if module_name == nil or module_name == "" then
                unresolved_count = unresolved_count + 1
            elseif not seen_modules[module_name] then
                modules[#modules + 1] = module_name
                seen_modules[module_name] = true
            end
        end
    end

    table.sort(modules)
    local module_details = {}
    for _, module_name in ipairs(modules) do
        local state, state_err = _dependencies.kmod_get_disable_state({ name = module_name })
        if not state then
            return nil, state_err
        end
        module_details[#module_details + 1] = state
        if state.disabled ~= true then
            invalid_count = invalid_count + 1
        end
    end

    return {
        available = true,
        wireless_present = #details > 0,
        module_count = #modules,
        unresolved_count = unresolved_count,
        invalid_count = invalid_count,
        disabled = unresolved_count == 0 and invalid_count == 0,
        details = details,
        module_details = module_details,
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
