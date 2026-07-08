--- Environment detection probes for seharden reinforce guards.
-- These probes detect the runtime environment so that dangerous
-- reinforce actions (e.g. disabling overlay, killing ip_forward)
-- can be safely skipped on container hosts.
local log = require('runtime.log')
local M = {}

local _default_dependencies = {
    io_open    = io.open,
    os_execute = os.execute,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

--- Check whether a file exists on disk.
local function file_exists(path)
    local f = _dependencies.io_open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

--- Check whether kubelet is running (hardcoded to avoid shell injection).
local function kubelet_running()
    local ok, _, code = _dependencies.os_execute(
        "pgrep -x kubelet >/dev/null 2>&1")
    return ok == true or code == 0
end

--- Detect whether the host is running a container runtime.
-- Checks: Docker socket, containerd socket, kubelet, /.dockerenv
-- Returns: true, reason  when container runtime is detected
--          false          when no container runtime found
function M.is_container_host(_params)
    if file_exists("/run/docker.sock") then
        return true, "container runtime detected: /run/docker.sock exists"
    end

    if file_exists("/run/containerd/containerd.sock") then
        return true, "container runtime detected: /run/containerd/containerd.sock exists"
    end

    if kubelet_running() then
        return true, "container runtime detected: kubelet process found"
    end

    if file_exists("/.dockerenv") then
        return true, "container runtime detected: /.dockerenv exists"
    end

    log.debug("env_detect.is_container_host: no container runtime detected")
    return false
end

return M
