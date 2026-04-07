local M = {}

local _default_dependencies = {
    io_popen = io.popen,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
end

M._test_set_dependencies()

local function run_command(cmd)
    local handle = _dependencies.io_popen(cmd, "r")
    if not handle then
        return nil
    end

    local lines = {}
    for line in handle:lines() do
        lines[#lines + 1] = line
    end

    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        return nil
    end

    return lines
end

local function get_machine_arch()
    local lines = run_command("uname -m")
    if not lines or not lines[1] or lines[1] == "" then
        return nil
    end

    return lines[1]
end

local function add_arch(arches, seen, arch)
    if not seen[arch] then
        arches[#arches + 1] = arch
        seen[arch] = true
    end
end

local function get_fallback_audit_arches(machine_arch)
    local arches = {}
    local seen = {}

    if machine_arch == "x86_64" then
        add_arch(arches, seen, "b64")
        add_arch(arches, seen, "b32")
        return arches
    end

    if type(machine_arch) == "string" and machine_arch:match("^i[%d]86$") then
        add_arch(arches, seen, "b32")
        return arches
    end

    if type(machine_arch) == "string" and machine_arch:find("64", 1, true) then
        add_arch(arches, seen, "b64")
        return arches
    end

    add_arch(arches, seen, "b32")
    return arches
end

local function supports_audit_arch(arch)
    return run_command(string.format("ausyscall %s 0 2>/dev/null", arch)) ~= nil
end

function M.get_supported_audit_arches()
    local arches = {}
    local seen = {}
    local machine_arch = get_machine_arch()

    for _, arch in ipairs({ "b64", "b32" }) do
        if supports_audit_arch(arch) then
            add_arch(arches, seen, arch)
        end
    end

    if #arches == 0 then
        arches = get_fallback_audit_arches(machine_arch)
    end

    return {
        count = #arches,
        arches = arches,
        machine_arch = machine_arch,
    }
end

return M
