local text = require('seharden.shared.text')

local M = {}

local DEFAULT_CURRENT_POLICY_PATH = "/etc/crypto-policies/state/CURRENT.pol"

local _default_dependencies = {
    io_open = io.open,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function normalize(value)
    return text.trim(tostring(value or "")):lower()
end

local function uppercase(value)
    return tostring(value or ""):upper()
end

local function strip_comment(line)
    local comment_start = tostring(line or ""):find("#", 1, true)
    if comment_start then
        return line:sub(1, comment_start - 1)
    end
    return line
end

local function read_logical_lines(handle)
    local lines = {}
    local pending = ""

    for raw_line in handle:lines() do
        local line = tostring(raw_line or ""):gsub("\r$", "")
        local trimmed_right = line:gsub("%s+$", "")

        if trimmed_right:sub(-1) == "\\" then
            pending = pending .. trimmed_right:sub(1, -2) .. " "
        else
            lines[#lines + 1] = pending .. line
            pending = ""
        end
    end

    if pending ~= "" then
        lines[#lines + 1] = pending
    end

    return lines
end

local function parse_scopes(scope_expr)
    if not scope_expr or scope_expr == "" then
        return { "" }
    end

    scope_expr = text.trim(scope_expr)
    scope_expr = scope_expr:gsub("^%{", ""):gsub("%}$", "")

    local scopes = {}
    for scope in scope_expr:gmatch("[^,]+") do
        local normalized = normalize(scope)
        if normalized ~= "" then
            scopes[#scopes + 1] = normalized
        end
    end

    if #scopes == 0 then
        scopes[1] = ""
    end

    return scopes
end

local function parse_entry_line(line)
    local active = text.trim(strip_comment(line))
    if active == "" then
        return {}
    end

    local key, value = active:match("^([^=%s]+)%s*=%s*(.-)%s*$")
    if not key then
        return {}
    end

    key = normalize(key)
    local option, scope_expr = key:match("^([^@]+)@(.+)$")
    option = option or key

    local entries = {}
    for _, scope in ipairs(parse_scopes(scope_expr)) do
        entries[#entries + 1] = {
            option = option,
            scope = scope,
            value = value,
        }
    end
    return entries
end

local function read_entries(path)
    local file, err = _dependencies.io_open(path, "r")
    if not file then
        return nil, err
    end

    local entries = {}
    for _, line in ipairs(read_logical_lines(file)) do
        for _, entry in ipairs(parse_entry_line(line)) do
            entries[#entries + 1] = entry
        end
    end
    file:close()
    return entries
end

local function split_tokens(value)
    local tokens = {}
    for token in tostring(value or ""):gmatch("[^,%s]+") do
        tokens[#tokens + 1] = token
    end
    return tokens
end

local function parse_token(raw_token)
    local token = text.trim(tostring(raw_token or ""))
    if token == "" then
        return nil
    end

    if token:sub(1, 1) == "-" and #token > 1 then
        return {
            op = "remove",
            value = uppercase(token:sub(2)),
        }
    end

    if token:sub(-1) == "+" and #token > 1 then
        return {
            op = "append",
            value = uppercase(token:sub(1, -2)),
        }
    end

    return {
        op = "set",
        value = uppercase(token),
    }
end

local function escape_lua_pattern(value)
    return tostring(value or ""):gsub("([%^%$%(%)%%%.%[%]%+%-%?%*])", "%%%1")
end

local function wildcard_matches(pattern, token)
    pattern = escape_lua_pattern(uppercase(pattern)):gsub("%%%*", ".*")
    return uppercase(token):match("^" .. pattern .. "$") ~= nil
end

local function remove_matching_tokens(state, pattern)
    local kept = {}
    local seen = {}

    for _, token in ipairs(state.tokens) do
        if not wildcard_matches(pattern, token) and not seen[token] then
            kept[#kept + 1] = token
            seen[token] = true
        end
    end

    state.tokens = kept
    state.token_seen = seen
end

local function add_token(state, token)
    if token == "" or state.token_seen[token] then
        return
    end
    state.tokens[#state.tokens + 1] = token
    state.token_seen[token] = true
end

local function get_scope_state(policy_state, option, scope)
    policy_state[option] = policy_state[option] or {}
    policy_state[option][scope] = policy_state[option][scope] or {
        present = false,
        tokens = {},
        token_seen = {},
    }
    return policy_state[option][scope]
end

local function build_effective_state(entries)
    local policy_state = {}

    for _, entry in ipairs(entries or {}) do
        local scope_state = get_scope_state(policy_state, entry.option, entry.scope)
        local parsed_tokens = {}
        local has_set_token = false
        local raw_tokens = split_tokens(entry.value)

        scope_state.present = true

        for _, raw_token in ipairs(raw_tokens) do
            local parsed = parse_token(raw_token)
            if parsed then
                parsed_tokens[#parsed_tokens + 1] = parsed
                if parsed.op == "set" then
                    has_set_token = true
                end
            end
        end

        if has_set_token or #raw_tokens == 0 then
            scope_state.tokens = {}
            scope_state.token_seen = {}
        end

        for _, parsed in ipairs(parsed_tokens) do
            if parsed.op == "remove" then
                remove_matching_tokens(scope_state, parsed.value)
            else
                add_token(scope_state, parsed.value)
            end
        end
    end

    return policy_state
end

local function get_existing_scope(policy_state, option, scope)
    return policy_state[option] and policy_state[option][scope] or nil
end

local function scope_present(policy_state, option, scope)
    local scope_state = get_existing_scope(policy_state, option, scope)
    return scope_state ~= nil and scope_state.present == true
end

local function token_contains(token, needle)
    return uppercase(token):find(uppercase(needle), 1, true) ~= nil
end

local function token_has_segment_with_boundary(token, segment)
    token = uppercase(token)
    segment = uppercase(segment)

    local start = 1
    while true do
        local found_start, found_end = token:find(segment, start, true)
        if not found_start then
            return false
        end

        local following = token:sub(found_end + 1, found_end + 1)
        if following == "" or not following:match("[%w_]") then
            return true
        end

        start = found_end + 1
    end
end

local function scope_has_token(policy_state, option, scope, predicate)
    local scope_state = get_existing_scope(policy_state, option, scope)
    if not scope_state then
        return false
    end

    for _, token in ipairs(scope_state.tokens) do
        if predicate(token) then
            return true
        end
    end

    return false
end

local function option_has_token(policy_state, option, predicate)
    for scope in pairs(policy_state[option] or {}) do
        if scope_has_token(policy_state, option, scope, predicate) then
            return true
        end
    end
    return false
end

local function scalar_value_is(policy_state, option, expected)
    local scope_state = get_existing_scope(policy_state, option, "")
    return scope_state ~= nil
        and scope_state.present == true
        and #scope_state.tokens == 1
        and scope_state.tokens[1] == uppercase(expected)
end

local function sha1_hash_signature_disabled(policy_state)
    if not scope_present(policy_state, "hash", "") or not scope_present(policy_state, "sign", "") then
        return false
    end

    for _, option in ipairs({ "hash", "sign" }) do
        if option_has_token(policy_state, option, function(token)
            return token_contains(token, "SHA1")
        end) then
            return false
        end
    end

    return true
end

local function sha1_in_certs_disabled(policy_state)
    return scalar_value_is(policy_state, "sha1_in_certs", "0")
end

local function weak_macs_disabled(policy_state)
    if not scope_present(policy_state, "mac", "") then
        return false
    end

    return not option_has_token(policy_state, "mac", function(token)
        return token_has_segment_with_boundary(token, "-128")
    end)
end

local function is_ssh_scope(scope)
    scope = normalize(scope)
    return scope == "ssh"
        or scope == "libssh"
        or scope == "libssh-server"
        or scope == "libssh-client"
        or scope == "openssh"
        or scope == "openssh-server"
        or scope == "openssh-client"
end

local function ssh_scope_has_cbc(policy_state, scope)
    return scope_has_token(policy_state, "cipher", scope, function(token)
        return token_has_segment_with_boundary(token, "-CBC")
    end)
end

local function ssh_scope_present_and_clean(policy_state, scope)
    return scope_present(policy_state, "cipher", scope) and not ssh_scope_has_cbc(policy_state, scope)
end

local function ssh_family_clean(policy_state, family)
    return ssh_scope_present_and_clean(policy_state, family)
        or (ssh_scope_present_and_clean(policy_state, family .. "-server")
            and ssh_scope_present_and_clean(policy_state, family .. "-client"))
end

local function ssh_cbc_disabled(policy_state)
    if not scope_present(policy_state, "cipher", "") then
        return false
    end

    for scope in pairs(policy_state.cipher or {}) do
        if is_ssh_scope(scope) and ssh_scope_has_cbc(policy_state, scope) then
            return false
        end
    end

    local global_has_cbc = ssh_scope_has_cbc(policy_state, "")
    if not global_has_cbc then
        return true
    end

    return ssh_scope_present_and_clean(policy_state, "ssh")
        or (ssh_family_clean(policy_state, "openssh") and ssh_family_clean(policy_state, "libssh"))
end

function M.inspect_current(params)
    params = params or {}
    local path = params.path or DEFAULT_CURRENT_POLICY_PATH
    local entries, err = read_entries(path)

    if not entries then
        return {
            available = false,
            path = path,
            error = tostring(err),
            sha1_hash_signature_disabled = false,
            sha1_in_certs_disabled = false,
            sha1_disabled = false,
            weak_macs_disabled = false,
            ssh_cbc_disabled = false,
        }
    end

    local policy_state = build_effective_state(entries)
    local sha1_hash_sign_ok = sha1_hash_signature_disabled(policy_state)
    local sha1_certs_ok = sha1_in_certs_disabled(policy_state)

    return {
        available = true,
        path = path,
        sha1_hash_signature_disabled = sha1_hash_sign_ok,
        sha1_in_certs_disabled = sha1_certs_ok,
        sha1_disabled = sha1_hash_sign_ok and sha1_certs_ok,
        weak_macs_disabled = weak_macs_disabled(policy_state),
        ssh_cbc_disabled = ssh_cbc_disabled(policy_state),
    }
end

return M
