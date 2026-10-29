local M = {}

-- Embedded policy signature trailer, modeled after Linux module signatures
-- and RPM signatures: the signature is stored at the end of the policy file
-- itself instead of in a loose sidecar file.
--
-- Layout:
--   <Lua policy source>
--   <SM2 signature (DER, sig_len bytes)>
--   <16-byte trailer>
--     [0..5]   magic "LULSM\x01"
--     [6]      algo (0x01 = SM2 with SM3 digest)
--     [7..10]  sig_len, little-endian uint32
--     [11..15] reserved, zero (5 bytes)

local TRAILER_SIZE = 16
local MAGIC = 'LULSM\x01'
local ALGO_SM2_SM3 = 1

local SM2_USER_ID = '1234567812345678'
local SM2_CURVE_OID = string.char(0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d)

local DEFAULT_TRUST_DIR = '/var/lib/loongshield/lua-lsm/pubkeys'

local deps = {
    getenv = os.getenv,
    io_open = io.open,
    require = require,
}

local function read_file(path)
    local file, err = deps.io_open(path, 'rb')
    if not file then
        return nil, err or ('failed to open ' .. path)
    end

    local content = file:read('*a')
    file:close()
    return content or ''
end

local function write_file(path, content)
    local file, err = deps.io_open(path, 'wb')
    if not file then
        return nil, err or ('failed to open ' .. path)
    end

    local ok, write_err = file:write(content)
    file:close()
    if not ok then
        return nil, write_err or ('failed to write ' .. path)
    end

    return true
end

local function load_openssl()
    local ok, openssl = pcall(deps.require, 'openssl')
    if not ok or type(openssl) ~= 'table' then
        return nil, 'openssl module is unavailable'
    end
    return openssl
end

local function load_key(pem, private)
    local openssl, err = load_openssl()
    if not openssl then
        return nil, err
    end

    local key, read_err = openssl.pkey.read(pem, private, 'pem')
    if not key then
        return nil, 'failed to read SM2 key: ' .. tostring(read_err)
    end

    local der = key:export('der')
    if type(der) ~= 'string' or not der:find(SM2_CURVE_OID, 1, true) then
        return nil, 'key is not an SM2 key'
    end
    return key
end

local function u32le(value)
    return string.char(
        bit.band(value, 0xff),
        bit.band(bit.rshift(value, 8), 0xff),
        bit.band(bit.rshift(value, 16), 0xff),
        bit.band(bit.rshift(value, 24), 0xff)
    )
end

local function read_u32le(data, offset)
    local b1, b2, b3, b4 = data:byte(offset, offset + 3)
    return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

--- Split a policy file into (source, signature). Unsigned policies return
--- (content, nil).
function M.read_policy(content)
    if type(content) ~= 'string' then
        return nil, 'policy content must be a string'
    end

    if #content < TRAILER_SIZE then
        return content, nil
    end

    local trailer = content:sub(#content - TRAILER_SIZE + 1)
    if trailer:sub(1, #MAGIC) ~= MAGIC then
        return content, nil
    end

    local algo = trailer:byte(#MAGIC + 1)
    if algo ~= ALGO_SM2_SM3 then
        return nil, 'unsupported policy signature algorithm: ' .. tostring(algo)
    end

    local sig_len = read_u32le(trailer, #MAGIC + 2)
    if sig_len == 0 or sig_len + TRAILER_SIZE > #content then
        return nil, 'corrupt policy signature trailer'
    end

    local signature = content:sub(#content - TRAILER_SIZE - sig_len + 1, #content - TRAILER_SIZE)
    local source = content:sub(1, #content - TRAILER_SIZE - sig_len)
    return source, signature
end

local function build_signed(source, signature)
    return source .. signature .. MAGIC .. string.char(ALGO_SM2_SM3) .. u32le(#signature) .. string.char(0, 0, 0, 0, 0)
end

--- Sign a policy file in place, like `rpm --addsign`. The signature is
--- embedded at the end of the policy file itself.
function M.sign_file(policy_path, key_path, opts)
    if type(policy_path) ~= 'string' or policy_path == '' then
        return nil, 'policy path is required'
    end
    if type(key_path) ~= 'string' or key_path == '' then
        return nil, 'private key path is required'
    end

    opts = opts or {}

    local content, err = read_file(policy_path)
    if not content then
        return nil, err
    end

    -- Re-signing strips any previous signature first.
    local source, split_err = M.read_policy(content)
    if not source then
        return nil, split_err
    end

    local pem, pem_err = read_file(key_path)
    if not pem then
        return nil, pem_err
    end

    local key, key_err = load_key(pem, true)
    if not key then
        return nil, key_err
    end

    local signature, sign_err = key:sign(source, 'sm3', SM2_USER_ID)
    if not signature then
        return nil, 'SM2 signing failed: ' .. tostring(sign_err)
    end

    local signed = build_signed(source, signature)
    local out_path = opts.output_path or policy_path
    local ok, write_err = write_file(out_path, signed)
    if not ok then
        return nil, write_err
    end

    return out_path
end

--- Key id derived from the SM3 digest of the stored key material,
--- like an RPM key fingerprint.
function M.key_id(pem)
    local openssl, err = load_openssl()
    if not openssl then
        return nil, err
    end

    local digest, digest_err = openssl.digest.digest('sm3', pem)
    if not digest then
        return nil, 'failed to digest public key: ' .. tostring(digest_err)
    end
    return digest:sub(1, 16)
end

function M.trust_dir(opts)
    opts = opts or {}
    return opts.trust_dir or deps.getenv('LOONGSHIELD_LUA_LSM_PUBKEY_DIR') or DEFAULT_TRUST_DIR
end

--- Import a public key into the local trust store, like `rpm --import`.
function M.import_key(pem_path, opts)
    if type(pem_path) ~= 'string' or pem_path == '' then
        return nil, 'public key path is required'
    end

    local pem, err = read_file(pem_path)
    if not pem then
        return nil, err
    end

    -- Validate before storing.
    local key, key_err = load_key(pem, false)
    if not key then
        return nil, 'not a valid public key: ' .. tostring(key_err)
    end

    local id, id_err = M.key_id(pem)
    if not id then
        return nil, id_err
    end

    local dir = M.trust_dir(opts)
    local ok, lfs = pcall(deps.require, 'lfs')
    if ok and lfs then
        lfs.mkdir(dir)
    end

    local stored = dir .. '/' .. id .. '.pem'
    local ok, write_err = write_file(stored, pem)
    if not ok then
        return nil, write_err
    end

    return id
end

function M.list_keys(opts)
    local dir = M.trust_dir(opts)
    local keys = {}

    local ok, lfs = pcall(deps.require, 'lfs')
    if not ok or not lfs then
        return keys, 'lfs is required to list Lua-LSM trusted keys'
    end

    if lfs.attributes(dir, 'mode') ~= 'directory' then
        return keys
    end

    for entry in lfs.dir(dir) do
        if entry:match('^[%w]+%.pem$') then
            local path = dir .. '/' .. entry
            local pem = read_file(path)
            if pem then
                keys[#keys + 1] = {
                    id = entry:gsub('%.pem$', ''),
                    path = path,
                }
            end
        end
    end

    table.sort(keys, function(a, b)
        return a.id < b.id
    end)
    return keys
end

local function verify_with_key(source, signature, pem)
    local key, err = load_key(pem, false)
    if not key then
        return nil, err
    end

    local ok = key:verify(source, signature, 'sm3', SM2_USER_ID)
    if ok == true then
        return true
    end
    return nil, 'signature did not verify'
end

--- Verify an embedded signature against every key in the trust store.
function M.verify_policy(source, signature, opts)
    if type(source) ~= 'string' then
        return false, 'policy source is required'
    end
    if type(signature) ~= 'string' or signature == '' then
        return false, 'policy is not signed'
    end

    local keys = M.list_keys(opts)
    if #keys == 0 then
        return false, 'no trusted Lua-LSM public keys imported'
    end

    local last_err = 'signature did not verify'
    for _, key in ipairs(keys) do
        local pem = read_file(key.path)
        if pem then
            local ok, err = verify_with_key(source, signature, pem)
            if ok then
                return true, nil, key.id
            end
            last_err = err
        end
    end

    return false, last_err
end

--- Appraisal mode, like ima_appraise: off | log | enforce.
function M.appraise_mode(opts)
    opts = opts or {}
    local mode = opts.appraise or deps.getenv('LOONGSHIELD_LUA_LSM_APPRAISE') or 'off'

    if mode ~= 'off' and mode ~= 'log' and mode ~= 'enforce' then
        return nil, "invalid appraisal mode '" .. tostring(mode) .. "' (expected off, log, or enforce)"
    end
    return mode
end

function M._test_set_dependencies(overrides)
    overrides = overrides or {}
    for key, value in pairs(overrides) do
        deps[key] = value
    end
end

function M._test_reset_dependencies()
    deps.getenv = os.getenv
    deps.io_open = io.open
    deps.require = require
end

return M
