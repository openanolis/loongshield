local integrity = require('lua_lsm.integrity')

local PRIV_PEM = [[
-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIKbp83WDypEh9kqF
7JoFS/6Yc+vGFSSY2FFHq8WsvJnIoUQDQgAEnhq16xNbKDc0exyU+sSr2g1ZrzvD
CcWN7YVvpcL/nsdewUAAnuqPolzPviEU0fyiY+XfE9s/GAF43YGMRK4Bhg==
-----END PRIVATE KEY-----
]]

local PUB_PEM = [[
-----BEGIN PUBLIC KEY-----
MFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABJ4atesTWyg3NHsclPrEq9oNWa87
wwnFje2Fb6XC/57HXsFAAJ7qj6Jcz74hFNH8omPl3xPbPxgBeN2BjESuAYY=
-----END PUBLIC KEY-----
]]

local policy = [[
local errno = require("errno")

return {
    name = "integrity_demo",
    author = "LoongShield",
    description = "demo",
    license = "MIT",
    version = 1,
    file_open = function(file)
        return true, errno.EPERM
    end,
}
]]

local files = {}
local key_id

local fake_lfs = {
    mkdir = function()
        return true
    end,
    dir = function(path)
        local names = {}
        local prefix = path .. '/'
        for name in pairs(files) do
            if name:sub(1, #prefix) == prefix then
                local entry = name:sub(#prefix + 1):match('^[^/]+$')
                if entry then
                    names[#names + 1] = entry
                end
            end
        end
        table.sort(names)
        local index = 0
        return function()
            index = index + 1
            return names[index]
        end
    end,
}

local function fake_io_open(path, mode)
    if mode == 'wb' then
        return {
            write = function(_, content)
                files[path] = content
                return true
            end,
            close = function() end,
        }
    end
    if files[path] ~= nil then
        return {
            read = function()
                return files[path]
            end,
            close = function() end,
        }
    end
    return nil, 'not found: ' .. path
end

local function with_fixture(fn)
    files = {
        ['/policy/demo.lua'] = policy,
        ['/key/sm2.key'] = PRIV_PEM,
        ['/key/sm2.pub'] = PUB_PEM,
    }
    key_id = integrity.key_id(PUB_PEM)
    files['/trust/' .. key_id .. '.pem'] = PUB_PEM

    integrity._test_set_dependencies({
        io_open = fake_io_open,
        require = function(name)
            if name == 'openssl' then
                return require('openssl')
            elseif name == 'lfs' then
                return fake_lfs
            end
            return require(name)
        end,
    })

    local ok, err = pcall(fn)
    integrity._test_reset_dependencies()
    if not ok then
        error(err, 0)
    end
end

local function opts()
    return { trust_dir = '/trust' }
end

function test_lua_lsm_integrity_sign_embeds_signature_and_split_roundtrips()
    with_fixture(function()
        local signed, err = integrity.sign_file('/policy/demo.lua', '/key/sm2.key', {
            output_path = '/policy/signed.lua',
        })
        assert(signed == '/policy/signed.lua', tostring(err))

        local source, signature = integrity.read_policy(files['/policy/signed.lua'])
        assert(source == policy, 'Expected stripped source to round-trip')
        assert(type(signature) == 'string' and #signature > 0, 'Expected embedded signature')

        local ok, verify_err, verified_key = integrity.verify_policy(source, signature, opts())
        assert(ok == true, 'Expected embedded signature to verify: ' .. tostring(verify_err))
        assert(verified_key == key_id, 'Expected trusted key id')
    end)
end

function test_lua_lsm_integrity_unsigned_policy_has_no_signature()
    with_fixture(function()
        local source, signature = integrity.read_policy(policy)
        assert(source == policy, 'Expected unsigned policy to pass through')
        assert(signature == nil, 'Expected no signature')
    end)
end

function test_lua_lsm_integrity_rejects_tampered_policy()
    with_fixture(function()
        local signed, err = integrity.sign_file('/policy/demo.lua', '/key/sm2.key', {
            output_path = '/policy/signed.lua',
        })
        assert(signed, tostring(err))

        local tampered = files['/policy/signed.lua']:gsub('integrity_demo', 'tampered_demo')
        local source, signature = integrity.read_policy(tampered)
        assert(source ~= nil, 'Expected split to succeed')

        local ok, verify_err = integrity.verify_policy(source, signature, opts())
        assert(ok == false, 'Expected tampered policy to be rejected')
        assert(tostring(verify_err):find('did not verify', 1, true), 'Unexpected error: ' .. tostring(verify_err))
    end)
end

function test_lua_lsm_integrity_rejects_unsigned_policy_in_verify()
    with_fixture(function()
        local ok, err = integrity.verify_policy(policy, nil, opts())
        assert(ok == false, 'Expected unsigned policy to be rejected by verify')
        assert(tostring(err):find('not signed', 1, true), 'Unexpected error: ' .. tostring(err))
    end)
end

function test_lua_lsm_integrity_rejects_empty_trust_store()
    with_fixture(function()
        files['/trust/' .. key_id .. '.pem'] = nil
        local signed, err = integrity.sign_file('/policy/demo.lua', '/key/sm2.key', {
            output_path = '/policy/signed.lua',
        })
        assert(signed, tostring(err))

        local source, signature = integrity.read_policy(files['/policy/signed.lua'])
        local ok, verify_err = integrity.verify_policy(source, signature, opts())
        assert(ok == false, 'Expected empty trust store to be rejected')
        assert(tostring(verify_err):find('no trusted', 1, true), 'Unexpected error: ' .. tostring(verify_err))
    end)
end

function test_lua_lsm_integrity_import_key_stores_by_key_id()
    with_fixture(function()
        files['/trust/' .. key_id .. '.pem'] = nil
        files['/incoming/sm2.pub'] = PUB_PEM

        local imported, err = integrity.import_key('/incoming/sm2.pub', opts())
        assert(imported == key_id, 'Expected key id import: ' .. tostring(err))
        assert(files['/trust/' .. key_id .. '.pem'] == PUB_PEM, 'Expected PEM stored in trust dir')

        local keys = integrity.list_keys(opts())
        assert(#keys == 1 and keys[1].id == key_id, 'Expected one imported key')
    end)
end

function test_lua_lsm_integrity_rejects_invalid_public_key_import()
    with_fixture(function()
        files['/incoming/bad.pub'] = 'not a pem key'
        local imported, err = integrity.import_key('/incoming/bad.pub', opts())
        assert(imported == nil, 'Expected invalid key import to fail')
        assert(tostring(err):find('not a valid public key', 1, true), 'Unexpected error: ' .. tostring(err))
    end)
end

function test_lua_lsm_integrity_appraise_mode_validation()
    integrity._test_set_dependencies({
        getenv = function()
            return nil
        end,
    })
    assert(integrity.appraise_mode() == 'off', 'Expected off to be the default mode')
    integrity._test_reset_dependencies()

    integrity._test_set_dependencies({
        getenv = function(name)
            if name == 'LOONGSHIELD_LUA_LSM_APPRAISE' then
                return 'log'
            end
            return nil
        end,
    })
    assert(integrity.appraise_mode() == 'log')
    integrity._test_reset_dependencies()

    assert(integrity.appraise_mode({ appraise = 'off' }) == 'off')
    assert(integrity.appraise_mode({ appraise = 'enforce' }) == 'enforce')

    local mode, err = integrity.appraise_mode({ appraise = 'bogus' })
    assert(mode == nil, 'Expected invalid mode to be rejected')
    assert(tostring(err):find('invalid appraisal mode', 1, true), 'Unexpected error: ' .. tostring(err))
end

function test_lua_lsm_integrity_sign_file_resigns_from_stripped_source()
    with_fixture(function()
        local first, err = integrity.sign_file('/policy/demo.lua', '/key/sm2.key', {
            output_path = '/policy/signed.lua',
        })
        assert(first, tostring(err))

        -- Re-signing the already-signed file must produce a fresh valid
        -- signature over the same source, not a nested double signature.
        local second, second_err = integrity.sign_file('/policy/signed.lua', '/key/sm2.key', {
            output_path = '/policy/resigned.lua',
        })
        assert(second, tostring(second_err))

        local source, signature = integrity.read_policy(files['/policy/resigned.lua'])
        assert(source == policy, 'Expected re-signed source to match original')
        local ok, verify_err = integrity.verify_policy(source, signature, opts())
        assert(ok == true, 'Expected re-signed policy to verify: ' .. tostring(verify_err))
    end)
end

function test_lua_lsm_integrity_rejects_corrupt_trailer()
    with_fixture(function()
        local signed, err = integrity.sign_file('/policy/demo.lua', '/key/sm2.key', {
            output_path = '/policy/signed.lua',
        })
        assert(signed, tostring(err))

        -- Corrupt the most significant sig_len byte so the split cannot be trusted.
        local bytes = { files['/policy/signed.lua']:byte(1, #files['/policy/signed.lua']) }
        bytes[#bytes - 5] = 0xff
        local corrupt = string.char(unpack(bytes))
        local source, split_err = integrity.read_policy(corrupt)
        assert(source == nil, 'Expected corrupt trailer to be rejected')
        assert(tostring(split_err):find('corrupt', 1, true), 'Unexpected error: ' .. tostring(split_err))
    end)
end
