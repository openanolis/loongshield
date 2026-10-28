#!/usr/bin/env luajit
--
-- Sign a Lua-LSM policy in place with an SM2 private key (SM3 digest).
-- The signature is embedded at the end of the policy file itself.
--
-- Usage:
--   luajit tools/lua-lsm/sign_policy.lua <policy.lua> <sm2-private.pem> [output.lua]

local integrity = require('lua_lsm.integrity')

if #arg < 2 or #arg > 3 then
    print('Usage: luajit tools/lua-lsm/sign_policy.lua <policy.lua> <sm2-private.pem> [output.lua]')
    os.exit(1)
end

local signed_path, err = integrity.sign_file(arg[1], arg[2], {
    output_path = arg[3],
})
if not signed_path then
    io.stderr:write('error: ' .. tostring(err) .. '\n')
    os.exit(1)
end

print('Signed Lua-LSM policy (signature embedded): ' .. signed_path)
