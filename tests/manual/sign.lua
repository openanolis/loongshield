#!/usr/bin/env luajit

local pkcs7 = require("openssl").pkcs7
local kmod = require("kmod")

local cmd, file = ...

local ctx = kmod.ctx_new()

local key = ".sm2_ca.key"
local cert = ".sm2_ca.pem"

-- sign

local modfiles = {
    "tls.ko",
    "soundcore.ko"
}

for _, file in ipairs(modfiles) do
    local ok, err = kmod.sign(file, "sm3", key, cert, "signed_" .. file)
    if ok then
        print("sign: OK", file)
    else
        print("sign: err = ", err)
    end

    local sig, err = kmod.sigraw("signed_" .. file)
    if sig then
        local p7 = pkcs7.read(sig)
        print(string.rep('*', 75))
        print(p7:export())
        print(string.rep('*', 75))
    else
        print("sigraw: err = ", err)
    end
end

for _, file in ipairs(modfiles) do
    local ok, err = kmod.sign(file, "sm3", key, cert, file .. ".p7s", true)
    if ok then
        print("sign sig: OK", file)
    else
        print("sign sig: err = ", err)
    end
end

for _, file in ipairs(modfiles) do
    local ok, err = kmod.verify(file, cert, file .. ".p7s")
    if ok then
        print("verify sig: OK", file)
    else
        print("verify sig: err = ", err)
    end
end
