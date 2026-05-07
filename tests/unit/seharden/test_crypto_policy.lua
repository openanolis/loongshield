local crypto_policy = require('seharden.probes.crypto_policy')

local function make_reader(content)
    local lines = {}
    content = tostring(content or "")

    for line in (content .. "\n"):gmatch("(.-)\n") do
        lines[#lines + 1] = line
    end

    local index = 0
    return {
        lines = function()
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function()
            return true
        end,
    }
end

local function with_policy_content(content, fn)
    crypto_policy._test_set_dependencies({
        io_open = function(path, mode)
            assert(path == "/tmp/CURRENT.pol", "Expected crypto policy probe to read the requested path")
            assert(mode == "r", "Expected crypto policy probe to open the policy read-only")
            return make_reader(content)
        end,
    })

    local ok, err = pcall(fn)
    crypto_policy._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

local function with_missing_policy(fn)
    crypto_policy._test_set_dependencies({
        io_open = function()
            return nil, "No such file or directory"
        end,
    })

    local ok, err = pcall(fn)
    crypto_policy._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

local function inspect_content(content)
    local result
    with_policy_content(content, function()
        result = crypto_policy.inspect_current({
            path = "/tmp/CURRENT.pol",
        })
    end)
    return result
end

function test_inspect_current_reports_missing_policy_file()
    local result

    with_missing_policy(function()
        result = crypto_policy.inspect_current({
            path = "/tmp/CURRENT.pol",
        })
    end)

    assert(result.available == false, "Expected missing CURRENT.pol to be reported explicitly")
    assert(result.sha1_hash_signature_disabled == false, "Expected missing policy to fail SHA1 hash/sign check")
    assert(result.sha1_in_certs_disabled == false, "Expected missing policy to fail SHA1 cert check")
    assert(result.sha1_disabled == false, "Expected missing policy to fail aggregate SHA1 check")
    assert(result.weak_macs_disabled == false, "Expected missing policy to fail weak MAC check")
    assert(result.ssh_cbc_disabled == false, "Expected missing policy to fail SSH CBC check")
end

function test_sha1_hash_and_signature_checks_ignore_disabling_directives()
    local compliant = inspect_content(table.concat({
        "hash = -SHA1 SHA2-256 SHA2-512",
        "sign = -*-SHA1 RSA-SHA2-256",
        "sha1_in_certs = 0",
        "mac = HMAC-SHA2-256",
        "cipher = AES-256-GCM AES-256-CTR",
    }, "\n"))

    assert(compliant.available == true, "Expected readable policy to be available")
    assert(compliant.sha1_hash_signature_disabled == true,
        "Expected SHA1 hash/sign disabling directives not to count as enabled SHA1")
    assert(compliant.sha1_in_certs_disabled == true, "Expected sha1_in_certs = 0 to pass")
    assert(compliant.sha1_disabled == true, "Expected aggregate SHA1 check to pass")

    local comment_and_continuation = inspect_content(table.concat({
        "hash = SHA2-256# SHA1 only appears in the comment",
        "sign = RSA-SHA2-256 \\",
        " EDDSA",
        "sha1_in_certs = 0",
        "mac = HMAC-SHA2-256",
        "cipher = AES-256-GCM",
    }, "\n"))

    assert(comment_and_continuation.sha1_disabled == true,
        "Expected crypto-policy comments and line continuations not to create false SHA1 findings")

    local hash_enabled = inspect_content(table.concat({
        "hash = SHA1 SHA2-256",
        "sign = -*-SHA1",
        "sha1_in_certs = 0",
    }, "\n"))

    assert(hash_enabled.sha1_hash_signature_disabled == false,
        "Expected enabled SHA1 hash token to fail")
    assert(hash_enabled.sha1_disabled == false,
        "Expected enabled SHA1 hash token to fail aggregate SHA1 check")

    local sign_enabled = inspect_content(table.concat({
        "hash = -SHA1",
        "sign = RSA-SHA1 RSA-SHA2-256",
        "sha1_in_certs = 0",
    }, "\n"))

    assert(sign_enabled.sha1_hash_signature_disabled == false,
        "Expected enabled RSA-SHA1 signature token to fail")

    local scoped_sha1_enabled = inspect_content(table.concat({
        "hash = SHA2-256",
        "sign = RSA-SHA2-256",
        "hash@DNSSEC = SHA1+",
        "sign@OpenSSL = RSA-SHA1+",
        "sha1_in_certs = 0",
    }, "\n"))

    assert(scoped_sha1_enabled.sha1_hash_signature_disabled == false,
        "Expected scoped SHA1 hash/sign tokens to fail")

    local certs_enabled = inspect_content(table.concat({
        "hash = -SHA1",
        "sign = -*-SHA1",
        "sha1_in_certs = 1",
    }, "\n"))

    assert(certs_enabled.sha1_hash_signature_disabled == true,
        "Expected hash/sign check to stay independent from sha1_in_certs")
    assert(certs_enabled.sha1_in_certs_disabled == false,
        "Expected sha1_in_certs values other than 0 to fail")
    assert(certs_enabled.sha1_disabled == false,
        "Expected aggregate SHA1 check to fail when cert SHA1 remains enabled")

    local missing_hash_or_sign = inspect_content("sha1_in_certs = 0\n")

    assert(missing_hash_or_sign.sha1_hash_signature_disabled == false,
        "Expected missing hash/sign policy evidence to fail closed")
end

function test_weak_mac_check_ignores_disabled_128_bit_mac_patterns()
    local weak_enabled = inspect_content(table.concat({
        "sha1_in_certs = 0",
        "mac = HMAC-SHA2-256 HMAC-SHA1-128",
    }, "\n"))

    assert(weak_enabled.weak_macs_disabled == false,
        "Expected enabled -128 MAC token to fail")

    local weak_enabled_with_suffix = inspect_content(table.concat({
        "sha1_in_certs = 0",
        "mac = UMAC-128-ETM HMAC-SHA2-256",
    }, "\n"))

    assert(weak_enabled_with_suffix.weak_macs_disabled == false,
        "Expected enabled MAC tokens containing -128 before another separator to fail")

    local weak_scoped_enabled = inspect_content(table.concat({
        "mac = HMAC-SHA2-256",
        "mac@SSH = HMAC-SHA1-128",
    }, "\n"))

    assert(weak_scoped_enabled.weak_macs_disabled == false,
        "Expected weak MAC tokens in scoped policy entries to fail")

    local weak_disabled = inspect_content(table.concat({
        "sha1_in_certs = 0",
        "mac = -*-128 HMAC-SHA2-256",
        "mac = -*-128* HMAC-SHA2-512",
    }, "\n"))

    assert(weak_disabled.weak_macs_disabled == true,
        "Expected -128 MAC wildcard disabling directives not to count as enabled weak MACs")

    local weak_reset = inspect_content(table.concat({
        "mac = HMAC-SHA1-128",
        "mac = HMAC-SHA2-256",
    }, "\n"))

    assert(weak_reset.weak_macs_disabled == true,
        "Expected later MAC reassignment to replace earlier weak MAC values")

    local weak_removed = inspect_content(table.concat({
        "mac = HMAC-SHA1-128 HMAC-SHA2-256",
        "mac = -*-128",
    }, "\n"))

    assert(weak_removed.weak_macs_disabled == true,
        "Expected later wildcard remove directives to clear earlier weak MAC values")

    local missing_mac = inspect_content("cipher = AES-256-GCM\n")

    assert(missing_mac.weak_macs_disabled == false,
        "Expected missing MAC policy evidence to fail closed")
end

function test_ssh_cbc_check_requires_ssh_override_only_when_global_cbc_is_enabled()
    local globally_disabled = inspect_content("cipher = AES-256-GCM AES-256-CTR\n")

    assert(globally_disabled.ssh_cbc_disabled == true,
        "Expected SSH CBC to pass when global cipher policy has no enabled CBC token")

    local global_cbc_without_ssh_override = inspect_content("cipher = AES-256-CBC AES-256-GCM\n")

    assert(global_cbc_without_ssh_override.ssh_cbc_disabled == false,
        "Expected global CBC ciphers without SSH override to fail")

    local ssh_cbc_disabled = inspect_content(table.concat({
        "cipher = AES-256-CBC AES-256-GCM",
        "cipher@SSH = -*-CBC AES-256-GCM",
    }, "\n"))

    assert(ssh_cbc_disabled.ssh_cbc_disabled == true,
        "Expected generic cipher@SSH CBC disabling directive to satisfy the SSH override")

    local ssh_cbc_enabled = inspect_content(table.concat({
        "cipher = AES-256-CBC AES-256-GCM",
        "cipher@openssh-server = AES-128-CBC-SHA AES-256-GCM",
    }, "\n"))

    assert(ssh_cbc_enabled.ssh_cbc_disabled == false,
        "Expected enabled CBC under an SSH-specific cipher key to fail, including CBC before another separator")

    local ssh_cbc_disabled_for_backends = inspect_content(table.concat({
        "cipher = AES-256-CBC AES-256-GCM",
        "cipher@openssh = -*-CBC AES-256-GCM",
        "cipher@libssh = -*-CBC AES-256-GCM",
    }, "\n"))

    assert(ssh_cbc_disabled_for_backends.ssh_cbc_disabled == true,
        "Expected libssh and OpenSSH scoped CBC disabling directives to satisfy the SSH override")

    local partial_ssh_override = inspect_content(table.concat({
        "cipher = AES-256-CBC AES-256-GCM",
        "cipher@openssh-server = -*-CBC",
    }, "\n"))

    assert(partial_ssh_override.ssh_cbc_disabled == false,
        "Expected a partial SSH backend override not to mask inherited global CBC")

    local braced_ssh_overrides = inspect_content(table.concat({
        "cipher = AES-256-CBC AES-256-GCM",
        "cipher@{OpenSSH,libssh} = -*-CBC",
    }, "\n"))

    assert(braced_ssh_overrides.ssh_cbc_disabled == true,
        "Expected braced OpenSSH/libssh scopes to cover both SSH backends")

    local ssh_append_enables_cbc = inspect_content(table.concat({
        "cipher = AES-256-GCM",
        "cipher@SSH = AES-256-CBC+",
    }, "\n"))

    assert(ssh_append_enables_cbc.ssh_cbc_disabled == false,
        "Expected SSH-scoped CBC append tokens to fail even when global ciphers are clean")

    local scoped_reenable_after_generic_disable = inspect_content(table.concat({
        "cipher = AES-256-CBC AES-256-GCM",
        "cipher@SSH = -*-CBC",
        "cipher@libssh = AES-256-CBC+",
    }, "\n"))

    assert(scoped_reenable_after_generic_disable.ssh_cbc_disabled == false,
        "Expected backend-specific CBC re-enablement to override a generic SSH CBC disablement")

    local cipher_reset = inspect_content(table.concat({
        "cipher = AES-256-CBC",
        "cipher = AES-256-GCM",
    }, "\n"))

    assert(cipher_reset.ssh_cbc_disabled == true,
        "Expected later cipher reassignment to replace earlier CBC values")

    local missing_cipher = inspect_content("mac = HMAC-SHA2-256\n")

    assert(missing_cipher.ssh_cbc_disabled == false,
        "Expected missing cipher policy evidence to fail closed")
end
