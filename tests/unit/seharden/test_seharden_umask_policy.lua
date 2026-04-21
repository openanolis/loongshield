local umask_policy = require('seharden.shared.umask_policy')

function test_parse_mask_rejects_invalid_values()
    assert(umask_policy.parse_mask("027") == tonumber("027", 8),
        "Expected octal masks to be parsed")
    assert(umask_policy.parse_mask("invalid") == nil,
        "Expected invalid masks to be rejected")
    assert(umask_policy.parse_mask("") == nil,
        "Expected empty masks to be rejected")
end

function test_classify_handles_octal_and_symbolic_masks()
    local baseline = umask_policy.parse_mask("027")

    assert(umask_policy.classify("027", baseline) == "compliant",
        "Expected the baseline mask to be compliant")
    assert(umask_policy.classify("022", baseline) == "conflict",
        "Expected weaker octal masks to be rejected")
    assert(umask_policy.classify("u=rwx,g=rx,o=", baseline) == "compliant",
        "Expected equivalent symbolic masks to be accepted")
    assert(umask_policy.classify("g-w,o-rwx", baseline) == "compliant",
        "Expected guaranteed-stricter relative masks to be accepted")
    assert(umask_policy.classify("o-rwx", baseline) == "indeterminate",
        "Expected partially-relative masks to remain indeterminate")
end
