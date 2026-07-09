local crypto_policy = require('seharden.shared.crypto_policy')

function test_crypto_policy_parse_policy_string_splits_base_and_subpolicies()
    local base, subpolicies = crypto_policy.parse_policy_string(' DEFAULT : NO-SHA1 : NO-WEAK-MACS ')

    assert(base == 'DEFAULT', 'Expected base policy to be parsed')
    assert(subpolicies[1] == 'NO-SHA1', 'Expected first subpolicy to be parsed')
    assert(subpolicies[2] == 'NO-WEAK-MACS', 'Expected second subpolicy to be parsed')
    assert(subpolicies[3] == nil, 'Expected exactly two subpolicies')
end

function test_crypto_policy_effective_policy_uses_bare_base_requests_exactly()
    local effective = crypto_policy.build_effective_policy('DEFAULT', 'LEGACY:NO-WEAK-MACS')

    assert(effective == 'DEFAULT', 'Expected bare base-policy request to switch away from current base exactly')
end

function test_crypto_policy_effective_policy_preserves_stronger_current_base_for_default_subpolicies()
    local effective = crypto_policy.build_effective_policy('DEFAULT:NO-SHA1', 'FIPS:NO-WEAK-MACS')

    assert(
        effective == 'FIPS:NO-WEAK-MACS:NO-SHA1',
        'Expected DEFAULT subpolicy request to preserve non-LEGACY current base'
    )
end

function test_crypto_policy_effective_policy_switches_legacy_base_and_deduplicates_subpolicies()
    local effective = crypto_policy.build_effective_policy('DEFAULT:NO-SHA1:NO-WEAK-MACS', 'LEGACY:NO-SHA1')

    assert(
        effective == 'DEFAULT:NO-SHA1:NO-WEAK-MACS',
        'Expected LEGACY base to switch to DEFAULT while preserving and deduplicating subpolicies'
    )
end
