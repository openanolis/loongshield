local comparators = require('seharden.comparators')

function test_mode_is_no_more_permissive_accepts_stricter_modes()
    assert(comparators.mode_is_no_more_permissive(384, 420) == true,
        "Expected 0600 to be accepted as stricter than 0644")
    assert(comparators.mode_is_no_more_permissive(416, 420) == true,
        "Expected 0640 to be accepted as stricter than 0644")
    assert(comparators.mode_is_no_more_permissive(448, 488) == true,
        "Expected 0700 to be accepted as stricter than 0750")
end

function test_mode_is_no_more_permissive_rejects_cross_class_permission_swaps()
    assert(comparators.mode_is_no_more_permissive(400, 420) == false,
        "Expected group write to be rejected even when the numeric value is lower")
    assert(comparators.mode_is_no_more_permissive(310, 420) == false,
        "Expected other write to be rejected")
    assert(comparators.mode_is_no_more_permissive(493, 488) == false,
        "Expected extra execute permission for others to be rejected")
end

function test_mode_is_no_more_permissive_rejects_unexpected_special_bits()
    assert(comparators.mode_is_no_more_permissive(2536, 488) == false,
        "Expected setuid directories to be rejected when the baseline does not allow special bits")
    assert(comparators.mode_is_no_more_permissive(932, 420) == false,
        "Expected sticky files to be rejected when the baseline does not allow special bits")
end

function test_mode_is_no_more_permissive_rejects_invalid_inputs()
    assert(comparators.mode_is_no_more_permissive("bad", 420) == false,
        "Expected invalid actual mode values to be rejected")
    assert(comparators.mode_is_no_more_permissive(420, "bad") == false,
        "Expected invalid expected mode values to be rejected")
end
