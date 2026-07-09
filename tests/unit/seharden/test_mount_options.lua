local mount_options = require('seharden.shared.mount_options')

function test_mount_options_parse_returns_ordered_options_and_set()
    local ordered, set = mount_options.parse('rw,nosuid,nodev')

    assert(#ordered == 3, 'Expected three parsed mount options')
    assert(ordered[1] == 'rw', 'Expected option order to be preserved')
    assert(ordered[2] == 'nosuid', 'Expected option order to be preserved')
    assert(ordered[3] == 'nodev', 'Expected option order to be preserved')
    assert(set.rw == true, 'Expected option set to include rw')
    assert(set.nosuid == true, 'Expected option set to include nosuid')
    assert(set.nodev == true, 'Expected option set to include nodev')
end

function test_mount_options_parse_handles_empty_values()
    local ordered, set = mount_options.parse(nil)

    assert(#ordered == 0, 'Expected nil options to produce an empty ordered list')
    assert(next(set) == nil, 'Expected nil options to produce an empty set')
end
