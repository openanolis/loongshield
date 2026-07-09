local dotfiles = require('seharden.shared.dotfiles')

function test_dotfile_policy_helpers_cover_shared_policy()
    assert(dotfiles.basename('/home/alice/.netrc') == '.netrc', 'Expected basename extraction')
    assert(dotfiles.is_forbidden('.forward') == true, 'Expected .forward to be forbidden')
    assert(dotfiles.is_forbidden('.bashrc') == false, 'Expected .bashrc to be allowed')
    assert(dotfiles.max_mode_for('.netrc') == tonumber('600', 8), 'Expected strict .netrc mode')
    assert(dotfiles.max_mode_for('.profile') == tonumber('644', 8), 'Expected default dotfile mode')
    assert(dotfiles.is_dot_entry('.profile') == true, 'Expected dot entries to be detected')
    assert(dotfiles.is_dot_entry('Documents') == false, 'Expected non-dot entries to be ignored')
    assert(dotfiles.same_device_or_unknown({ dev = 10 }, 10) == true, 'Expected same device to pass')
    assert(dotfiles.same_device_or_unknown({ dev = 11 }, 10) == false, 'Expected different device to fail')
    assert(dotfiles.same_device_or_unknown({ mode = 'file' }, 10) == true, 'Expected unknown device to pass')
end
