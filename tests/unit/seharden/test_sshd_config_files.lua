local sshd_config_files = require('seharden.shared.sshd_config_files')

local function make_reader(lines)
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

local function make_deps(files, dirs)
    return {
        lfs_attributes = function(path)
            if files[path] then
                return { mode = 'file' }
            end
            if dirs[path] then
                return { mode = 'directory' }
            end
            return nil
        end,
        lfs_dir = function(path)
            local entries = dirs[path] or {}
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == 'r', 'Expected sshd config discovery to read files')
            local lines = files[path]
            if not lines then
                return nil
            end
            return make_reader(lines)
        end,
    }
end

function test_sshd_config_parse_directive_strips_comments_and_preserves_case()
    local key, value = sshd_config_files.parse_directive('  Include /etc/ssh/*.conf # trailing comment')
    assert(key == 'Include', 'Expected directive key casing to be preserved')
    assert(value == '/etc/ssh/*.conf', 'Expected directive value before trailing comment')

    key, value = sshd_config_files.parse_directive('   # Include /ignored.conf')
    assert(key == nil and value == nil, 'Expected comment-only lines to produce no directive')

    key, value = sshd_config_files.parse_directive('PasswordAuthentication no')
    assert(key == 'PasswordAuthentication', 'Expected directive key to parse without leading whitespace')
    assert(value == 'no', 'Expected directive value to parse without trailing comment')
end

function test_sshd_config_discovery_preserves_traversal_order_and_deduplicates()
    local files = {
        ['/etc/ssh/sshd_config'] = {
            '# Include /ignored/*.conf',
            'Include /opt/ssh/*.conf # trailing comment',
            'Include relative.conf',
        },
        ['/etc/ssh/sshd_config.d/10-hardening.conf'] = {},
        ['/opt/ssh/custom.conf'] = {
            'Include /etc/ssh/sshd_config.d/10-hardening.conf',
        },
        ['/etc/ssh/relative.conf'] = {},
    }
    local dirs = {
        ['/etc/ssh/sshd_config.d'] = { '.', '..', '10-hardening.conf' },
        ['/opt/ssh'] = { '.', '..', 'custom.conf' },
    }
    local deps = make_deps(files, dirs)

    local result = sshd_config_files.discover({
        path = '/etc/ssh/sshd_config',
        include_dir = '/etc/ssh/sshd_config.d',
        base_dir = '/etc/ssh',
        io_open = deps.io_open,
        lfs_attributes = deps.lfs_attributes,
        lfs_dir = deps.lfs_dir,
    })

    assert(result[1] == '/etc/ssh/sshd_config', 'Expected main config first')
    assert(result[2] == '/etc/ssh/sshd_config.d/10-hardening.conf', 'Expected default drop-in second')
    assert(result[3] == '/opt/ssh/custom.conf', 'Expected Include target after seeded files')
    assert(result[4] == '/etc/ssh/relative.conf', 'Expected relative Include to resolve from base_dir')
    assert(result[5] == nil, 'Expected duplicate Include target to be returned once')
end

function test_sshd_config_discovery_can_sort_result_for_probe_evidence()
    local files = {
        ['/etc/ssh/sshd_config'] = {
            'Include /opt/ssh/*.conf',
        },
        ['/etc/ssh/sshd_config.d/90-last.conf'] = {},
        ['/opt/ssh/20-middle.conf'] = {},
    }
    local dirs = {
        ['/etc/ssh/sshd_config.d'] = { '.', '..', '90-last.conf' },
        ['/opt/ssh'] = { '.', '..', '20-middle.conf' },
    }
    local deps = make_deps(files, dirs)

    local result = sshd_config_files.discover({
        path = '/etc/ssh/sshd_config',
        include_dir = '/etc/ssh/sshd_config.d',
        base_dir = '/etc/ssh',
        io_open = deps.io_open,
        lfs_attributes = deps.lfs_attributes,
        lfs_dir = deps.lfs_dir,
        sort_result = true,
    })

    assert(result[1] == '/etc/ssh/sshd_config', 'Expected sorted result to preserve lexical order')
    assert(result[2] == '/etc/ssh/sshd_config.d/90-last.conf', 'Expected sorted drop-in path before /opt path')
    assert(result[3] == '/opt/ssh/20-middle.conf', 'Expected sorted external include last')
end

function test_sshd_config_discovery_returns_empty_when_main_and_dropins_are_missing()
    local deps = make_deps({}, {})

    local result = sshd_config_files.discover({
        path = '/etc/ssh/sshd_config',
        include_dir = '/etc/ssh/sshd_config.d',
        io_open = deps.io_open,
        lfs_attributes = deps.lfs_attributes,
        lfs_dir = deps.lfs_dir,
    })

    assert(#result == 0, 'Expected missing config paths to return an empty discovery result')
end
