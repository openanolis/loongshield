local distribute = require('lua_lsm.distribute')

local function assert_contains(haystack, needle)
    assert(tostring(haystack):find(needle, 1, true), 'Expected text to contain: ' .. needle)
end

function test_lua_lsm_distribute_safe_name_rules()
    assert(distribute.is_safe_name('policy.lua'))
    assert(distribute.is_safe_name('policies/01-deny.lua'))
    assert(distribute.is_safe_name('sm2.pub'))
    assert(distribute.is_safe_name('policies.d/sub-dir_1/x.pub'))

    assert(not distribute.is_safe_name(''))
    assert(not distribute.is_safe_name(nil))
    assert(not distribute.is_safe_name('/absolute.lua'))
    assert(not distribute.is_safe_name('a/..'))
    assert(not distribute.is_safe_name('../escape.lua'))
    assert(not distribute.is_safe_name('a/../b.lua'))
    assert(not distribute.is_safe_name('..'))
    assert(not distribute.is_safe_name('.'))
    assert(not distribute.is_safe_name('a//b.lua'))
    assert(not distribute.is_safe_name('a/'))
    assert(not distribute.is_safe_name('a\\b.lua'))
    assert(not distribute.is_safe_name('a b.lua'))
    assert(not distribute.is_safe_name('a\0b.lua'))
end

function test_lua_lsm_distribute_list_files_uses_allowlist_and_skips_symlinks()
    local base = os.getenv('TMPDIR') or '/tmp'
    local root = base
        .. '/loongshield_distribute_test.'
        .. tostring(os.time())
        .. '.'
        .. tostring(math.random(10000, 99999))
    os.execute('rm -rf ' .. root)
    assert(os.execute('mkdir -p ' .. root .. '/policies'))

    local function write(path, content)
        local file = assert(io.open(path, 'wb'))
        file:write(content)
        file:close()
    end

    write(root .. '/policies/01-deny.lua', 'return {}')
    write(root .. '/sm2.pub', 'public key')
    write(root .. '/private.pem', 'private key material')
    write(root .. '/secret.KEY', 'private key material')
    assert(os.execute('ln -s ' .. root .. '/private.pem ' .. root .. '/leak.pub'))
    assert(os.execute('ln -s ' .. root .. ' ' .. root .. '/self-loop'))

    local files = distribute.list_files(root)

    local names = {}
    for _, file in ipairs(files) do
        names[file.name] = true
    end

    assert(names['policies/01-deny.lua'], 'Expected lua policy in index')
    assert(names['sm2.pub'], 'Expected public key in index')
    assert(not names['private.pem'], 'Private key must not be indexed')
    assert(not names['secret.KEY'], 'Non-allowlisted extension must not be indexed')
    assert(not names['leak.pub'], 'Symlink must not be indexed')
    assert(not names['self-loop'], 'Directory symlink must not be indexed')

    os.execute('rm -rf ' .. root)
end

function test_lua_lsm_distribute_validate_index_rejects_unsafe_entries()
    local count, err = distribute.validate_index({
        files = {
            { name = 'policies/01.lua' },
            { name = 'sm2.pub' },
        },
    })
    assert(count == 2, 'Expected valid index to pass: ' .. tostring(err))

    count, err = distribute.validate_index({ files = { { name = '../../etc/cron.d/x' } } })
    assert(count == nil, 'Expected traversal to be rejected')
    assert_contains(err, 'unsafe file name')

    count, err = distribute.validate_index({ files = { { name = 'a.lua' }, { name = 'a.lua' } } })
    assert(count == nil, 'Expected duplicates to be rejected')
    assert_contains(err, 'duplicate')

    count, err = distribute.validate_index({ files = {} })
    assert(count == nil, 'Expected empty index to be rejected')
    assert_contains(err, 'empty')

    count, err = distribute.validate_index({ files = { { name = 'a.lua' }, nil, { name = 'b.lua' } } })
    assert(count == nil, 'Expected holes to be rejected')

    count, err = distribute.validate_index({ files = { { name = 'a.lua' }, extra = 1 } })
    assert(count == nil, 'Expected non-array keys to be rejected')

    count, err = distribute.validate_index({ files = 'not-a-table' })
    assert(count == nil, 'Expected non-table files to be rejected')
end
