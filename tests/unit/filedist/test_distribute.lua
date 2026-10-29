local distribute = require('filedist.distribute')

local function assert_contains(haystack, needle)
    assert(tostring(haystack):find(needle, 1, true), 'Expected text to contain: ' .. needle)
end

function test_filedist_distribute_safe_name_rules()
    assert(distribute.is_safe_name('policy.lua'))
    assert(distribute.is_safe_name('policies/01-deny.lua'))
    assert(distribute.is_safe_name('sm2.pub'))
    assert(distribute.is_safe_name('policies.d/sub-dir_1/x.pub'))
    assert(distribute.is_safe_name('ima policy.conf'))

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
    assert(not distribute.is_safe_name('a\0b.lua'))
    assert(not distribute.is_safe_name('a\nb.lua'))
end

function test_filedist_distribute_list_files_serves_any_regular_file()
    local base = os.getenv('TMPDIR') or '/tmp'
    local root = base
        .. '/loongshield_filedist_test.'
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

    write(root .. '/policies/ima-policy', 'measure func=BPRM_CHECK\n')
    write(root .. '/app.conf', 'enabled=true\n')
    write(root .. '/binary.dat', '\0\1\255loongshield')
    assert(os.execute('ln -s /etc/shadow ' .. root .. '/leak.conf'))

    local files = distribute.list_files(root, {
        file_filter = function()
            return true
        end,
    })

    local names = {}
    for _, file in ipairs(files) do
        names[file.name] = true
    end

    assert(names['policies/ima-policy'], 'Expected extensionless file in index')
    assert(names['app.conf'], 'Expected config file in index')
    assert(names['binary.dat'], 'Expected binary file in index')
    assert(not names['leak.conf'], 'Symlink must not be indexed')

    os.execute('rm -rf ' .. root)
end

function test_filedist_distribute_validate_index_rejects_unsafe_entries()
    local all_files = {
        file_filter = function()
            return true
        end,
    }

    local count, err = distribute.validate_index({
        files = {
            { name = 'policies/01.lua' },
            { name = 'sm2.pub' },
        },
    }, all_files)
    assert(count == 2, 'Expected valid index to pass: ' .. tostring(err))

    count, err = distribute.validate_index({ files = { { name = '../../etc/cron.d/x' } } }, all_files)
    assert(count == nil, 'Expected traversal to be rejected')
    assert_contains(err, 'unsafe file name')

    count, err = distribute.validate_index({ files = { { name = 'a.lua' }, { name = 'a.lua' } } }, all_files)
    assert(count == nil, 'Expected duplicates to be rejected')
    assert_contains(err, 'duplicate')

    count, err = distribute.validate_index({ files = {} }, all_files)
    assert(count == nil, 'Expected empty index to be rejected')
    assert_contains(err, 'empty')

    count, err = distribute.validate_index({ files = { { name = 'a.lua' }, nil, { name = 'b.lua' } } }, all_files)
    assert(count == nil, 'Expected holes to be rejected')

    count, err = distribute.validate_index({ files = { { name = 'a.lua' }, extra = 1 } }, all_files)
    assert(count == nil, 'Expected non-array keys to be rejected')

    count, err = distribute.validate_index({ files = 'not-a-table' }, all_files)
    assert(count == nil, 'Expected non-table files to be rejected')

    count, err = distribute.validate_index({ files = { { name = 'secret.txt' } } })
    assert(count == nil, 'Expected missing filter to be rejected')
    assert_contains(err, 'not a distributable file')

    count, err = distribute.validate_index({
        files = { { name = 'secret.txt' } },
    }, all_files)
    assert(count == 1, 'Expected arbitrary file to pass with filedist filter: ' .. tostring(err))
end
