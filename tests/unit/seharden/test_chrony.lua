local chrony_probe = require('seharden.probes.chrony')

local function make_reader(content)
    local lines = {}
    for line in (tostring(content or '') .. '\n'):gmatch('(.-)\n') do
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

local function with_fake_fs(files, dirs, fn, opts)
    files = files or {}
    dirs = dirs or {}
    opts = opts or {}
    local unreadable = opts.unreadable or {}
    local open_counts = opts.open_counts
    chrony_probe._test_set_dependencies({
        io_open = function(path, mode)
            assert(mode == 'r', 'Expected chrony probe to open files read-only')
            if open_counts then
                open_counts[path] = (open_counts[path] or 0) + 1
            end
            if unreadable[path] then
                return nil, 'Permission denied'
            end
            if files[path] == nil then
                return nil, 'No such file or directory'
            end
            return make_reader(files[path])
        end,
        lfs_attributes = function(path)
            if files[path] ~= nil or unreadable[path] then
                return { mode = 'file' }
            end
            if dirs[path] ~= nil then
                return { mode = 'directory' }
            end
            return nil
        end,
        lfs_dir = function(path)
            local entries = assert(dirs[path], 'Unexpected directory: ' .. tostring(path))
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
    })

    local ok, err = pcall(fn)
    chrony_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

local function assert_list_equals(actual, expected, message)
    assert(#actual == #expected, message .. ': expected ' .. #expected .. ' item(s), got ' .. #actual)
    for index, value in ipairs(expected) do
        assert(actual[index] == value, message .. ': mismatch at index ' .. index)
    end
end

function test_inspect_configuration_finds_server_and_pool_directives()
    with_fake_fs({
        ['/etc/chrony.conf'] = table.concat({
            '# pool ignored.example',
            'server time-a.example iburst',
            'pool: time.example maxsources 4',
            'OPTIONS="-u root"',
        }, '\n'),
    }, {}, function()
        local result = chrony_probe.inspect_configuration({
            config_paths = { '/etc/chrony.conf' },
            sysconfig_path = '/etc/sysconfig/chronyd',
        })

        assert(result.config_available == true, 'Expected readable chrony.conf to be available')
        assert(result.has_time_source == true, 'Expected active server/pool directives to satisfy time source check')
        assert(result.source_count == 2, 'Expected both server and pool directives to be reported')
        assert(result.runs_as_root == false, 'Expected OPTIONS in chrony.conf not to be treated as sysconfig')
    end)
end

function test_inspect_configuration_follows_confdir_sourcedir_and_globs()
    local open_counts = {}
    with_fake_fs({
        ['/etc/chrony.conf'] = table.concat({
            'confdir /etc/chrony.d',
            'confdir /etc/chrony.d',
            'sourcedir /etc/sources.d/*.sources',
        }, '\n'),
        ['/etc/chrony.d/05-extra.conf'] = 'pool extra.example iburst\n',
        ['/etc/chrony.d/10-local.conf'] = 'server local.example iburst\n',
        ['/etc/chrony.d/20-nested.conf'] = 'sourcedir /etc/nested.d/*.sources\n',
        ['/etc/nested.d/40-nested.sources'] = 'server nested.example iburst\n',
        ['/etc/sources.d/60-sources.sources'] = 'pool pool.example iburst maxsources 4\n',
        ['/etc/sysconfig/chronyd'] = 'OPTIONS="-F 2"\n',
    }, {
        ['/etc/chrony.d'] = { '.', '..', '20-nested.conf', '10-local.conf', '05-extra.conf' },
        ['/etc/nested.d'] = { '.', '..', '40-nested.sources' },
        ['/etc/sources.d'] = { '.', '..', '60-sources.sources', 'README' },
    }, function()
        local result = chrony_probe.inspect_configuration({
            config_paths = { '/etc/chrony.conf' },
            sysconfig_path = '/etc/sysconfig/chronyd',
        })

        assert(result.config_available == true, 'Expected included chrony config files to be readable')
        assert(result.source_count == 4, 'Expected sources from confdir, nested sourcedir, and sourcedir globs')
        assert(result.has_time_source == true, 'Expected included sources to satisfy chrony configuration')
        assert_list_equals(result.config_files, {
            '/etc/chrony.conf',
            '/etc/chrony.d/05-extra.conf',
            '/etc/chrony.d/10-local.conf',
            '/etc/chrony.d/20-nested.conf',
            '/etc/nested.d/40-nested.sources',
            '/etc/sources.d/60-sources.sources',
        }, 'Expected stable sorted config file list')
    end, {
        open_counts = open_counts,
    })

    assert(open_counts['/etc/chrony.conf'] == 1, 'Expected root config to be read once')
    assert(open_counts['/etc/chrony.d/05-extra.conf'] == 1, 'Expected included config to be read once')
    assert(open_counts['/etc/chrony.d/10-local.conf'] == 1, 'Expected included config to be read once')
    assert(open_counts['/etc/chrony.d/20-nested.conf'] == 1, 'Expected nested include config to be read once')
    assert(open_counts['/etc/nested.d/40-nested.sources'] == 1, 'Expected nested source file to be read once')
    assert(open_counts['/etc/sources.d/60-sources.sources'] == 1, 'Expected source file to be read once')
    assert(open_counts['/etc/sysconfig/chronyd'] == 1, 'Expected sysconfig to be read once')
end

function test_inspect_configuration_fails_closed_without_readable_sources()
    with_fake_fs({}, {}, function()
        local result = chrony_probe.inspect_configuration({
            config_paths = { '/etc/chrony.conf' },
            sysconfig_path = '/etc/sysconfig/chronyd',
        })

        assert(result.config_available == false, 'Expected missing chrony configuration to be unavailable')
        assert(result.source_count == 0, 'Expected missing config to report no time sources')
        assert(result.has_time_source == false, 'Expected missing time source evidence to fail closed')
    end)
end

function test_inspect_configuration_reports_unreadable_config_files()
    with_fake_fs({
        ['/etc/chrony.conf'] = 'confdir /etc/chrony.d\n',
        ['/etc/sysconfig/chronyd'] = 'OPTIONS="-F 2"\n',
    }, {
        ['/etc/chrony.d'] = { '.', '..', '10-local.conf' },
    }, function()
        local result = chrony_probe.inspect_configuration({
            config_paths = { '/etc/chrony.conf' },
            sysconfig_path = '/etc/sysconfig/chronyd',
        })

        assert(result.config_available == false, 'Expected unreadable config to make config unavailable')
        assert(result.unreadable_count == 1, 'Expected unreadable config file to be counted')
        assert(result.source_count == 0, 'Expected unreadable file not to fabricate sources')
        assert_list_equals(result.config_files, {
            '/etc/chrony.conf',
            '/etc/chrony.d/10-local.conf',
        }, 'Expected unreadable discovered file to remain in config file evidence')
    end, {
        unreadable = {
            ['/etc/chrony.d/10-local.conf'] = true,
        },
    })
end

function test_inspect_configuration_detects_chrony_root_user_override()
    with_fake_fs({
        ['/etc/chrony.conf'] = 'server time-a.example iburst\n',
        ['/etc/sysconfig/chronyd'] = table.concat({
            '# OPTIONS="-u root"',
            'OPTIONS="-F 2 -u root"',
        }, '\n'),
    }, {}, function()
        local result = chrony_probe.inspect_configuration({
            config_paths = { '/etc/chrony.conf' },
            sysconfig_path = '/etc/sysconfig/chronyd',
        })

        assert(result.sysconfig_available == true, 'Expected sysconfig availability to be reported')
        assert(result.runs_as_root == true, 'Expected OPTIONS -u root to be detected')
        assert(result.non_root_configured == false, 'Expected root-user override to fail non-root evidence')
    end)
end

function test_inspect_configuration_ignores_non_root_chrony_user_override()
    with_fake_fs({
        ['/etc/chrony.conf'] = 'server time-a.example iburst\n',
        ['/etc/sysconfig/chronyd'] = 'OPTIONS="-F 2 -u chrony"\n',
    }, {}, function()
        local result = chrony_probe.inspect_configuration({
            config_paths = { '/etc/chrony.conf' },
            sysconfig_path = '/etc/sysconfig/chronyd',
        })

        assert(result.runs_as_root == false, 'Expected OPTIONS -u chrony not to fail the root-user check')
        assert(result.non_root_configured == true, 'Expected readable non-root sysconfig to satisfy non-root evidence')
    end)
end

function test_inspect_configuration_fails_non_root_check_without_sysconfig_evidence()
    with_fake_fs({
        ['/etc/chrony.conf'] = 'server time-a.example iburst\n',
    }, {}, function()
        local result = chrony_probe.inspect_configuration({
            config_paths = { '/etc/chrony.conf' },
            sysconfig_path = '/etc/sysconfig/chronyd',
        })

        assert(result.sysconfig_available == false, 'Expected missing chronyd sysconfig to be reported')
        assert(result.runs_as_root == false, 'Expected missing sysconfig not to fabricate a root override')
        assert(
            result.non_root_configured == false,
            'Expected missing sysconfig evidence to fail the non-root configuration check'
        )
    end)
end
