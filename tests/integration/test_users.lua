local users_probe = require('seharden.probes.users')
local lfs = require('lfs')
local T = {}

T.TEST_PASSWD = "/tmp/loongshield_users_probe_test_passwd.txt"
T.TEST_USER_HOME = "/tmp/loongshield_test_home"
T.TEST_FILENAME = ".testfile"

function T.setup(passwd_content, create_files)
    local f = io.open(T.TEST_PASSWD, "w")
    assert(f, "Failed to create test passwd file: " .. T.TEST_PASSWD)
    f:write(passwd_content)
    f:close()

    users_probe._test_set_dependencies({
        passwd_path = T.TEST_PASSWD,
    })

    lfs.mkdir(T.TEST_USER_HOME)
    if create_files then
        for user, _ in pairs(create_files) do
            local user_dir = T.TEST_USER_HOME .. "/" .. user
            lfs.mkdir(user_dir)
            local file_path = user_dir .. "/" .. T.TEST_FILENAME
            local file = io.open(file_path, "w")
            assert(file, "Failed to create test file: " .. file_path)
            file:close()
        end
    end
end

function T.teardown()
    users_probe._test_set_dependencies()
    os.remove(T.TEST_PASSWD)
    for file in lfs.dir(T.TEST_USER_HOME) do
        if file ~= "." and file ~= ".." then
            local user_dir = T.TEST_USER_HOME .. "/" .. file
            os.remove(user_dir .. "/" .. T.TEST_FILENAME)
            lfs.rmdir(user_dir)
        end
    end
    lfs.rmdir(T.TEST_USER_HOME)
end

function test_missing_filename_param()
    local result, err = users_probe.find_files({})
    assert(result == nil, "Expected result to be nil when filename is missing")
    assert(err == "Probe 'users.find_files' requires a 'filename' parameter.", "Incorrect error message")
end

function test_no_real_users()
    local passwd_content = [[
# Comment
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nfsnobody:x:65534:65534:nfsnobody:/var/lib/nfs:/sbin/nologin
]]
    T.setup(passwd_content)

    local params = { filename = T.TEST_FILENAME }
    local result = users_probe.find_files(params)

    assert(result.count == 0, "Expected count to be 0 when no real users")
    assert(type(result.details) == "table", "Details should be a table")
    assert(#result.details == 0, "Details table should be empty")

    T.teardown()
end

function test_real_users_no_files()
    local passwd_content = [[
root:x:0:0:root:/root:/bin/bash
user1:x:1001:1001:user1:/home/user1:/bin/bash
user2:x:1002:1002:user2:/home/user2:/bin/bash
]]
    T.setup(passwd_content)

    local params = { filename = T.TEST_FILENAME }
    local result = users_probe.find_files(params)

    assert(result.count == 0, "Expected count to be 0 when no files exist")
    assert(#result.details == 0, "Details table should be empty")

    T.teardown()
end

function test_ignore_non_files()
    local passwd_content = [[
user1:x:1001:1001:user1:]] .. T.TEST_USER_HOME .. [[/user1:/bin/bash
]]
    T.setup(passwd_content)

    lfs.mkdir(T.TEST_USER_HOME .. "/user1/" .. T.TEST_FILENAME)

    local params = { filename = T.TEST_FILENAME }
    local result = users_probe.find_files(params)

    assert(result.count == 0, "Expected count to be 0 for non-file")
    assert(#result.details == 0, "Details table should be empty")

    lfs.rmdir(T.TEST_USER_HOME .. "/user1/" .. T.TEST_FILENAME)
    T.teardown()
end

function test_cannot_open_passwd()
    users_probe._test_set_dependencies({
        passwd_path = T.TEST_PASSWD,
    })
    os.remove(T.TEST_PASSWD)
    local params = { filename = T.TEST_FILENAME }
    local result, err = users_probe.find_files(params)

    assert(result == nil, "Expected passwd read failures to be surfaced")
    assert(err:find(T.TEST_PASSWD, 1, true), "Expected error to mention the unreadable passwd path")
    users_probe._test_set_dependencies()
end

function test_sanitizes_filename_path_traversal()
    local passwd_content = [[
user1:x:1001:1001:user1:]] .. T.TEST_USER_HOME .. [[/user1:/bin/bash
]]
    T.setup(passwd_content)

    local result, err = users_probe.find_files({ filename = "../.netrc" })
    assert(err == nil, "Expected no error for sanitized filename")
    assert(result.count == 0, "Expected count 0 for sanitized filename")
    T.teardown()
end

return T
