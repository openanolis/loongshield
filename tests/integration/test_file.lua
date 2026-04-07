local file_probe = require('seharden.probes.file')
local lfs = require('lfs')
local T = {}

T.TEST_FILE = "/tmp/loongshield_file_probe_test.txt"

function T.setup(content)
    local f = assert(io.open(T.TEST_FILE, "w"), "Failed to create test file: " .. T.TEST_FILE)
    if content then
        f:write(content)
    end
    f:close()
end

function T.teardown()
    os.remove(T.TEST_FILE)
end

function test_find_duplicate_no_duplicates_found()
    local file_content = [[
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
]]
    T.setup(file_content)
    local result = file_probe.find_duplicate_values_in_field({
        path = T.TEST_FILE,
        field_index = 3,
        key_name = "uid",
        value_index = 1
    })
    assert(result.count == 0, "Expected duplicate count to be 0")
    assert(#result.details == 0, "Details table should be empty")
    T.teardown()
end

function test_find_duplicate_single_duplicate_uid()
    local file_content = [[
root:x:0:0:root:/root:/bin/bash
userA:x:1001:1000::/home/userA:/bin/bash
userB:x:1001:1001::/home/userB:/bin/bash
userC:x:1002:1002::/home/userC:/bin/bash
]]
    T.setup(file_content)
    local result = file_probe.find_duplicate_values_in_field({
        path = T.TEST_FILE,
        field_index = 3,
        key_name = "uid",
        value_index = 1
    })
    assert(result.count == 1, "Expected duplicate count to be 1")
    assert(result.details[1].uid == 1001, "Incorrect duplicate UID found")
    T.teardown()
end

function test_find_duplicate_can_filter_to_specific_key()
    local file_content = [[
root:x:0:0:root:/root:/bin/bash
userA:x:1001:1000::/home/userA:/bin/bash
userB:x:1001:1001::/home/userB:/bin/bash
]]
    T.setup(file_content)
    local result = file_probe.find_duplicate_values_in_field({
        path = T.TEST_FILE,
        field_index = 3,
        match_key = 0,
        key_name = "uid",
        value_index = 1
    })
    assert(result.count == 0, "Expected non-target duplicate keys to be ignored")
    T.teardown()
end

function test_find_duplicate_ignores_malformed_lines()
    local file_content = [[
# This is a comment
userA:x:1001:1000::/home/userA:/bin/bash
userB:x:1001:1001::/home/userB:/bin/bash
malformedline
]]
    T.setup(file_content)
    local result = file_probe.find_duplicate_values_in_field({
        path = T.TEST_FILE,
        field_index = 3,
        key_name = "uid",
        value_index = 1
    })
    assert(result.count == 1, "Expected to find exactly one set of duplicates")
    assert(result.details[1].uid == 1001, "The wrong duplicate was identified")
    T.teardown()
end

function test_find_duplicate_handles_non_existent_file()
    os.remove(T.TEST_FILE)
    local result, err = file_probe.find_duplicate_values_in_field({
        path = T.TEST_FILE,
        field_index = 3,
        key_name = "uid",
        value_index = 1
    })
    assert(result == nil, "Expected unreadable duplicate-check file to fail")
    assert(err:find(T.TEST_FILE, 1, true), "Expected error to mention the unreadable file path")
end

local PatternTestHelper = {}
PatternTestHelper.TEST_ROOT = "/tmp/loongshield_pattern_probe_test"

function PatternTestHelper.setup(files_to_create)
    os.execute("rm -rf " .. PatternTestHelper.TEST_ROOT)
    assert(lfs.mkdir(PatternTestHelper.TEST_ROOT), "Failed to create test root")
    if files_to_create then
        for filename, content in pairs(files_to_create) do
            local dir_path = filename:match("^(.*)/")
            if dir_path then
                os.execute("mkdir -p " .. PatternTestHelper.TEST_ROOT .. "/" .. dir_path)
            end
            local f = assert(io.open(PatternTestHelper.TEST_ROOT .. "/" .. filename, "w"))
            f:write(content)
            f:close()
        end
    end
end

function PatternTestHelper.teardown()
    os.execute("rm -rf " .. PatternTestHelper.TEST_ROOT)
end

function test_find_pattern_successfully()
    PatternTestHelper.setup({ ["sudoers"] = "Defaults use_pty" })
    local result = file_probe.find_pattern({
        paths = { PatternTestHelper.TEST_ROOT .. "/sudoers" },
        pattern = "^Defaults use_pty"
    })
    assert(result.found == true, "Expected pattern to be found")
    PatternTestHelper.teardown()
end

function test_find_pattern_handles_case_insensitive()
    PatternTestHelper.setup({ ["sshd_config"] = "MaxAuthTries 4" })
    local result = file_probe.find_pattern({
        paths = { PatternTestHelper.TEST_ROOT .. "/sshd_config" },
        pattern = "(?i)^maxauthtries"
    })
    assert(result.found == true, "Expected case-insensitive pattern to be found")
    PatternTestHelper.teardown()
end

function test_find_pattern_supports_regex_alternation()
    PatternTestHelper.setup({ ["crypto"] = "FUTURE\n" })
    local result = file_probe.find_pattern({
        paths = { PatternTestHelper.TEST_ROOT .. "/crypto" },
        pattern = "(?i)^(FUTURE|FIPS)"
    })
    assert(result.found == true, "Expected alternation pattern to be found")
    PatternTestHelper.teardown()
end

function test_find_pattern_ignores_glob_expansion_under_regular_file()
    PatternTestHelper.setup({ ["single"] = "content" })
    local ok, result = pcall(file_probe.find_pattern, {
        paths = { PatternTestHelper.TEST_ROOT .. "/single/*" },
        pattern = "content"
    })
    assert(ok, "Expected find_pattern to ignore non-directory glob bases")
    assert(result.found == false, "Expected no matches when glob base is a regular file")
    PatternTestHelper.teardown()
end

function test_parse_key_values_handles_equals_and_whitespace()
    T.setup([[
# Comment line
KEY=value
OTHER = spaced
KEY2    value2
]])
    local result = file_probe.parse_key_values({ path = T.TEST_FILE })
    assert(result.KEY == "value", "Expected KEY=value to be parsed")
    assert(result.OTHER == "spaced", "Expected 'OTHER = spaced' to be parsed")
    assert(result.KEY2 == "value2", "Expected 'KEY2    value2' to be parsed")
    T.teardown()
end

function test_parse_key_values_strips_inline_comments()
    T.setup([[
UMASK 027 # login.defs comment
max_log_file = 8 # auditd comment
quoted = "value # keep"
]])
    local result = file_probe.parse_key_values({ path = T.TEST_FILE })

    assert(result.UMASK == "027", "Expected inline comments to be stripped from whitespace-delimited values")
    assert(result.max_log_file == "8", "Expected inline comments to be stripped from key=value pairs")
    assert(result.quoted == "value # keep", "Expected quoted # characters to be preserved")
    T.teardown()
end

function test_parse_key_values_can_normalize_values_to_lowercase()
    T.setup([[
max_log_file_action = ROTATE
space_left_action = SYSLOG
]])
    local result = file_probe.parse_key_values({
        path = T.TEST_FILE,
        normalize_values = "lower"
    })

    assert(result.max_log_file_action == "rotate", "Expected parsed values to be normalized to lowercase")
    assert(result.space_left_action == "syslog", "Expected uppercase auditd.conf values to compare case-insensitively")
    T.teardown()
end

function test_parse_key_values_handles_unreadable_file()
    os.remove(T.TEST_FILE)

    local result, err = file_probe.parse_key_values({ path = T.TEST_FILE })

    assert(result == nil, "Expected unreadable key-value file to fail")
    assert(err:find(T.TEST_FILE, 1, true), "Expected error to mention the unreadable file path")
end
