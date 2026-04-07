local xattr = require('xattr')

local T = {}
T.TEST_FILE = "/tmp/loongshield_xattr_test.txt"

function T.setup()
    local f = io.open(T.TEST_FILE, "w")
    assert(f, "Failed to create test file")
    f:write("hello xattr")
    f:close()

    T.file = xattr.new(T.TEST_FILE)
    assert(T.file, "xattr.new() failed")
end

function T.teardown()
    os.remove(T.TEST_FILE)
end

-- ==================== Test Cases ====================

function test_xattr_can_set_and_get_attribute()
    T.setup()

    local ok, err = T.file:set("user.author", "TestUser")
    assert(ok, "Failed to set attribute: " .. tostring(err))

    local value = T.file:get("user.author")
    assert(value == "TestUser", "Got incorrect attribute value")

    local non_existent = T.file:get("user.non_existent")
    assert(non_existent == nil, "Expected nil for non-existent attribute")

    T.teardown()
end

function test_xattr_can_list_attributes()
    T.setup()

    T.file:set("user.author", "TestUser")
    T.file:set("user.project", "Loongshield")

    local list = T.file:list()
    assert(type(list) == "table", "list() should return a table")
    assert(#list == 2, "Expected 2 attributes in the list")

    local found = {}
    for _, name in ipairs(list) do
        found[name] = true
    end
    assert(
        found["user.author"] and found["user.project"],
        "List did not contain all set attributes"
    )

    T.teardown()
end

function test_xattr_can_remove_attribute()
    T.setup()

    T.file:set("user.to_be_deleted", "temporary")

    assert(
        T.file:get("user.to_be_deleted") == "temporary",
        "Attribute was not set correctly before removal"
    )

    local ok, err = T.file:remove("user.to_be_deleted")
    assert(ok, "Failed to remove attribute: " .. tostring(err))

    assert(
        T.file:get("user.to_be_deleted") == nil,
        "Attribute still exists after removal"
    )

    assert(#T.file:list() == 0, "List should be empty after removal")

    T.teardown()
end

function test_xattr_flags_work_correctly()
    T.setup()

    local ok_create, err_create = T.file:set("user.comment", "A new comment", xattr.CREATE)
    assert(ok_create, "CREATE flag failed on new attribute: " .. tostring(err_create))

    local ok_create_fail, err_create_fail = T.file:set("user.comment", "Another comment", xattr.CREATE)
    assert(not ok_create_fail, "CREATE flag should have failed on an existing attribute")

    local ok_replace, err_replace = T.file:set("user.comment", "Replaced comment", xattr.REPLACE)
    assert(ok_replace, "REPLACE flag failed on existing attribute: " .. tostring(err_replace))
    assert(T.file:get("user.comment") == "Replaced comment", "Value was not replaced correctly")

    local ok_replace_fail, err_replace_fail = T.file:set("user.new_attr", "some value", xattr.REPLACE)
    assert(not ok_replace_fail, "REPLACE flag should have failed on a new attribute")

    T.teardown()
end
