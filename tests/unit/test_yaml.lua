local assert = assert
local lyaml = require('lyaml')

local T = {}
function T.setup() end

function T.teardown() end

-- ==================== Test Cases ====================

function test_yaml_can_be_required_and_has_load_function()
    T.setup()
    assert(type(lyaml) == "table", "require('lyaml') should return a table")
    assert(type(lyaml.load) == "function", "lyaml.load should be a function")
    T.teardown()
end

function test_yaml_parses_simple_map()
    T.setup()
    local yaml_string = "name: loongshield\nversion: 1.0"
    local data = lyaml.load(yaml_string)

    assert(type(data) == "table", "Parsed result should be a table")
    assert(data.name == "loongshield", "Incorrect value for key 'name'")
    assert(data.version == 1.0, "Incorrect value for key 'version'")
    T.teardown()
end

function test_yaml_parses_list()
    T.setup()
    local yaml_string = "- bash\n- nginx\n- sshd"
    local data = lyaml.load(yaml_string)

    assert(type(data) == "table", "Parsed result should be a table")
    assert(#data == 3, "List should have 3 items")
    assert(data[2] == "nginx", "Incorrect value at index 2")
    T.teardown()
end

function test_yaml_handles_invalid_syntax_gracefully()
    T.setup()
    local invalid_yaml = "key: value: this is not valid yaml"

    local ok, err = pcall(lyaml.load, invalid_yaml)

    assert(not ok, "lyaml.load should have failed on invalid syntax")
    assert(type(err) == 'string', "The error message should be a string")
    T.teardown()
end
