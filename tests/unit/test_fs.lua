local fs = require('fs')

function test_fs_exports_file_attribute_mutators()
    assert(type(fs.chmod) == "function", "Expected fs.chmod to be available")
    assert(type(fs.chown) == "function", "Expected fs.chown to be available")
end
