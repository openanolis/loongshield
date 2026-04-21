local pam_parser = require('seharden.parsers.pam')

function test_pam_parser_handles_bracketed_controls()
    local entry = pam_parser.parse_line("auth [success=1 default=ignore] pam_unix.so try_first_pass nullok")

    assert(entry ~= nil, "Expected bracketed PAM control syntax to be parsed")
    assert(entry.kind == "auth", "Expected the PAM parser to preserve the stack kind")
    assert(entry.control == "[success=1 default=ignore]",
        "Expected the PAM parser to preserve bracketed control expressions")
    assert(entry.module == "pam_unix.so", "Expected the PAM parser to preserve the module name")
    assert(#entry.args == 2 and entry.args[1] == "try_first_pass" and entry.args[2] == "nullok",
        "Expected the PAM parser to split trailing module arguments into tokens")
end
