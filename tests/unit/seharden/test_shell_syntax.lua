local shell_syntax = require('seharden.shared.shell_syntax')

function test_shell_syntax_strips_trailing_comments_and_trims()
    assert(shell_syntax.strip_comment('  export TMOUT=900   # comment ') == 'export TMOUT=900')
    assert(shell_syntax.strip_comment('   # TMOUT=0') == '')
end

function test_shell_syntax_detects_tmout_unset_commands()
    assert(shell_syntax.line_unsets_tmout('echo ok; unset TMOUT') == true)
    assert(shell_syntax.line_unsets_tmout('unset OTHER; TMOUT=900') == false)
end

function test_shell_syntax_detects_tmout_readonly_export_and_values()
    local typeset_line = 'typeset -xr TMOUT=900'
    assert(shell_syntax.line_sets_tmout_readonly(typeset_line) == true)
    assert(shell_syntax.line_sets_tmout_export(typeset_line) == true)

    assert(shell_syntax.line_sets_tmout_readonly('readonly HISTSIZE TMOUT') == true)
    assert(shell_syntax.line_sets_tmout_export('export PATH TMOUT') == true)

    local values = shell_syntax.tmout_values_from_line('TMOUT=900; export TMOUT; TMOUT=1200')
    assert(values[1] == 900, 'Expected first TMOUT value')
    assert(values[2] == 1200, 'Expected second TMOUT value')
    assert(values[3] == nil, 'Expected exactly two TMOUT values')
end

function test_shell_syntax_detects_tmout_word_boundaries()
    assert(shell_syntax.line_mentions_tmout('export TMOUT=900') == true)
    assert(shell_syntax.line_mentions_tmout('export MYTMOUT=900') == false)
end
