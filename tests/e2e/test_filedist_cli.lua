local EXIT_MARKER = '__LOONGSHIELD_FILEDIST_EXIT__:'

local BIN = os.getenv('LOONGSHIELD_E2E_BIN') or os.getenv('LOONGSHIELD_BIN') or 'build/src/daemon/loongshield'

local function shell_escape(arg)
    return "'" .. tostring(arg):gsub("'", "'\\''") .. "'"
end

local function write_file(path, content)
    local file = assert(io.open(path, 'wb'), 'Failed to open file for write: ' .. path)
    file:write(content)
    file:close()
end

local function read_file(path)
    local file = assert(io.open(path, 'rb'), 'Failed to open file for read: ' .. path)
    local content = file:read('*a') or ''
    file:close()
    return content
end

local function file_exists(path)
    local file = io.open(path, 'rb')
    if file then
        file:close()
        return true
    end
    return false
end

local function run_loongshield(args)
    local parts = { shell_escape(BIN) }
    for _, arg in ipairs(args) do
        parts[#parts + 1] = shell_escape(arg)
    end

    local cmd = table.concat(parts, ' ') .. " 2>&1; code=$?; printf '\\n" .. EXIT_MARKER .. '%s\\n\' "$code"'
    local pipe = assert(io.popen(cmd, 'r'), 'Failed to run loongshield')
    local output = pipe:read('*a') or ''
    pipe:close()

    local code = tonumber(output:match(EXIT_MARKER .. '(%d+)\n?$'))
    output = output:gsub('\n?' .. EXIT_MARKER .. '%d+\n?$', '')
    assert(code ~= nil, 'Failed to parse exit code:\n' .. output)
    return code, output
end

local function make_temp_dir()
    local cmd = 'mktemp -d /tmp/loongshield_filedist_cli.XXXXXX'
    local pipe = assert(io.popen(cmd, 'r'), 'Failed to create temp directory')
    local path = (pipe:read('*l') or ''):gsub('%s+$', '')
    assert(pipe:close() and path ~= '', 'Failed to create temp directory')
    return path
end

local function make_tls_certificate(root)
    assert(os.execute('mkdir -p ' .. shell_escape(root)))
    local key = root .. '/tls.key'
    local certificate = root .. '/tls.crt'
    local command = table.concat({
        'openssl req -x509 -newkey rsa:2048 -nodes -days 1',
        '-subj ' .. shell_escape('/CN=localhost'),
        '-addext ' .. shell_escape('subjectAltName=DNS:localhost,IP:127.0.0.1'),
        '-keyout ' .. shell_escape(key),
        '-out ' .. shell_escape(certificate),
    }, ' ')
    assert(os.execute(command), 'Failed to create TLS certificate')
    return certificate, key
end

function test_filedist_cli_help_and_invalid_port()
    local code, output = run_loongshield({ 'filedist', '--help' })
    assert(code == 0, 'Expected filedist --help to exit 0:\n' .. output)
    assert(output:find('Usage: loongshield filedist', 1, true), output)
    assert(output:find('server --dir <path>', 1, true), output)
    assert(output:find('pull <url>', 1, true), output)

    code, output = run_loongshield({ 'filedist', 'server', '--dir', '.', '--port', 'not-a-number' })
    assert(code == 1, 'Expected invalid filedist port to exit 1:\n' .. output)
    assert(output:find('invalid server port', 1, true), output)
end

function test_filedist_cli_rejects_plaintext_and_missing_ca()
    local root = make_temp_dir()

    local code, output = run_loongshield({
        'filedist',
        'pull',
        'http://127.0.0.1:8443/',
        '--dir',
        root,
    })
    assert(code == 1, 'Expected plain HTTP pull to fail:\n' .. output)
    assert(output:find('file distribution requires an HTTPS URL', 1, true), output)

    code, output = run_loongshield({
        'filedist',
        'pull',
        'https://127.0.0.1:8443/',
        '--dir',
        root,
    })
    assert(code == 1, 'Expected pull without CA to fail:\n' .. output)
    assert(output:find('pull requires --ca <trusted-ca-pem>', 1, true), output)

    os.execute('rm -rf ' .. shell_escape(root))
end

function test_filedist_cli_distributes_any_regular_file()
    local root = make_temp_dir()
    local certificate, key = make_tls_certificate(root .. '/tls')
    local server_dir = root .. '/server'
    local client_dir = root .. '/client'
    assert(os.execute('mkdir -p ' .. shell_escape(server_dir .. '/policies')))
    assert(os.execute('mkdir -p ' .. shell_escape(client_dir)))

    local ima_policy = 'measure func=BPRM_CHECK\nappraise fowner=0\n'
    local binary = '\0\1\255loongshield-filedist'
    write_file(server_dir .. '/policies/ima-policy', ima_policy)
    write_file(server_dir .. '/app.conf', 'enabled=true\n')
    write_file(server_dir .. '/binary.dat', binary)
    write_file(server_dir .. '/private.key', 'private key material\n')
    assert(os.execute('ln -s /etc/shadow ' .. shell_escape(server_dir .. '/leak.conf')))

    local port = 20000 + math.random(0, 1999)
    local server_cmd = table.concat({
        shell_escape(BIN),
        'filedist',
        'server',
        '--dir',
        shell_escape(server_dir),
        '--port',
        tostring(port),
        '--cert',
        shell_escape(certificate),
        '--key',
        shell_escape(key),
    }, ' ')
    local server_log = root .. '/server.log'
    local server = io.popen(server_cmd .. ' > ' .. shell_escape(server_log) .. ' 2>&1 & echo $!')
    local server_pid = (server:read('*l') or ''):gsub('%s+$', '')
    server:close()
    assert(server_pid ~= '', 'Failed to start filedist server')

    local pull_code, pull_output
    for _ = 1, 20 do
        pull_code, pull_output = run_loongshield({
            'filedist',
            'pull',
            'https://127.0.0.1:' .. port .. '/',
            '--dir',
            client_dir,
            '--ca',
            certificate,
        })
        if pull_code == 0 then
            break
        end
        os.execute('sleep 0.1')
    end

    os.execute('kill ' .. server_pid .. ' 2>/dev/null')
    assert(
        pull_code == 0,
        'Expected filedist pull to succeed:\n' .. tostring(pull_output) .. '\nserver log:\n' .. read_file(server_log)
    )
    assert(pull_output:find('Pulled 4 files', 1, true), pull_output)

    local wrong_certificate = make_tls_certificate(root .. '/wrong-tls')
    local reject_dir = root .. '/rejected'
    local reject_code, reject_output = run_loongshield({
        'filedist',
        'pull',
        'https://127.0.0.1:' .. port .. '/',
        '--dir',
        reject_dir,
        '--ca',
        wrong_certificate,
    })
    assert(reject_code == 1, 'Expected pull with an untrusted CA to fail:\n' .. reject_output)
    assert(not file_exists(reject_dir), 'Expected rejected pull to write no files')

    assert(read_file(client_dir .. '/policies/ima-policy') == ima_policy)
    assert(read_file(client_dir .. '/app.conf') == 'enabled=true\n')
    assert(read_file(client_dir .. '/binary.dat') == binary)
    assert(read_file(client_dir .. '/private.key') == 'private key material\n')
    assert(not file_exists(client_dir .. '/leak.conf'), 'Symlink must not be distributed')

    os.execute('rm -rf ' .. shell_escape(root))
end
