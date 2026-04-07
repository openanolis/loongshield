local sbom = require('rpm.sbom')

function test_construct_url_substitutes_fields()
    local url = sbom.construct_url("http://x/{name_first}/{name}-{version}-{release}.{arch}",
        { name = "Bash", version = "5.2", release = "1", arch = "x86_64" })
    assert(url == "http://x/b/Bash-5.2-1.x86_64", "URL template substitution failed")
end

function test_parse_spdx_json_rejects_non_json()
    local result, err = sbom.parse_spdx_json("<html>nope</html>")
    assert(result == nil, "Expected parse failure for non-JSON content")
    assert(err and err:match("not JSON"), "Expected non-JSON error")
end

function test_parse_spdx_json_handles_api_404()
    local body = [[{"status":{"code":404,"message":"not found"}}]]
    local result, err = sbom.parse_spdx_json(body)
    assert(result == nil, "Expected nil result for API error")
    assert(err and err:match("404"), "Expected 404 error message")
    assert(err and err:find("configured repository", 1, true),
        "Expected 404 error to describe the configured SBOM repository")
end

function test_parse_spdx_json_extracts_sha256()
    local body = [[
    {
      "spdxVersion": "SPDX-2.2",
      "files": [
        {
          "fileName": "./usr/bin/test",
          "checksums": [
            { "algorithm": "SHA1", "checksumValue": "ignored" },
            { "algorithm": "SHA256", "checksumValue": "ABCDEF" }
          ]
        },
        {
          "fileName": "etc/config",
          "checksums": [
            { "algorithm": "SHA256", "checksumValue": "1234" }
          ]
        }
      ]
    }
    ]]

    local result, err = sbom.parse_spdx_json(body)
    assert(result and not err, "Expected successful parse")
    assert(result["/usr/bin/test"] == "abcdef", "Expected normalized sha256 checksum")
    assert(result["/etc/config"] == "1234", "Expected normalized path and checksum")
end
