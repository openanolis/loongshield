local rule_schema = require("seharden.rule_schema")

local function make_rule(overrides)
    local rule = {
        id = "rule.1",
        desc = "demo rule",
        assertion = {
            compare = "is_true",
            actual = true,
        },
    }

    for key, value in pairs(overrides or {}) do
        rule[key] = value
    end

    return rule
end

function test_rule_schema_accepts_single_probe_task_shorthand()
    local ok = rule_schema.validate_rule(make_rule({
        probes = {
            name = "attrs",
            func = "permissions.get_attributes",
            params = { path = "/etc/passwd" },
        },
    }), "rules[1]")

    assert(ok == true, "Expected single probe shorthand to remain valid")
end

function test_rule_schema_rejects_probe_task_missing_name()
    local ok, err = rule_schema.validate_rule(make_rule({
        probes = {
            {
                func = "permissions.get_attributes",
                params = { path = "/etc/passwd" },
            },
        },
    }), "rules[1]")

    assert(ok == nil, "Expected malformed probe tasks to be rejected")
    assert(err:find("rules[1].probes[1].name must be a non-empty string.", 1, true),
        "Expected schema error to point at the missing probe name")
end

function test_rule_schema_rejects_duplicate_probe_names()
    local ok, err = rule_schema.validate_rule(make_rule({
        probes = {
            {
                name = "attrs",
                func = "permissions.get_attributes",
                params = { path = "/etc/passwd" },
            },
            {
                name = "attrs",
                func = "permissions.get_attributes",
                params = { path = "/etc/group" },
            },
        },
    }), "rules[1]")

    assert(ok == nil, "Expected duplicate probe names to be rejected")
    assert(err:find("duplicates probe name 'attrs'", 1, true),
        "Expected schema error to call out duplicate probe names")
end

function test_rule_schema_rejects_non_list_reinforce_steps()
    local ok, err = rule_schema.validate_rule(make_rule({
        reinforce = {
            action = "file.append_line",
            params = { path = "/tmp/demo", line = "ok" },
        },
    }), "rules[1]")

    assert(ok == nil, "Expected reinforce mappings to be rejected when not wrapped in a list")
    assert(err:find("rules[1].reinforce must be a list of reinforce steps.", 1, true),
        "Expected schema error to require reinforce lists explicitly")
end

function test_rule_schema_rejects_unknown_comparator()
    local ok, err = rule_schema.validate_rule(make_rule({
        assertion = {
            compare = "does_not_exist",
            actual = true,
        },
    }), "rules[1]")

    assert(ok == nil, "Expected unknown comparators to be rejected during schema validation")
    assert(err:find("rules[1].assertion.compare references unknown comparator 'does_not_exist'.", 1, true),
        "Expected schema error to mention the unknown comparator")
end

function test_rule_schema_rejects_non_assertion_for_all_expected()
    local ok, err = rule_schema.validate_rule(make_rule({
        assertion = {
            compare = "for_all",
            actual = {
                { value = true },
            },
            expected = true,
        },
    }), "rules[1]")

    assert(ok == nil, "Expected for_all to require a nested assertion tree in expected")
    assert(err:find("rules[1].assertion.expected must be an assertion table when compare is 'for_all'.", 1, true),
        "Expected schema error to point at the nested for_all assertion")
end

function test_rule_schema_accepts_reinforce_guard_with_name()
    local ok = rule_schema.validate_rule(make_rule({
        reinforce_guard = {
            name = "container_host_check",
            func = "env_detect.is_container_host",
            skip_message = "Container host detected.",
        },
        reinforce = {
            { action = "sysctl.set_value", params = { key = "net.ipv4.ip_forward", value = "0" } },
        },
    }), "rules[1]")

    assert(ok == true, "Expected rule with well-formed reinforce_guard to validate")
end

function test_rule_schema_rejects_reinforce_guard_without_name()
    local ok, err = rule_schema.validate_rule(make_rule({
        reinforce_guard = {
            func = "env_detect.is_container_host",
        },
    }), "rules[1]")

    assert(ok == nil, "Expected guard without name to be rejected")
    assert(err:find("reinforce_guard") and err:find("name must be a non%-empty string"),
        "Expected schema error to point at reinforce_guard.name, got: " .. tostring(err))
end
