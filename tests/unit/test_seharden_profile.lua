local function with_stubbed_profile(stubs, fn)
    local saved_profile = package.loaded["seharden.profile"]
    local saved_util = package.loaded["seharden.util"]
    local saved_lyaml = package.loaded["lyaml"]

    package.loaded["seharden.profile"] = nil
    package.loaded["seharden.util"] = stubs.util
    package.loaded["lyaml"] = stubs.lyaml

    local ok, err = pcall(function()
        local profile = require("seharden.profile")
        fn(profile)
    end)

    package.loaded["seharden.profile"] = saved_profile
    package.loaded["seharden.util"] = saved_util
    package.loaded["lyaml"] = saved_lyaml

    if not ok then
        error(err, 2)
    end
end

local profile = require("seharden.profile")

function test_get_rules_for_level_rejects_non_list_rules_schema()
    local rules, err = profile.get_rules_for_level({
        levels = {
            { id = "baseline" }
        },
        rules = {
            id = "rule.1",
            desc = "bad schema",
            assertion = {}
        }
    })

    assert(rules == nil, "Expected invalid rules schema to be rejected")
    assert(err:find("field 'rules' must be a list", 1, true),
        "Expected schema error to explain that rules must be a list")
end

function test_get_rules_for_level_rejects_unknown_rule_level_reference()
    local rules, err = profile.get_rules_for_level({
        levels = {
            { id = "baseline" }
        },
        rules = {
            {
                id = "rule.1",
                desc = "bad level reference",
                level = { "strict" },
                assertion = {
                    compare = "is_true",
                    actual = true,
                }
            }
        }
    }, "baseline")

    assert(rules == nil, "Expected unknown rule level reference to be rejected")
    assert(err:find("unknown level 'strict'", 1, true),
        "Expected schema error to surface the unknown level id")
end

function test_get_rules_for_level_rejects_probe_task_missing_name()
    local rules, err = profile.get_rules_for_level({
        levels = {
            { id = "baseline" }
        },
        rules = {
            {
                id = "rule.1",
                desc = "bad probe",
                probes = {
                    {
                        func = "permissions.get_attributes",
                        params = { path = "/etc/passwd" },
                    }
                },
                assertion = {
                    compare = "is_true",
                    actual = true,
                }
            }
        }
    }, "baseline")

    assert(rules == nil, "Expected malformed probe schema to be rejected during profile validation")
    assert(err:find("rules[1].probes[1].name must be a non-empty string.", 1, true),
        "Expected schema error to point at the invalid probe task")
end

function test_get_rules_for_level_rejects_unknown_assertion_comparator()
    local rules, err = profile.get_rules_for_level({
        levels = {
            { id = "baseline" }
        },
        rules = {
            {
                id = "rule.1",
                desc = "bad comparator",
                assertion = {
                    compare = "does_not_exist",
                    actual = true,
                }
            }
        }
    }, "baseline")

    assert(rules == nil, "Expected unknown comparators to be rejected during profile validation")
    assert(err:find("rules[1].assertion.compare references unknown comparator 'does_not_exist'.", 1, true),
        "Expected schema error to surface the invalid comparator")
end

function test_load_allows_inactive_rules_to_use_unknown_comparators()
    with_stubbed_profile({
        util = {
            read_file_content = function()
                return "stub"
            end
        },
        lyaml = {
            load = function()
                return {
                    levels = {
                        { id = "baseline" },
                        { id = "strict" },
                    },
                    rules = {
                        {
                            id = "rule.baseline",
                            desc = "baseline rule",
                            level = { "baseline" },
                            assertion = {
                                compare = "is_true",
                                actual = true,
                            }
                        },
                        {
                            id = "rule.strict",
                            desc = "strict rule",
                            level = { "strict" },
                            assertion = {
                                compare = "does_not_exist",
                                actual = true,
                            }
                        }
                    }
                }
            end
        }
    }, function(stubbed_profile)
        local loaded = stubbed_profile.load("mixed_profile")
        assert(loaded ~= nil, "Expected structural profile loading to ignore inactive-rule comparator capability")
    end)
end

function test_get_rules_for_level_ignores_unknown_comparator_in_inactive_rule()
    local rules, err = profile.get_rules_for_level({
        levels = {
            { id = "baseline" },
            { id = "strict" },
        },
        rules = {
            {
                id = "rule.baseline",
                desc = "baseline rule",
                level = { "baseline" },
                assertion = {
                    compare = "is_true",
                    actual = true,
                }
            },
            {
                id = "rule.strict",
                desc = "strict rule",
                level = { "strict" },
                assertion = {
                    compare = "does_not_exist",
                    actual = true,
                }
            }
        }
    }, "baseline")

    assert(err == nil, "Expected inactive unknown comparators not to poison the selected rule set")
    assert(#rules == 1 and rules[1].id == "rule.baseline",
        "Expected only the selected level's valid rules to be returned")
end

function test_get_rules_for_level_rejects_unknown_comparator_in_active_rule()
    local rules, err = profile.get_rules_for_level({
        levels = {
            { id = "baseline" },
            { id = "strict" },
        },
        rules = {
            {
                id = "rule.baseline",
                desc = "baseline rule",
                level = { "baseline" },
                assertion = {
                    compare = "is_true",
                    actual = true,
                }
            },
            {
                id = "rule.strict",
                desc = "strict rule",
                level = { "strict" },
                assertion = {
                    compare = "does_not_exist",
                    actual = true,
                }
            }
        }
    }, "strict")

    assert(rules == nil, "Expected active unknown comparators to be rejected after level filtering")
    assert(err:find("rules%[2%]%.assertion%.compare references unknown comparator 'does_not_exist'%."),
        "Expected active rule validation to surface the unsupported comparator")
end

function test_get_rules_for_level_includes_inherited_levels()
    local rules = assert(profile.get_rules_for_level({
        levels = {
            { id = "baseline" },
            { id = "strict", inherits_from = { "baseline" } }
        },
        rules = {
            {
                id = "rule.baseline",
                desc = "baseline rule",
                level = { "baseline" },
                assertion = {
                    compare = "is_true",
                    actual = true,
                }
            },
            {
                id = "rule.strict",
                desc = "strict rule",
                level = { "strict" },
                assertion = {
                    compare = "is_true",
                    actual = true,
                }
            }
        }
    }, "strict"))

    assert(#rules == 2, "Expected inherited baseline rules to remain active")
end

function test_get_manual_review_items_for_level_rejects_invalid_schema()
    local items, err = profile.get_manual_review_items_for_level({
        levels = {
            { id = "baseline" }
        },
        manual_review_required = {
            {
                area = "audit",
                item = "",
                reason = "requires approval"
            }
        },
        rules = {}
    }, "baseline")

    assert(items == nil, "Expected invalid manual-review schema to be rejected")
    assert(err:find("manual_review_required[1].item must be a non-empty string.", 1, true),
        "Expected schema error to point at the invalid manual-review item")
end

function test_get_manual_review_items_for_level_includes_inherited_levels()
    local items = assert(profile.get_manual_review_items_for_level({
        levels = {
            { id = "baseline" },
            { id = "strict", inherits_from = { "baseline" } }
        },
        manual_review_required = {
            {
                area = "global",
                item = "always review",
                reason = "applies everywhere"
            },
            {
                area = "baseline",
                item = "baseline review",
                reason = "baseline scope",
                level = { "baseline" }
            },
            {
                area = "strict",
                item = "strict review",
                reason = "strict scope",
                level = { "strict" }
            }
        },
        rules = {}
    }, "strict"))

    assert(#items == 3, "Expected inherited manual-review items to remain active")
    assert(items[1].item == "always review", "Expected global manual-review item first")
    assert(items[2].item == "baseline review", "Expected inherited baseline review item")
    assert(items[3].item == "strict review", "Expected strict-level review item")
end

function test_load_rejects_invalid_schema_before_runtime()
    with_stubbed_profile({
        util = {
            read_file_content = function()
                return "stub"
            end
        },
        lyaml = {
            load = function()
                return {
                    levels = {
                        { id = "baseline", inherits_from = { "missing" } }
                    },
                    rules = {
                        {
                            id = "rule.1",
                            desc = "demo rule",
                            level = { "baseline" },
                            assertion = {
                                compare = "is_true",
                                actual = true,
                            }
                        }
                    }
                }
            end
        }
    }, function(stubbed_profile)
        local loaded = stubbed_profile.load("broken_profile")
        assert(loaded == nil, "Expected invalid profile schema to fail during load")
    end)
end

function test_load_rejects_invalid_rule_schema_before_runtime()
    with_stubbed_profile({
        util = {
            read_file_content = function()
                return "stub"
            end
        },
        lyaml = {
            load = function()
                return {
                    levels = {
                        { id = "baseline" }
                    },
                    rules = {
                        {
                            id = "rule.1",
                            desc = "demo rule",
                            probes = {
                                {
                                    func = "permissions.get_attributes",
                                    params = { path = "/etc/passwd" },
                                }
                            },
                            assertion = {
                                compare = "is_true",
                                actual = true,
                            }
                        }
                    }
                }
            end
        }
    }, function(stubbed_profile)
        local loaded = stubbed_profile.load("broken_profile")
        assert(loaded == nil, "Expected invalid rule schema to fail during load")
    end)
end
