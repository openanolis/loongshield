local log = require('runtime.log')
local rule_schema = require('seharden.rule_schema')
local utils = require('seharden.util')
local lyaml = require('lyaml')
local M = {}
local _validated_marker = {}

local RULES_BASE_PATH =
    os.getenv("LOONGSHIELD_SEHARDEN_RULES_PATH")
    or "/etc/loongshield/seharden"

local function is_non_empty_string(value)
    return type(value) == "string" and value ~= ""
end

local function is_list(value)
    if type(value) ~= "table" then
        return false
    end

    local count = 0
    for key, _ in pairs(value) do
        if type(key) ~= "number" or key < 1 or key % 1 ~= 0 then
            return false
        end
        count = count + 1
    end

    for i = 1, count do
        if value[i] == nil then
            return false
        end
    end

    return true
end

local function validate_string_list(values, field_name)
    if not is_list(values) then
        return nil, string.format("%s must be a list of non-empty strings.", field_name)
    end

    for i, value in ipairs(values) do
        if not is_non_empty_string(value) then
            return nil, string.format("%s[%d] must be a non-empty string.", field_name, i)
        end
    end

    return true
end

function M.validate(profile_data)
    if type(profile_data) ~= "table" then
        return nil, "Profile root must be a YAML mapping."
    end

    if profile_data[_validated_marker] then
        return true
    end

    if not is_list(profile_data.levels) then
        return nil, "Profile field 'levels' must be a list."
    end

    if not is_list(profile_data.rules) then
        return nil, "Profile field 'rules' must be a list."
    end

    local level_ids = {}
    for i, level_def in ipairs(profile_data.levels) do
        if type(level_def) ~= "table" then
            return nil, string.format("levels[%d] must be a table.", i)
        end
        if not is_non_empty_string(level_def.id) then
            return nil, string.format("levels[%d].id must be a non-empty string.", i)
        end
        if level_ids[level_def.id] then
            return nil, string.format("Duplicate level id '%s'.", level_def.id)
        end
        level_ids[level_def.id] = true

        if level_def.inherits_from ~= nil then
            local ok, err = validate_string_list(level_def.inherits_from,
                string.format("levels[%d].inherits_from", i))
            if not ok then
                return nil, err
            end
        end
    end

    for i, level_def in ipairs(profile_data.levels) do
        if level_def.inherits_from then
            for _, parent_id in ipairs(level_def.inherits_from) do
                if not level_ids[parent_id] then
                    return nil, string.format(
                        "levels[%d].inherits_from references unknown level '%s'.", i, parent_id)
                end
            end
        end
    end

    if profile_data.manual_review_required ~= nil then
        if not is_list(profile_data.manual_review_required) then
            return nil, "Profile field 'manual_review_required' must be a list."
        end

        for i, entry in ipairs(profile_data.manual_review_required) do
            if type(entry) ~= "table" then
                return nil, string.format("manual_review_required[%d] must be a table.", i)
            end
            if not is_non_empty_string(entry.area) then
                return nil, string.format("manual_review_required[%d].area must be a non-empty string.", i)
            end
            if not is_non_empty_string(entry.item) then
                return nil, string.format("manual_review_required[%d].item must be a non-empty string.", i)
            end
            if not is_non_empty_string(entry.reason) then
                return nil, string.format("manual_review_required[%d].reason must be a non-empty string.", i)
            end

            if entry.level ~= nil then
                local ok, err = validate_string_list(entry.level,
                    string.format("manual_review_required[%d].level", i))
                if not ok then
                    return nil, err
                end
                for _, level_id in ipairs(entry.level) do
                    if not level_ids[level_id] then
                        return nil, string.format(
                            "manual_review_required[%d].level references unknown level '%s'.", i, level_id)
                    end
                end
            end
        end
    end

    local rule_ids = {}
    for i, rule in ipairs(profile_data.rules) do
        local ok, err = rule_schema.validate_rule(
            rule,
            string.format("rules[%d]", i),
            { validate_comparators = false }
        )
        if not ok then
            return nil, err
        end
        if rule_ids[rule.id] then
            return nil, string.format("Duplicate rule id '%s'.", rule.id)
        end
        rule_ids[rule.id] = true

        if rule.level ~= nil then
            local levels_ok, levels_err = validate_string_list(rule.level, string.format("rules[%d].level", i))
            if not levels_ok then
                return nil, levels_err
            end
            for _, level_id in ipairs(rule.level) do
                if not level_ids[level_id] then
                    return nil, string.format(
                        "rules[%d].level references unknown level '%s'.", i, level_id)
                end
            end
        end
    end

    profile_data[_validated_marker] = true
    return true
end

function M.load(config_name_or_path)
    if not is_non_empty_string(config_name_or_path) then
        log.error("Profile name/path must be a non-empty string.")
        return nil
    end

    local rule_path
    if config_name_or_path:match("/") then
        rule_path = config_name_or_path
    else
        local name = config_name_or_path
        if not (name:match("%.yml$") or name:match("%.yaml$")) then
            name = name .. ".yml"
        end
        rule_path = string.format("%s/%s", RULES_BASE_PATH, name)
    end

    log.debug("Attempting to load profile from: %s", rule_path)
    local yaml_content, err = utils.read_file_content(rule_path)
    if not yaml_content then
        log.error("Failed to read profile file '%s': %s", rule_path, tostring(err))
        return nil
    end

    local ok, profile_data = pcall(lyaml.load, yaml_content)
    if not ok or type(profile_data) ~= 'table' then
        log.error("Failed to parse YAML from profile '%s'. Error: %s", config_name_or_path, tostring(profile_data))
        return nil
    end

    local valid, schema_err = M.validate(profile_data)
    if not valid then
        log.error("Invalid profile schema in '%s': %s", config_name_or_path, schema_err)
        return nil
    end

    return profile_data
end

local function build_active_levels(profile_data, target_level_id)
    local levels_by_id = {}
    for _, level_def in ipairs(profile_data.levels) do
        levels_by_id[level_def.id] = level_def
    end

    if not target_level_id then
        local active_levels = {}
        for level_id, _ in pairs(levels_by_id) do
            active_levels[level_id] = true
        end
        return active_levels
    end

    if not levels_by_id[target_level_id] then
        log.error("Specified level '%s' not found in profile.", target_level_id)
        return nil
    end

    local active_levels = {}
    local levels_to_process = { target_level_id }
    local processed_ids = {}

    while #levels_to_process > 0 do
        local current_id = table.remove(levels_to_process)
        if not processed_ids[current_id] then
            local level_def = levels_by_id[current_id]
            if level_def then
                active_levels[current_id] = true
                processed_ids[current_id] = true
                if level_def.inherits_from then
                    for _, parent_id in ipairs(level_def.inherits_from) do
                        table.insert(levels_to_process, parent_id)
                    end
                end
            end
        end
    end

    local active_level_names = {}
    for name, _ in pairs(active_levels) do table.insert(active_level_names, name) end
    table.sort(active_level_names)
    log.debug("Active levels for target '%s': %s", target_level_id or "all", table.concat(active_level_names, ", "))

    return active_levels
end

function M.get_rules_for_level(profile_data, target_level_id)
    local valid, schema_err = M.validate(profile_data)
    if not valid then
        log.error("Invalid profile schema: %s", schema_err)
        return nil, schema_err
    end

    local active_levels = build_active_levels(profile_data, target_level_id)
    if not active_levels then
        return nil
    end

    local rules_to_run = {}
    for index, rule in ipairs(profile_data.rules) do
        if not rule.level then
            local ok, err = rule_schema.validate_rule(
                rule,
                string.format("rules[%d]", index),
                { validate_comparators = true }
            )
            if not ok then
                return nil, err
            end
            table.insert(rules_to_run, rule)
        elseif type(rule.level) == 'table' then
            for _, rule_level_id in ipairs(rule.level) do
                if active_levels[rule_level_id] then
                    local ok, err = rule_schema.validate_rule(
                        rule,
                        string.format("rules[%d]", index),
                        { validate_comparators = true }
                    )
                    if not ok then
                        return nil, err
                    end
                    table.insert(rules_to_run, rule)
                    break
                end
            end
        end
    end

    return rules_to_run
end

function M.get_manual_review_items_for_level(profile_data, target_level_id)
    local valid, schema_err = M.validate(profile_data)
    if not valid then
        log.error("Invalid profile schema: %s", schema_err)
        return nil, schema_err
    end

    local active_levels = build_active_levels(profile_data, target_level_id)
    if not active_levels then
        return nil
    end

    local items_to_review = {}
    for _, entry in ipairs(profile_data.manual_review_required or {}) do
        if not entry.level then
            table.insert(items_to_review, entry)
        else
            for _, entry_level_id in ipairs(entry.level) do
                if active_levels[entry_level_id] then
                    table.insert(items_to_review, entry)
                    break
                end
            end
        end
    end

    return items_to_review
end

return M
