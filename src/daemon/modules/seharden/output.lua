local log = require('runtime.log')
local utils = require('seharden.shared.util')

local M = {}

local function get_probe_data(node, contexts)
    if type(node) ~= "table" or type(node.actual) ~= "string" then
        return nil, nil
    end

    local probe_name = node.actual:match('^%%{probe%.([^}]+)}$')
    if not probe_name then
        return nil, nil
    end

    return probe_name, contexts.probe[probe_name]
end

local function format_item_value(key, value)
    if key == "mode" and type(value) == "number" then
        return string.format("0%03o", value)
    end

    return utils.serialize_for_log(value)
end

local function format_verbose_value(key, value)
    if key == "mode" and type(value) == "number" then
        return string.format("0%03o", value)
    end

    if type(value) == "string" then
        return string.format("'%s'", value)
    end

    if value == nil then
        return "nil"
    end

    return tostring(value)
end

local function summarize_item(item)
    if type(item) ~= "table" then
        return utils.serialize_for_log(item)
    end

    local summary = {}
    local seen = {}
    local preferred_keys = {
        "path", "user", "name", "uid", "gid", "mode", "shell", "value", "found"
    }

    local function append_value(source, key)
        if type(source) ~= "table" or source[key] == nil or seen[key] then
            return
        end

        seen[key] = true
        summary[#summary + 1] = string.format("%s=%s", key, format_item_value(key, source[key]))
    end

    local meta = getmetatable(item)
    local inherited = meta and type(meta.__index) == "table" and meta.__index or nil

    for _, key in ipairs(preferred_keys) do
        append_value(item, key)
        append_value(inherited, key)
    end

    if #summary == 0 then
        return utils.serialize_for_log(item)
    end

    return table.concat(summary, ", ")
end

local function collect_probe_focus_keys(node, focus)
    if type(node) ~= "table" then
        return focus
    end

    focus = focus or {}

    local actual = node.actual
    if type(actual) == "string" then
        local probe_name = actual:match('^%%{probe%.([^}]+)}$')
        if probe_name and type(node.key) == "string" and node.key ~= "" then
            focus[probe_name] = focus[probe_name] or {}
            focus[probe_name][node.key] = true
        end
    end

    if type(node.all_of) == "table" then
        for _, child in ipairs(node.all_of) do
            collect_probe_focus_keys(child, focus)
        end
    end

    if type(node.any_of) == "table" then
        for _, child in ipairs(node.any_of) do
            collect_probe_focus_keys(child, focus)
        end
    end

    if type(node.expected) == "table" then
        collect_probe_focus_keys(node.expected, focus)
    end

    return focus
end

local function summarize_probe_value(value, focus_keys)
    if type(value) ~= "table" then
        return format_verbose_value(nil, value)
    end

    if next(value) == nil then
        return "empty"
    end

    local parts = {}
    local seen = {}
    local preferred_keys = {
        "available",
        "value",
        "count",
        "conflicting_count",
        "found",
        "compliant",
        "UnitFileState",
        "ActiveState",
        "error",
        "path",
        "path_type",
        "user",
        "name",
        "uid",
        "gid",
        "mode",
        "shell",
    }

    local function append_part(key)
        if key == nil or seen[key] or value[key] == nil then
            return
        end

        seen[key] = true
        parts[#parts + 1] = string.format("%s=%s", key, format_verbose_value(key, value[key]))
    end

    if type(focus_keys) == "table" then
        local keys = {}
        for key in pairs(focus_keys) do
            keys[#keys + 1] = key
        end
        table.sort(keys)
        for _, key in ipairs(keys) do
            append_part(key)
        end
    end

    for _, key in ipairs(preferred_keys) do
        append_part(key)
    end

    if type(value.details) == "table" then
        if value.count == nil then
            parts[#parts + 1] = string.format("count=%d", #value.details)
        end
        if #value.details > 0 then
            parts[#parts + 1] = string.format("first=%s", summarize_item(value.details[1]))
        end
    elseif value[1] ~= nil then
        if value.count == nil then
            parts[#parts + 1] = string.format("count=%d", #value)
        end
        parts[#parts + 1] = string.format("first=%s", summarize_item(value[1]))
    end

    if #parts == 0 then
        local extra_keys = {}
        local total_keys = 0
        for key, map_value in pairs(value) do
            total_keys = total_keys + 1
            if not seen[key] and type(key) == "string" and type(map_value) ~= "table" then
                extra_keys[#extra_keys + 1] = key
            end
        end

        table.sort(extra_keys)
        if #extra_keys > 0 and #extra_keys <= 4 then
            for _, key in ipairs(extra_keys) do
                append_part(key)
            end
        elseif total_keys > 0 then
            return string.format("table(%d keys)", total_keys)
        end
    end

    if #parts == 0 then
        return "table"
    end

    return table.concat(parts, ", ")
end

function M.format_failure_detail(node, contexts, actual, comparator_detail)
    local probe_name, probe_data = get_probe_data(node, contexts)

    if type(comparator_detail) == "table" and comparator_detail.item ~= nil then
        local item_summary = summarize_item(comparator_detail.item)
        if comparator_detail.index ~= nil then
            return string.format("first failing item #%d: %s", comparator_detail.index, item_summary)
        end
        return "first failing item: " .. item_summary
    end

    if actual == nil and probe_name and type(probe_data) == "table" and probe_data.error ~= nil then
        return "probe error: " .. tostring(probe_data.error)
    end

    return "actual: " .. utils.serialize_for_log(actual)
end

function M.emit_verbose_rule_details(rule, status, probed_data, reason, probe_tasks)
    local label

    if status == "PASS" then
        label = "PASS"
    elseif status == "FAIL" then
        label = "FAIL"
    else
        return
    end

    local styled_label = label == "PASS"
        and log.style(label, "bold", "green")
        or log.style(label, "bold", "red")

    print(string.format("  %s [%s] %s", styled_label, tostring(rule.id), tostring(rule.desc)))
    if label == "FAIL" and reason then
        local formatted_reason = tostring(reason):gsub("\n%s*", "\n      ")
        print(string.format("    %s %s", log.style("reason:", "yellow"), formatted_reason))
    end

    if type(probe_tasks) ~= "table" or #probe_tasks == 0 then
        return
    end

    local focus_keys = collect_probe_focus_keys(rule.assertion)
    for _, task in ipairs(probe_tasks) do
        if type(task) == "table" and type(task.name) == "string" then
            local value = probed_data and probed_data[task.name]
            if value ~= nil then
                print(string.format("    - %s: %s", task.name,
                    summarize_probe_value(value, focus_keys[task.name])))
            end
        end
    end
end

function M.emit_verbose_summary(passed, fixed, failed, manual, dry_run_pending, total)
    local summary = log.style("Summary:", "bold", "cyan")
    local passed_text = log.style(string.format("%d passed", passed), "green")
    local fixed_text = log.style(string.format("%d fixed", fixed), "green")
    local failed_text = log.style(string.format("%d failed", failed), failed > 0 and "red" or "green")
    local manual_text = log.style(string.format("%d manual", manual), manual > 0 and "yellow" or "dim")
    local pending_text = log.style(
        string.format("%d dry-run-pending", dry_run_pending),
        dry_run_pending > 0 and "yellow" or "dim")

    print(string.format(
        "%s %s, %s, %s, %s, %s / %d total",
        summary, passed_text, fixed_text, failed_text, manual_text, pending_text, total))
end

return M
