local lfs = require('lfs')

-- ANSI color codes for readable output
local colors = {
    red = "\27[31m",
    green = "\27[32m",
    yellow = "\27[33m",
    reset = "\27[0m"
}

local function split_csv(value)
    local items = {}
    for item in value:gmatch("[^,]+") do
        items[#items + 1] = item
    end
    return items
end

local function parse_args(args)
    local opts = {
        types = {},
        pattern = nil
    }

    local i = 1
    while i <= #args do
        local arg = args[i]
        if arg == "--type" then
            i = i + 1
            if args[i] then
                for _, t in ipairs(split_csv(args[i])) do
                    opts.types[t] = true
                end
            end
        elseif arg:match("^%-%-type=") then
            local v = arg:match("^%-%-type=(.+)$")
            for _, t in ipairs(split_csv(v)) do
                opts.types[t] = true
            end
        elseif arg == "--pattern" then
            i = i + 1
            opts.pattern = args[i]
        elseif arg:match("^%-%-pattern=") then
            opts.pattern = arg:match("^%-%-pattern=(.+)$")
        end
        i = i + 1
    end

    return opts
end

local function add_test_files(root, out)
    local function visit(dir)
        for entry in lfs.dir(dir) do
            if entry ~= "." and entry ~= ".." then
                local path = dir .. "/" .. entry
                local attr = lfs.attributes(path)
                if attr and attr.mode == "directory" then
                    visit(path)
                elseif entry:match("^test_.*%.lua$") then
                    out[#out + 1] = path
                end
            end
        end
    end
    if lfs.attributes(root) then
        visit(root)
    end
end

local opts = parse_args(arg or {})

if not next(opts.types) or opts.types.all then
    opts.types = { unit = true, integration = true, e2e = true }
end

local roots = {}
if opts.types.unit then roots[#roots + 1] = "tests/unit" end
if opts.types.integration then roots[#roots + 1] = "tests/integration" end
if opts.types.e2e then roots[#roots + 1] = "tests/e2e" end

package.path = table.concat({
    "src/daemon/modules/?.lua",
    "src/daemon/modules/?/init.lua",
    "tests/helpers/?.lua",
}, ";") .. ";" .. package.path

print("--- Starting Lua Test Suite ---")

local total_failures = 0
local total_tests_run = 0
local test_files = {}
local base_print = _G.print

local function capture_print(fn)
    local lines = {}
    _G.print = function(...)
        local parts = {}
        for i = 1, select("#", ...) do
            parts[#parts + 1] = tostring(select(i, ...))
        end
        lines[#lines + 1] = table.concat(parts, " ")
    end

    local ok, res = pcall(fn)
    _G.print = base_print
    return ok, res, lines
end

for _, root in ipairs(roots) do
    add_test_files(root, test_files)
end

if opts.pattern then
    local filtered = {}
    for _, path in ipairs(test_files) do
        if path:match(opts.pattern) then
            filtered[#filtered + 1] = path
        end
    end
    test_files = filtered
end

table.sort(test_files)

if #test_files == 0 then
    print(colors.yellow .. "No test files found for selected types." .. colors.reset)
    os.exit(0)
end

print("Found " .. #test_files .. " test file(s).\n")

for _, file_path in ipairs(test_files) do
    print(colors.yellow .. "SUITE:" .. colors.reset .. " " .. file_path)

    local existing_tests = {}
    for name in pairs(_G) do
        if name:match("^test_") then
            existing_tests[name] = true
        end
    end

    local ok, load_err = pcall(dofile, file_path)
    if not ok then
        print("  " .. colors.red .. "Failed to load suite: " .. tostring(load_err) .. colors.reset)
        total_failures = total_failures + 1
        goto continue
    end

    local tests_in_suite = {}
    for name, func in pairs(_G) do
        if name:match("^test_") and not existing_tests[name] and type(func) == 'function' then
            tests_in_suite[#tests_in_suite + 1] = { name = name, func = func }
        end
    end

    table.sort(tests_in_suite, function(a, b) return a.name < b.name end)

    if #tests_in_suite == 0 then
        print("  (No new test functions found in this file)")
    end

    for _, test in ipairs(tests_in_suite) do
        total_tests_run = total_tests_run + 1
        io.write("  " .. test.name .. ": ")

        local success, err_msg, logs = capture_print(test.func)

        if success then
            io.write(colors.green .. "PASS\n" .. colors.reset)
        else
            io.write(colors.red .. "FAIL\n" .. colors.reset)
            base_print("    " .. colors.red .. "Error: " .. tostring(err_msg) .. colors.reset)
            total_failures = total_failures + 1
        end

        if logs and #logs > 0 then
            for _, line in ipairs(logs) do
                base_print("    " .. line)
            end
        end
    end
    print("")
    ::continue::
end

print("-------------------------------")

if total_failures > 0 then
    print(string.format("\n" .. colors.red .. "Finished. %d total tests run, %d failed." .. colors.reset,
        total_tests_run, total_failures))
    os.exit(1)
else
    print(string.format("\n" .. colors.green .. "All %d tests passed!" .. colors.reset, total_tests_run))
    os.exit(0)
end
