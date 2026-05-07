local lyaml = require('lyaml')
local seharden_profile = require('seharden.profile')
local file_probe = require('seharden.probes.file')
local evaluator = require('seharden.evaluator')
local loader = require('seharden.loader')
local rule_schema = require('seharden.rule_schema')

local function read_file(path)
    local f = assert(io.open(path, "r"))
    local content = f:read("*a")
    f:close()
    return content
end

local function find_unit_filestate_is_falsy_rules(profile)
    local offenders = {}

    local function visit(rule_id, node)
        if type(node) ~= "table" then
            return
        end

        if node.key == "UnitFileState" and node.compare == "is_falsy" then
            offenders[#offenders + 1] = rule_id
        end

        for _, value in pairs(node) do
            visit(rule_id, value)
        end
    end

    for _, rule in ipairs(profile.rules or {}) do
        visit(rule.id or "<unknown>", rule.assertion)
    end

    table.sort(offenders)
    return offenders
end

local function assertion_tree_contains_key(node, key_name)
    if type(node) ~= "table" then
        return false
    end

    if node.key == key_name then
        return true
    end

    for _, value in pairs(node) do
        if assertion_tree_contains_key(value, key_name) then
            return true
        end
    end

    return false
end

local function walk_assertion_nodes(node, visitor)
    if type(node) ~= "table" then
        return
    end

    visitor(node)
    for _, value in pairs(node) do
        walk_assertion_nodes(value, visitor)
    end
end

local function find_ssh_probes_missing_localhost_conditions(profile)
    local offenders = {}

    for _, rule in ipairs(profile.rules or {}) do
        local probes = rule.probes
        if type(probes) == "table" and probes.func then
            probes = { probes }
        end

        if type(probes) == "table" then
            for _, probe in ipairs(probes) do
                if probe.func == "ssh.get_effective_value"
                    or probe.func == "ssh.inspect_access_restrictions"
                    or probe.func == "ssh.inspect_banner"
                    or probe.func == "ssh.inspect_effective_setting"
                    or probe.func == "ssh.inspect_effective_algorithm_list" then
                    local params = probe.params or {}
                    local conditions = params.conditions or {}
                    if conditions.from ~= "localhost"
                        or type(conditions.user) ~= "string"
                        or conditions.user == "" then
                        offenders[#offenders + 1] = rule.id or "<unknown>"
                    end
                end
            end
        end
    end

    table.sort(offenders)
    return offenders
end

local function collect_rule_descs(profile)
    local descs = {}
    for _, rule in ipairs(profile.rules or {}) do
        descs[#descs + 1] = rule.desc or ""
    end
    return descs
end

local function find_rule_by_id(profile, rule_id)
    for _, rule in ipairs(profile.rules or {}) do
        if rule.id == rule_id then
            return rule
        end
    end
    return nil
end

local function find_probe(rule, probe_name)
    local probes = rule.probes or {}

    if probes.func then
        probes = { probes }
    end

    local match
    local count = 0
    for _, probe in ipairs(probes) do
        if probe.name == probe_name then
            match = probe
            count = count + 1
        end
    end

    assert(count <= 1,
        string.format("Rule '%s' defines duplicate probe name '%s'", rule.id or "<unknown>", probe_name))
    return match
end

local function find_duplicate_probe_names(profile)
    local offenders = {}

    for _, rule in ipairs(profile.rules or {}) do
        local probes = rule.probes or {}
        if probes.func then
            probes = { probes }
        end

        local seen = {}
        for _, probe in ipairs(probes) do
            if probe.name ~= nil then
                if seen[probe.name] then
                    offenders[#offenders + 1] = string.format("%s:%s", rule.id or "<unknown>", probe.name)
                end
                seen[probe.name] = true
            end
        end
    end

    table.sort(offenders)
    return offenders
end

local function find_reinforce_action(rule, action_name)
    for _, step in ipairs(rule.reinforce or {}) do
        if step.action == action_name then
            return step
        end
    end
    return nil
end

local function contains_text(value, needle)
    return type(value) == "string" and value:find(needle, 1, true) ~= nil
end

local function octal(value)
    return assert(tonumber(value, 8))
end

local function manual_review_contains(profile, needle)
    for _, entry in ipairs(profile.manual_review_required or {}) do
        if contains_text(entry.item, needle) or contains_text(entry.reason, needle) then
            return true
        end
    end
    return false
end

local function write_temp_file(path, content)
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
end

function test_cis_profile_does_not_use_is_falsy_for_unit_file_state()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local offenders = find_unit_filestate_is_falsy_rules(profile)

    assert(#offenders == 0,
        "Expected cis_alinux_3 service rules to use explicit not-found semantics, offenders: " ..
        table.concat(offenders, ", "))
end

function test_cis_profile_declares_l1_server_as_default_level()
    local profile = seharden_profile.load("profiles/seharden/cis_alinux_3.yml")

    assert(profile.default_level == "l1_server",
        "Expected cis_alinux_3 to default omitted --level selections to l1_server")
    assert(seharden_profile.resolve_target_level(profile, nil) == "l1_server",
        "Expected cis_alinux_3 default level resolution to return l1_server")
end

function test_cis_profile_tracks_current_cis_benchmark_version()
    local profile = seharden_profile.load("profiles/seharden/cis_alinux_3.yml")

    assert(profile.benchmark_version == "2.0.0",
        "Expected cis_alinux_3 to declare the current CIS benchmark version")
    assert(contains_text(profile.title, "v2.0.0"),
        "Expected cis_alinux_3 title to name the current CIS benchmark")
    assert(profile.version ~= "0.0.2",
        "Expected cis_alinux_3 profile version to move past stale benchmark metadata")
    assert(profile.coverage == "automated_subset",
        "Expected cis_alinux_3 to declare that SEHarden coverage is an automated subset")
    assert(contains_text(profile.description, "CIS Alibaba Cloud Linux 3 Benchmark"),
        "Expected cis_alinux_3 description to explain the tracked upstream benchmark")
    assert(profile.source == "https://www.cisecurity.org/benchmark/aliyun_linux",
        "Expected cis_alinux_3 to point at the public CIS Alibaba Cloud Linux benchmark source")
    assert(profile.benchmark_workbench_source == "https://workbench.cisecurity.org/benchmarks/23595/files",
        "Expected cis_alinux_3 to retain the exact CIS WorkBench v2.0.0 artifact source")
    assert(profile.benchmark_pdf_source == "https://workbench.cisecurity.org/cis/api/v1/file/6532/download",
        "Expected cis_alinux_3 to retain the exact CIS WorkBench v2.0.0 PDF source")
    assert(profile.benchmark_build_kit_source == "https://workbench.cisecurity.org/files/6746",
        "Expected cis_alinux_3 to retain the exact CIS WorkBench v2.0.0 build kit source")
    assert(profile.benchmark_update_source == "https://www.cisecurity.org/insights/blog/cis-benchmarks-monthly-update-october-2025",
        "Expected cis_alinux_3 to retain the CIS update announcement source")
end

function test_cis_profile_selected_rules_and_manual_items_validate_through_runtime_api()
    local profile = seharden_profile.load("profiles/seharden/cis_alinux_3.yml")
    local l1_rules, l1_err = seharden_profile.get_rules_for_level(profile, "l1_server")
    local l2_rules, l2_err = seharden_profile.get_rules_for_level(profile, "l2_server")
    local l1_manual = seharden_profile.get_manual_review_items_for_level(profile, "l1_server")
    local l2_manual = seharden_profile.get_manual_review_items_for_level(profile, "l2_server")
    local l2_workstation_manual = seharden_profile.get_manual_review_items_for_level(profile, "l2_workstation")

    assert(l1_rules ~= nil, "Expected l1_server selected CIS rules to validate: " .. tostring(l1_err))
    assert(l2_rules ~= nil, "Expected l2_server selected CIS rules to validate: " .. tostring(l2_err))
    assert(#l2_rules > #l1_rules, "Expected l2_server to inherit l1_server and add L2 rules")
    assert(manual_review_contains({ manual_review_required = l2_manual }, "CIS 5.4.1.2"),
        "Expected Level 2 manual review selections to include CIS 5.4.1.2")
    assert(not manual_review_contains({ manual_review_required = l1_manual }, "CIS 5.4.1.2"),
        "Expected Level 1 manual review selections not to include CIS 5.4.1.2")
    assert(not manual_review_contains({ manual_review_required = l2_workstation_manual }, "CIS 5.4.1.2"),
        "Expected workstation selections not to include server-only CIS 5.4.1.2")
end

function test_bundled_profiles_validate_all_level_counts_through_runtime_api()
    local cases = {
        { path = "profiles/seharden/agentos_baseline.yml", level = "baseline", rules = 23, manual = 0 },
        { path = "profiles/seharden/agentos_baseline.yml", level = "openclaw", rules = 32, manual = 7 },
        { path = "profiles/seharden/cis_alinux_3.yml", level = "l1_server", rules = 236, manual = 3 },
        { path = "profiles/seharden/cis_alinux_3.yml", level = "l2_server", rules = 280, manual = 4 },
        { path = "profiles/seharden/cis_alinux_3.yml", level = "l1_workstation", rules = 167, manual = 3 },
        { path = "profiles/seharden/cis_alinux_3.yml", level = "l2_workstation", rules = 184, manual = 3 },
        { path = "profiles/seharden/dengbao_3.yml", level = "l1_server", rules = 53, manual = 15 },
        { path = "profiles/seharden/dengbao_3.yml", level = "l2_server", rules = 53, manual = 15 },
        { path = "profiles/seharden/dengbao_3.yml", level = "l1_workstation", rules = 53, manual = 15 },
        { path = "profiles/seharden/dengbao_3.yml", level = "l2_workstation", rules = 53, manual = 15 },
    }

    for _, case in ipairs(cases) do
        local profile = seharden_profile.load(case.path)
        local rules, rules_err = seharden_profile.get_rules_for_level(profile, case.level)
        local manual, manual_err = seharden_profile.get_manual_review_items_for_level(profile, case.level)
        local label = string.format("%s:%s", case.path, case.level)

        assert(rules ~= nil, "Expected selected rules to validate for " .. label .. ": " .. tostring(rules_err))
        assert(manual ~= nil, "Expected manual items to validate for " .. label .. ": " .. tostring(manual_err))
        assert(#rules == case.rules,
            string.format("Expected %s to select %d rule(s), got %d", label, case.rules, #rules))
        assert(#manual == case.manual,
            string.format("Expected %s to select %d manual item(s), got %d", label, case.manual, #manual))
        assert(#rules > 0, "Expected " .. label .. " to select non-empty automated coverage")
    end
end

function test_bundled_profile_selected_probe_and_enforcer_paths_resolve()
    local cases = {
        { path = "profiles/seharden/agentos_baseline.yml", levels = { "baseline", "openclaw" } },
        { path = "profiles/seharden/cis_alinux_3.yml", levels = {
            "l1_server",
            "l2_server",
            "l1_workstation",
            "l2_workstation",
        } },
        { path = "profiles/seharden/dengbao_3.yml", levels = {
            "l1_server",
            "l2_server",
            "l1_workstation",
            "l2_workstation",
        } },
    }
    local offenders = {}

    for _, case in ipairs(cases) do
        local profile = seharden_profile.load(case.path)
        for _, level in ipairs(case.levels) do
            local rules = assert(seharden_profile.get_rules_for_level(profile, level))
            for _, rule in ipairs(rules) do
                for _, task in ipairs(rule_schema.normalize_probe_tasks(rule.probes)) do
                    local probe_func = loader.get_probe(task.func)
                    if type(probe_func) ~= "function" then
                        offenders[#offenders + 1] = string.format(
                            "%s:%s:%s probe %s",
                            case.path, level, rule.id, tostring(task.func))
                    end
                end
                for _, task in ipairs(rule.reinforce or {}) do
                    local enforcer_func = loader.get_enforcer(task.action)
                    if type(enforcer_func) ~= "function" then
                        offenders[#offenders + 1] = string.format(
                            "%s:%s:%s enforcer %s",
                            case.path, level, rule.id, tostring(task.action))
                    end
                end
            end
        end
    end

    table.sort(offenders)
    assert(#offenders == 0,
        "Expected selected profile probe/enforcer paths to resolve: " ..
        table.concat(offenders, ", "))
end

function test_bundled_profiles_do_not_reuse_probe_names_within_a_rule()
    local profile_paths = {
        "profiles/seharden/agentos_baseline.yml",
        "profiles/seharden/cis_alinux_3.yml",
        "profiles/seharden/dengbao_3.yml",
    }

    for _, path in ipairs(profile_paths) do
        local profile = seharden_profile.load(path)
        local offenders = find_duplicate_probe_names(profile)

        assert(#offenders == 0,
            string.format("Expected unique probe names per rule in %s, offenders: %s",
                path, table.concat(offenders, ", ")))
    end
end

function test_cis_profile_uses_current_tmp_rule_numbering()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local tmp_rule = find_rule_by_id(profile, "1.1.2.1.1")

    assert(tmp_rule ~= nil, "Expected cis_alinux_3 to keep /tmp coverage at rule 1.1.2.1.1")
    assert(find_rule_by_id(profile, "1.1.22") == nil,
        "Expected cis_alinux_3 not to keep the legacy duplicate /tmp rule 1.1.22")
    assert(find_probe(tmp_rule, "tmp_mount_info").func == "mounts.get_mount_info",
        "Expected /tmp rule to rely on exact mount evidence, not tmp.mount service state")
    assert(find_probe(tmp_rule, "tmp_service_status") == nil,
        "Expected /tmp rule not to reject valid non-systemd separate /tmp partitions")
    assert(assertion_tree_contains_key(tmp_rule.assertion, "exists"),
        "Expected /tmp rule to require an exact /tmp mount point")
end

function test_cis_profile_remaps_existing_coverage_to_v2_rule_ids()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local expected_rules = {
        ["1.1.1.1"] = "Ensure cramfs kernel module is not available",
        ["1.1.1.2"] = "Ensure freevxfs kernel module is not available",
        ["1.1.1.3"] = "Ensure hfs kernel module is not available",
        ["1.1.1.4"] = "Ensure hfsplus kernel module is not available",
        ["1.1.1.5"] = "Ensure jffs2 kernel module is not available",
        ["1.1.1.6"] = "Ensure overlay kernel module is not available",
        ["1.1.1.7"] = "Ensure squashfs kernel module is not available",
        ["1.1.1.8"] = "Ensure udf kernel module is not available",
        ["1.1.1.9"] = "Ensure firewire-core kernel module is not available",
        ["1.1.1.10"] = "Ensure usb-storage kernel module is not available",
        ["1.1.2.2.1"] = "Ensure /dev/shm is tmpfs",
        ["1.1.2.3.2"] = "Ensure nodev option set on /home partition",
        ["1.1.2.4.2"] = "Ensure nodev option set on /var partition",
        ["1.1.2.6.2"] = "Ensure nodev option set on /var/log partition",
        ["1.1.2.6.3"] = "Ensure nosuid option set on /var/log partition",
        ["1.1.2.6.4"] = "Ensure noexec option set on /var/log partition",
        ["1.1.2.7.2"] = "Ensure nodev option set on /var/log/audit partition",
        ["1.1.2.7.3"] = "Ensure nosuid option set on /var/log/audit partition",
        ["1.1.2.7.4"] = "Ensure noexec option set on /var/log/audit partition",
        ["1.2.1.5"] = "Ensure weak dependencies are configured",
        ["1.3.1.1"] = "Ensure SELinux is installed",
        ["1.3.1.2"] = "Ensure SELinux policy is configured",
        ["1.3.1.3"] = "Ensure the SELinux mode is not disabled",
        ["1.3.1.5"] = "Ensure the MCS Translation Service (mcstrans) is not installed",
        ["1.3.1.6"] = "Ensure SETroubleshoot is not installed",
        ["1.5.1"] = "Ensure core file size is configured",
        ["1.5.2"] = "Ensure fs.protected_hardlinks is configured",
        ["1.5.3"] = "Ensure fs.protected_symlinks is configured",
        ["1.5.4"] = "Ensure fs.suid_dumpable is configured",
        ["1.5.5"] = "Ensure kernel.dmesg_restrict is configured",
        ["1.5.6"] = "Ensure kernel.kptr_restrict is configured",
        ["1.5.8"] = "Ensure systemd-coredump ProcessSizeMax is configured",
        ["1.5.9"] = "Ensure systemd-coredump Storage is configured",
        ["1.7.1"] = "Ensure /etc/motd is configured",
        ["1.7.2"] = "Ensure /etc/issue is configured",
        ["1.7.3"] = "Ensure /etc/issue.net is configured",
        ["1.8.3"] = "Ensure GDM screen lock is configured",
        ["1.8.4"] = "Ensure GDM automount is configured",
        ["1.8.5"] = "Ensure GDM autorun-never is configured",
        ["1.8.7"] = "Ensure Xwayland is configured",
        ["2.1.1"] = "Ensure autofs services are not in use",
        ["2.1.3"] = "Ensure cockpit web services are not in use",
        ["2.1.6"] = "Ensure dnsmasq services are not in use",
        ["2.1.13"] = "Ensure rsync services are not in use",
        ["2.1.16"] = "Ensure telnet server services are not in use",
        ["2.1.17"] = "Ensure tftp server services are not in use",
        ["2.1.21"] = "Ensure GNOME Display Manager is not installed",
        ["2.1.22"] = "Ensure X window server services are not in use",
        ["2.1.23"] = "Ensure mail transfer agents are configured for local-only mode",
        ["2.2.1"] = "Ensure ftp client is not installed",
        ["2.2.5"] = "Ensure tftp client is not installed",
        ["2.4.1.1"] = "Ensure cron daemon is enabled and active",
        ["2.4.1.2"] = "Ensure access to /etc/crontab is configured",
        ["2.4.1.8"] = "Ensure access to /etc/cron.d is configured",
        ["2.4.1.9"] = "Ensure access to crontab is configured",
        ["2.4.2.1"] = "Ensure access to at is configured",
        ["3.1.2"] = "Ensure wireless interfaces are not available",
        ["3.1.3"] = "Ensure bluetooth services are not in use",
        ["3.2.1"] = "Ensure atm kernel module is not available",
        ["3.2.2"] = "Ensure can kernel module is not available",
        ["3.2.3"] = "Ensure dccp kernel module is not available",
        ["3.2.4"] = "Ensure rds kernel module is not available",
        ["3.2.5"] = "Ensure sctp kernel module is not available",
        ["3.2.6"] = "Ensure tipc kernel module is not available",
        ["3.3.1.1"] = "Ensure net.ipv4.ip_forward is configured",
        ["3.3.1.2"] = "Ensure net.ipv4.conf.all.forwarding is configured",
        ["3.3.1.3"] = "Ensure net.ipv4.conf.default.forwarding is configured",
        ["3.3.1.14"] = "Ensure net.ipv4.conf.all.accept_source_route is configured",
        ["3.3.1.18"] = "Ensure net.ipv4.tcp_syncookies is configured",
        ["3.3.2.2"] = "Ensure net.ipv6.conf.default.forwarding is configured",
        ["3.3.2.5"] = "Ensure net.ipv6.conf.all.accept_source_route is configured",
        ["3.3.2.8"] = "Ensure net.ipv6.conf.default.accept_ra is configured",
        ["4.1.1"] = "Ensure firewalld is installed",
        ["5.1.1"] = "Ensure sshd crypto_policy is not set",
        ["5.1.2"] = "Ensure access to /etc/ssh/sshd_config is configured",
        ["5.1.3"] = "Ensure access to /etc/sysconfig/sshd is configured",
        ["5.1.4"] = "Ensure access to SSH private host key files is configured",
        ["5.1.5"] = "Ensure access to SSH public host key files is configured",
        ["5.1.6"] = "Ensure sshd access is configured",
        ["5.1.18"] = "Ensure sshd MaxAuthTries is configured",
        ["5.1.21"] = "Ensure sshd PermitEmptyPasswords is disabled",
        ["5.1.23"] = "Ensure sshd PermitUserEnvironment is disabled",
        ["5.1.24"] = "Ensure sshd UsePAM is enabled",
        ["5.2.1"] = "Ensure sudo is installed",
        ["5.2.3"] = "Ensure sudo log file exists",
        ["5.2.5"] = "Ensure re-authentication for privilege escalation is not disabled globally",
        ["5.2.6"] = "Ensure sudo timestamp_timeout is configured",
        ["6.2.1.1.1"] = "Ensure journald service is active",
        ["6.1.3"] = "Ensure cryptographic mechanisms are used to protect the integrity of audit tools",
        ["6.2.1.1.6"] = "Ensure journald Compress is configured",
        ["6.2.1.1.5"] = "Ensure journald Storage is configured",
        ["6.2.1.2.4"] = "Ensure systemd-journal-remote service is not in use",
        ["6.3.1.1"] = "Ensure auditd packages are installed",
        ["6.3.1.4"] = "Ensure auditd service is enabled and active",
        ["7.1.1"] = "Ensure access to /etc/passwd is configured",
        ["7.1.9"] = "Ensure access to /etc/shells is configured",
        ["7.1.10"] = "Ensure access to /etc/security/opasswd is configured",
        ["7.2.2"] = "Ensure /etc/shadow password fields are not empty",
        ["7.2.9"] = "Ensure local interactive user dot files access is configured",
    }
    local stale_ids = {
        "1.1.3.2",
        "1.2.1",
        "1.2.2",
        "1.2.3",
        "1.3.1",
        "1.11",
        "2.2.14",
        "2.2.7",
        "3.3.1",
        "3.3.2",
        "3.3.3",
        "3.3.4",
        "3.3.5",
        "3.3.6",
        "3.3.7",
        "3.3.8",
        "3.3.9",
        "3.4.1.1",
        "4.2.1.5",
        "4.1.1.1",
        "4.1.1.2",
        "5.6.1.2",
        "6.2.1",
        "6.2.7",
        "6.2.8",
        "6.2.9",
        "6.2.10",
    }
    local stale_descs = {
        "1.1.1.2 Ensure mounting of squashfs filesystems is disabled",
        "Ensure mounting of udf filesystems is disabled",
        "Ensure the AppArmor is installed",
        "Ensure AppArmor is enabled in the bootloader configuration",
        "Ensure SELinux is not disabled in bootloader configuration",
        "Ensure the SELinux state is enforcing",
        "Ensure SCTP is disabled",
        "Ensure DCCP is disabled",
        "Ensure IP forwarding is disabled",
        "Ensure packet redirect sending is disabled",
        "Ensure cron daemon is enabled",
        "Ensure permissions on /etc/crontab are configured",
        "Ensure permissions on /etc/cron.d are configured",
        "Ensure at/cron is restricted to authorized users",
        "Ensure SSH X11 forwarding is disabled",
        "Ensure SSH MaxAuthTries is set to 4 or less",
    }
    local desc_set = {}

    for rule_id, desc in pairs(expected_rules) do
        local rule = find_rule_by_id(profile, rule_id)
        assert(rule ~= nil, "Expected cis_alinux_3 to define v2.0.0 rule " .. rule_id)
        assert(rule.desc == desc, "Expected " .. rule_id .. " to use the v2.0.0 rule title")
    end

    for _, rule_id in ipairs(stale_ids) do
        assert(find_rule_by_id(profile, rule_id) == nil,
            "Expected cis_alinux_3 not to keep stale pre-v2 rule id " .. rule_id)
    end

    for _, desc in ipairs(collect_rule_descs(profile)) do
        desc_set[desc] = true
    end

    for _, desc in ipairs(stale_descs) do
        assert(desc_set[desc] ~= true,
            "Expected cis_alinux_3 not to keep stale pre-v2 rule title " .. desc)
    end
end

function test_cis_profile_has_unique_rule_ids()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local seen = {}

    for _, rule in ipairs(profile.rules or {}) do
        assert(seen[rule.id] == nil,
            "Expected cis_alinux_3 not to duplicate rule id " .. tostring(rule.id))
        seen[rule.id] = true
    end
end

function test_cis_profile_splits_network_sysctl_controls_to_v2_ids()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local expectations = {
        ["3.3.1.2"] = { "ipv4_all_forwarding", "net.ipv4.conf.all.forwarding", "0" },
        ["3.3.1.3"] = { "ipv4_default_forwarding", "net.ipv4.conf.default.forwarding", "0" },
        ["3.3.1.14"] = { "ipv4_all_accept_source_route", "net.ipv4.conf.all.accept_source_route", "0" },
        ["3.3.1.15"] = { "ipv4_default_accept_source_route", "net.ipv4.conf.default.accept_source_route", "0" },
        ["3.3.1.18"] = { "ipv4_tcp_syncookies", "net.ipv4.tcp_syncookies", "1" },
        ["3.3.2.2"] = { "ipv6_default_forwarding", "net.ipv6.conf.default.forwarding", "0" },
        ["3.3.2.5"] = { "ipv6_all_accept_source_route", "net.ipv6.conf.all.accept_source_route", "0" },
        ["3.3.2.8"] = { "ipv6_default_accept_ra", "net.ipv6.conf.default.accept_ra", "0" },
    }

    for rule_id, expectation in pairs(expectations) do
        local rule = find_rule_by_id(profile, rule_id)
        local probe_name, key, expected = expectation[1], expectation[2], expectation[3]
        local probe

        assert(rule ~= nil, "Expected cis_alinux_3 to define split network rule " .. rule_id)
        probe = find_probe(rule, probe_name)
        assert(probe ~= nil, "Expected " .. rule_id .. " to use probe " .. probe_name)
        assert(probe.params.key == key, "Expected " .. rule_id .. " to inspect " .. key)
        assert(rule.assertion.expected == expected,
            "Expected " .. rule_id .. " to assert the v2.0.0 sysctl value")
        assert((rule.reinforce or {})[1].params.key == key,
            "Expected " .. rule_id .. " reinforce action to persist " .. key)
    end
end

function test_cis_profile_network_kernel_module_rules_disable_loading_paths()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local modules = {
        ["1.1.1.1"] = { name = "cramfs", probe = "cramfs_disable_state" },
        ["1.1.1.2"] = { name = "freevxfs", probe = "freevxfs_disable_state" },
        ["1.1.1.3"] = { name = "hfs", probe = "hfs_disable_state" },
        ["1.1.1.4"] = { name = "hfsplus", probe = "hfsplus_disable_state" },
        ["1.1.1.5"] = { name = "jffs2", probe = "jffs2_disable_state" },
        ["1.1.1.6"] = { name = "overlay", probe = "overlay_disable_state" },
        ["1.1.1.7"] = { name = "squashfs", probe = "squashfs_disable_state" },
        ["1.1.1.8"] = { name = "udf", probe = "udf_disable_state" },
        ["1.1.1.9"] = { name = "firewire-core", probe = "firewire_core_disable_state" },
        ["1.1.1.10"] = { name = "usb-storage", probe = "usb_storage_disable_state" },
        ["3.2.1"] = { name = "atm", probe = "atm_disable_state" },
        ["3.2.2"] = { name = "can", probe = "can_disable_state" },
        ["3.2.3"] = { name = "dccp", probe = "dccp_disable_state" },
        ["3.2.4"] = { name = "rds", probe = "rds_disable_state" },
        ["3.2.5"] = { name = "sctp", probe = "sctp_disable_state" },
        ["3.2.6"] = { name = "tipc", probe = "tipc_disable_state" },
    }

    for rule_id, module in pairs(modules) do
        local rule = find_rule_by_id(profile, rule_id)
        local state_probe

        assert(rule ~= nil, "Expected cis_alinux_3 to define kernel module rule " .. rule_id)
        state_probe = find_probe(rule, module.probe)
        assert(state_probe ~= nil, "Expected " .. rule_id .. " to use the deep kmod disable-state probe")
        assert(state_probe.func == "kmod.get_disable_state",
            "Expected " .. rule_id .. " to pull kernel module disable policy into the kmod probe")
        assert(state_probe.params.name == module.name,
            "Expected " .. rule_id .. " to inspect the " .. module.name .. " module")
        assert(rule.assertion.actual == "%{probe." .. module.probe .. "}",
            "Expected " .. rule_id .. " to assert the disable-state probe")
        assert(rule.assertion.key == "disabled" and rule.assertion.compare == "is_true",
            "Expected " .. rule_id .. " to require the module disable contract to pass")
        assert(find_reinforce_action(rule, "kmod.unload") ~= nil,
            "Expected " .. rule_id .. " to unload " .. module.name .. " during reinforce")
        assert(find_reinforce_action(rule, "kmod.blacklist") ~= nil,
            "Expected " .. rule_id .. " to blacklist " .. module.name .. " during reinforce")
        assert(find_reinforce_action(rule, "kmod.set_install_command") ~= nil,
            "Expected " .. rule_id .. " to set a disabled install command during reinforce")
    end
end

function test_cis_profile_network_service_boundary_rules_use_deep_probes()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local mta_rule = find_rule_by_id(profile, "2.1.23")
    local wireless_rule = find_rule_by_id(profile, "3.1.2")

    assert(find_probe(mta_rule, "mta_local_only").func == "network.inspect_mta_local_only",
        "Expected MTA local-only rule to combine listener and MTA binding evidence in one probe")
    assert(find_probe(mta_rule, "mta_local_only").params.ports[1] == 25,
        "Expected MTA local-only rule to check SMTP submission ports")
    assert(find_probe(wireless_rule, "wireless_modules").func == "network.inspect_wireless_modules",
        "Expected wireless interface rule to resolve wireless sysfs modules and check kmod disable state")
    assert(assertion_tree_contains_key(wireless_rule.assertion, "available"),
        "Expected wireless interface rule to fail when sysfs evidence is unavailable")
end

function test_cis_profile_discloses_manual_v2_controls_outside_automation()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local manual_ids = {
        "CIS 1.2.1.1",
        "CIS 2.1.24",
        "CIS 5.4.1.2",
        "CIS 6.2.2.6",
    }
    local automated_absent = {
        "1.2.1.1",
        "2.1.24",
        "5.4.1.2",
        "6.2.2.6",
    }

    for _, needle in ipairs(manual_ids) do
        assert(manual_review_contains(profile, needle),
            "Expected cis_alinux_3 manual review notes to include " .. needle)
    end

    for _, rule_id in ipairs(automated_absent) do
        assert(find_rule_by_id(profile, rule_id) == nil,
            "Expected manual CIS control " .. rule_id .. " to stay outside automated rules")
    end
end

function test_cis_profile_service_rules_check_running_state()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local service_not_in_use_rules = {
        "2.1.1",
        "2.1.2",
        "2.1.4",
        "2.1.5",
        "2.1.7",
        "2.1.8",
        "2.1.9",
        "2.1.10",
        "2.1.11",
        "2.1.12",
        "2.1.13",
        "2.1.14",
        "2.1.15",
        "2.1.18",
        "2.1.19",
    }
    local enabled_active_rules = {
        "2.4.1.1",
        "6.2.2.2",
        "6.3.1.4",
    }

    for _, rule_id in ipairs(service_not_in_use_rules) do
        local rule = find_rule_by_id(profile, rule_id)
        assert(rule ~= nil, "Expected cis_alinux_3 to define service rule " .. rule_id)
        assert(assertion_tree_contains_key(rule.assertion, "UnitFileState"),
            "Expected service rule " .. rule_id .. " to inspect UnitFileState")
        assert(assertion_tree_contains_key(rule.assertion, "ActiveState"),
            "Expected service rule " .. rule_id .. " not to pass disabled-but-running services")
    end

    for _, rule_id in ipairs(enabled_active_rules) do
        local rule = find_rule_by_id(profile, rule_id)
        assert(rule ~= nil, "Expected cis_alinux_3 to define enabled-and-active service rule " .. rule_id)
        assert(assertion_tree_contains_key(rule.assertion, "UnitFileState"),
            "Expected service rule " .. rule_id .. " to inspect UnitFileState")
        assert(assertion_tree_contains_key(rule.assertion, "ActiveState"),
            "Expected service rule " .. rule_id .. " to inspect ActiveState")
    end
end

function test_cis_profile_new_service_rules_use_deep_not_in_use_probe()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local expectations = {
        ["2.1.3"] = "cockpit_services",
        ["2.1.6"] = "dnsmasq_service",
        ["2.1.16"] = "telnet_socket",
        ["2.1.17"] = "tftp_services",
        ["3.1.3"] = "bluetooth_service",
    }

    for rule_id, probe_name in pairs(expectations) do
        local rule = find_rule_by_id(profile, rule_id)
        local probe = find_probe(rule, probe_name)

        assert(rule ~= nil, "Expected cis_alinux_3 to define service rule " .. rule_id)
        assert(probe ~= nil, "Expected " .. rule_id .. " to use a service not-in-use probe")
        assert(probe.func == "services.get_not_in_use_state",
            "Expected " .. rule_id .. " to keep service state policy inside the services probe")
        assert(assertion_tree_contains_key(rule.assertion, "not_in_use"),
            "Expected " .. rule_id .. " to assert service not-in-use state")
    end
end

function test_cis_profile_service_not_in_use_rules_fail_disabled_but_running_units()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "2.1.13")
    local passed_disabled_active = evaluator.evaluate(rule.assertion, {
        probe = {
            rsync_service = {
                UnitFileState = "disabled",
                ActiveState = "active",
            },
        },
    })
    local passed_disabled_inactive = evaluator.evaluate(rule.assertion, {
        probe = {
            rsync_service = {
                UnitFileState = "disabled",
                ActiveState = "inactive",
            },
        },
    })
    local passed_not_found = evaluator.evaluate(rule.assertion, {
        probe = {
            rsync_service = {
                UnitFileState = "not-found",
                ActiveState = "active",
            },
        },
    })

    assert(passed_disabled_active == false, "Expected disabled but active services to fail not-in-use rules")
    assert(passed_disabled_inactive == true, "Expected disabled and inactive services to pass not-in-use rules")
    assert(passed_not_found == true, "Expected absent services to pass not-in-use rules")
end

function test_cis_profile_uses_structured_gpgcheck_value_validation()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "1.2.1.2")
    local dnf_probe = find_probe(rule, "dnf_conf_check")
    local repo_probe = find_probe(rule, "repo_gpgcheck_override")
    local accepted = {}

    for _, branch in ipairs(rule.assertion.all_of[1].any_of) do
        accepted[branch.expected] = true
    end

    assert(dnf_probe.params.normalize_values == "lower",
        "Expected global gpgcheck parsing to accept CIS boolean spellings case-insensitively")
    assert(accepted["1"] and accepted["true"] and accepted["yes"],
        "Expected global gpgcheck validation to accept 1, true, and yes")
    assert(repo_probe.func == "file.find_key_value_outside_allowed",
        "Expected repo gpgcheck validation to parse values structurally")
    assert(repo_probe.params.allowed_values[1] == "1"
        and repo_probe.params.allowed_values[2] == "true"
        and repo_probe.params.allowed_values[3] == "yes",
        "Expected repo gpgcheck validation to allow only CIS-enabled values")
end

function test_cis_profile_uses_structured_dnf_weak_dependency_validation()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "1.2.1.5")
    local probe = find_probe(rule, "dnf_conf_check")
    local accepted = {}

    for _, branch in ipairs(rule.assertion.any_of) do
        accepted[branch.expected] = true
    end

    assert(probe.func == "file.parse_key_values",
        "Expected weak dependency rule to parse dnf.conf structurally")
    assert(probe.params.section == "main",
        "Expected weak dependency rule to inspect the dnf.conf main section")
    assert(accepted["0"] and accepted["false"] and accepted["no"],
        "Expected weak dependency rule to accept CIS disabled values")
end

function test_cis_profile_selinux_package_and_policy_rules_are_structured()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local installed_rule = find_rule_by_id(profile, "1.3.1.1")
    local policy_rule = find_rule_by_id(profile, "1.3.1.2")
    local accepted = {}

    assert(find_probe(installed_rule, "libselinux_installed").func == "packages.get_installed",
        "Expected SELinux installed rule to query libselinux package state")
    for _, branch in ipairs(policy_rule.assertion.any_of) do
        accepted[branch.expected] = true
    end
    assert(find_probe(policy_rule, "selinux_policy").func == "file.parse_key_values",
        "Expected SELinux policy rule to parse /etc/selinux/config structurally")
    assert(find_probe(policy_rule, "selinux_policy").params.allow_missing == true,
        "Expected missing SELinux config to fail the rule without becoming an engine error")
    assert(accepted.targeted and accepted.mls,
        "Expected SELinux policy rule to allow targeted or mls")
end

function test_cis_profile_crypto_policy_rules_use_structured_current_policy_probe()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local expectations = {
        ["1.6.2"] = "sha1_disabled",
        ["1.6.3"] = "weak_macs_disabled",
        ["1.6.4"] = "ssh_cbc_disabled",
    }

    for rule_id, expected_key in pairs(expectations) do
        local rule = find_rule_by_id(profile, rule_id)

        assert(rule ~= nil, "Expected CIS profile to define crypto policy rule " .. rule_id)
        local probe = find_probe(rule, "crypto_policy_current")

        assert(rule.status == "automated", "Expected " .. rule_id .. " to be automated")
        assert(rule.level[1] == "l1_server" and rule.level[2] == "l1_workstation" and rule.level[3] == nil,
            "Expected " .. rule_id .. " to apply to CIS Level 1 server and workstation")
        assert(probe ~= nil, "Expected " .. rule_id .. " to inspect the current crypto policy")
        assert(probe.func == "crypto_policy.inspect_current",
            "Expected " .. rule_id .. " to use the structured crypto policy probe")
        assert(assertion_tree_contains_key(rule.assertion, "available"),
            "Expected " .. rule_id .. " to fail clearly when CURRENT.pol cannot be read")
        assert(assertion_tree_contains_key(rule.assertion, expected_key),
            "Expected " .. rule_id .. " to assert " .. expected_key)
    end
end

function test_cis_profile_bootloader_access_uses_deep_file_probe()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "1.4.1")
    local probe = find_probe(rule, "bootloader_config_access")

    assert(rule.level[1] == "l1_server" and rule.level[2] == nil,
        "Expected bootloader access rule to follow the CIS Level 1 Server applicability")
    assert(probe.func == "file.inspect_bootloader_config_access",
        "Expected bootloader access policy to be encapsulated in the file probe")
    assert(assertion_tree_contains_key(rule.assertion, "available"),
        "Expected bootloader rule to fail when /boot evidence is unavailable")
    assert(assertion_tree_contains_key(rule.assertion, "checked_count"),
        "Expected bootloader rule to reject missing grub evidence")
    assert(assertion_tree_contains_key(rule.assertion, "all_configured"),
        "Expected bootloader rule to assert the aggregate access contract")
end

function test_cis_profile_chrony_rules_use_structured_configuration_probe()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local configured_rule = find_rule_by_id(profile, "2.3.2")
    local user_rule = find_rule_by_id(profile, "2.3.3")

    assert(find_probe(configured_rule, "chrony_configuration").func == "chrony.inspect_configuration",
        "Expected 2.3.2 to parse chrony configuration and included source files structurally")
    assert(assertion_tree_contains_key(configured_rule.assertion, "config_available"),
        "Expected 2.3.2 to fail clearly when chrony configuration cannot be read")
    assert(assertion_tree_contains_key(configured_rule.assertion, "has_time_source"),
        "Expected 2.3.2 to require an active server or pool directive")
    assert(find_probe(user_rule, "chrony_configuration").func == "chrony.inspect_configuration",
        "Expected 2.3.3 to parse chronyd sysconfig through the chrony probe")
    assert(assertion_tree_contains_key(user_rule.assertion, "non_root_configured"),
        "Expected 2.3.3 to fail when chronyd sysconfig is missing or runs chrony as root")
end

function test_cis_profile_firewalld_rules_cover_backend_and_service_state()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local backend_rule = find_rule_by_id(profile, "4.1.2")
    local service_rule = find_rule_by_id(profile, "4.1.3")
    local zone_rule = find_rule_by_id(profile, "4.1.4")

    assert(find_probe(backend_rule, "firewalld_conf").func == "file.parse_key_values",
        "Expected 4.1.2 to parse firewalld.conf structurally")
    assert(find_probe(backend_rule, "firewalld_conf").params.normalize_values == "lower",
        "Expected 4.1.2 to compare FirewallBackend case-insensitively")
    assert(find_probe(backend_rule, "firewalld_conf").params.allow_missing == true,
        "Expected missing firewalld.conf to fail the rule without becoming an engine error")
    assert(assertion_tree_contains_key(backend_rule.assertion, "FirewallBackend"),
        "Expected 4.1.2 to require FirewallBackend=nftables")
    assert(find_probe(service_rule, "firewalld_service").func == "services.get_unit_properties",
        "Expected 4.1.3 to query systemd service state")
    assert(assertion_tree_contains_key(service_rule.assertion, "UnitFileState"),
        "Expected 4.1.3 to require firewalld.service enabled")
    assert(assertion_tree_contains_key(service_rule.assertion, "ActiveState"),
        "Expected 4.1.3 to require firewalld.service active")
    assert(find_probe(zone_rule, "firewalld_active_zone_targets").func == "firewalld.inspect_active_zone_targets",
        "Expected 4.1.4 to inspect active zone targets structurally")
    assert(assertion_tree_contains_key(zone_rule.assertion, "available"),
        "Expected 4.1.4 to report unavailable firewall-cmd evidence clearly")
    assert(assertion_tree_contains_key(zone_rule.assertion, "checked_count"),
        "Expected 4.1.4 to reject missing active non-loopback zone evidence")
    assert(assertion_tree_contains_key(zone_rule.assertion, "violation_count"),
        "Expected 4.1.4 to reject ACCEPT, empty, or non-permanent zone targets")
end

function test_cis_profile_uses_effective_sysctl_probe_for_cis_sysctl_rules()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local offenders = {}

    for _, rule in ipairs(profile.rules or {}) do
        local probes = rule.probes or {}
        if probes.func then
            probes = { probes }
        end
        for _, probe in ipairs(probes) do
            if probe.func == "sysctl.get_live_value" then
                offenders[#offenders + 1] = rule.id
            end
        end
    end

    assert(#offenders == 0,
        "Expected CIS sysctl rules to validate live and persistent values, offenders: " ..
        table.concat(offenders, ", "))
end

function test_cis_profile_uses_effective_section_aware_systemd_config()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local expectations = {
        ["1.5.8"] = { "coredump_conf", "Coredump" },
        ["1.5.9"] = { "coredump_conf", "Coredump" },
        ["6.2.2.3"] = { "journald_conf", "Journal" },
        ["6.2.1.1.6"] = { "journald_conf", "Journal" },
        ["6.2.1.1.5"] = { "journald_conf", "Journal" },
    }

    for rule_id, expectation in pairs(expectations) do
        local rule = find_rule_by_id(profile, rule_id)
        local probe = find_probe(rule, expectation[1])

        assert(probe.params.effective == true,
            "Expected " .. rule_id .. " to account for systemd main-file and drop-in precedence")
        assert(probe.params.section == expectation[2],
            "Expected " .. rule_id .. " to parse only the relevant systemd section")
    end
end

function test_cis_profile_uses_structured_logging_and_aide_probes()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local aide_rule = find_rule_by_id(profile, "6.1.3")
    local file_mode_rule = find_rule_by_id(profile, "6.2.2.4")
    local remote_input_rule = find_rule_by_id(profile, "6.2.2.7")
    local journald_rule = find_rule_by_id(profile, "6.2.1.1.4")
    local logfile_rule = find_rule_by_id(profile, "6.2.3.1")

    assert(find_probe(aide_rule, "aide_audit_tools").func == "aide.inspect_required_file_rules",
        "Expected 6.1.3 to inspect AIDE audit-tool rules structurally")
    assert(find_probe(file_mode_rule, "rsyslog_effective_config").func == "syslog.inspect_rsyslog_effective_config",
        "Expected 6.2.2.4 to parse rsyslog configuration structurally")
    assert(find_probe(remote_input_rule, "rsyslog_effective_config").func == "syslog.inspect_rsyslog_effective_config",
        "Expected 6.2.2.7 to parse rsyslog remote-input directives structurally")
    assert(find_probe(journald_rule, "journald_conf").func == "journald.inspect_forward_to_syslog_disabled",
        "Expected 6.2.1.1.4 to apply journald boolean defaults structurally")
    assert(find_probe(logfile_rule, "logfile_access").func == "logging.inspect_logfile_access",
        "Expected 6.2.3.1 to inspect logfile access with path-specific policy")
    assert(assertion_tree_contains_key(aide_rule.assertion, "available"),
        "Expected 6.1.3 to expose unavailable AIDE evidence in-band")
    assert(assertion_tree_contains_key(logfile_rule.assertion, "checked_count"),
        "Expected 6.2.3.1 to reject missing logfile evidence")
end

function test_cis_profile_uses_structured_audit_rule_coverage()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local backlog_rule = find_rule_by_id(profile, "6.3.1.3")
    local user_emulation_rule = find_rule_by_id(profile, "6.3.3.2")
    local access_rule = find_rule_by_id(profile, "6.3.3.7")
    local privileged_rule = find_rule_by_id(profile, "6.3.3.6")
    local immutable_rule = find_rule_by_id(profile, "6.3.3.21")
    local user_emulation_probe = find_probe(user_emulation_rule, "user_emulation_audit_rules")
    local access_probe = find_probe(access_rule, "access_audit_rules")

    assert(find_probe(backlog_rule, "audit_backlog_limit").func == "boot.inspect_kernel_parameter",
        "Expected 6.3.1.3 to parse boot parameter values numerically")
    assert(user_emulation_probe.func == "audit.inspect_rule_coverage",
        "Expected 6.3.3.2 to use structured audit rule coverage")
    assert(user_emulation_probe.params.requirements[1].comparisons_any[1] == "euid!=uid",
        "Expected 6.3.3.2 to require uid/euid comparison semantics")
    assert(access_probe.params.requirements[1].exits[1] == "EACCES",
        "Expected 6.3.3.7 to require unsuccessful access exit filters")
    assert(find_probe(privileged_rule, "privileged_command_audit_rules").func == "audit.inspect_privileged_command_coverage",
        "Expected 6.3.3.6 to derive privileged command audit requirements")
    assert(find_probe(immutable_rule, "audit_immutable").params.sources[1] == "persistent",
        "Expected 6.3.3.21 to inspect final persistent audit directives")
end

function test_cis_profile_gdm_rules_use_current_dconf_user_database_and_locks()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local banner_rule = find_rule_by_id(profile, "1.8.1")
    local user_list_rule = find_rule_by_id(profile, "1.8.2")
    local banner_enable_probe = find_probe(banner_rule, "gdm_banner_enable_check")
    local banner_text_probe = find_probe(banner_rule, "gdm_banner_text_check")
    local disable_user_list_probe = find_probe(user_list_rule, "gdm_disable_user_list_check")

    assert(find_probe(banner_rule, "gdm_profile_check").params.paths[1] == "/etc/dconf/profile/user",
        "Expected GDM banner rule to use /etc/dconf/profile/user")
    assert(find_probe(banner_rule, "gdm_profile_local_db_check") ~= nil,
        "Expected GDM banner rule to require system-db:local")
    assert(find_probe(banner_rule, "gdm_installed").func == "packages.get_installed",
        "Expected GDM banner rule to be not applicable when gdm is absent")
    assert(banner_enable_probe.func == "file.get_effective_key_value",
        "Expected GDM banner rule to validate the effective dconf key value")
    assert(banner_enable_probe.params.paths[1] == "/etc/dconf/db/local.d/*",
        "Expected GDM banner rule to use the local dconf database")
    assert(banner_enable_probe.params.section == "org/gnome/login-screen",
        "Expected GDM banner rule not to match banner keys in unrelated dconf sections")
    assert(banner_text_probe.params.section == "org/gnome/login-screen"
        and banner_text_probe.params.require_non_empty_value == true,
        "Expected GDM banner text rule to require a non-empty login-screen value")
    assert(find_probe(banner_rule, "gdm_banner_enable_lock_check").params.paths[1] == "/etc/dconf/db/local.d/locks/*",
        "Expected GDM banner rule to check dconf locks")
    assert(disable_user_list_probe.func == "file.get_effective_key_value",
        "Expected GDM user-list rule to validate the effective dconf key value")
    assert(disable_user_list_probe.params.paths[1] == "/etc/dconf/db/local.d/*",
        "Expected GDM user-list rule to use the local dconf database")
    assert(disable_user_list_probe.params.section == "org/gnome/login-screen",
        "Expected GDM user-list rule not to match keys in unrelated dconf sections")
    assert(find_probe(user_list_rule, "gdm_disable_user_list_lock_check").params.paths[1] == "/etc/dconf/db/local.d/locks/*",
        "Expected GDM user-list rule to check dconf locks")
end

function test_cis_profile_gdm_rules_are_not_applicable_when_gdm_is_absent()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))

    for _, rule_id in ipairs({ "1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6", "1.8.7" }) do
        local rule = find_rule_by_id(profile, rule_id)
        local has_absent_branch = false

        assert(find_probe(rule, "gdm_installed").func == "packages.get_installed",
            "Expected " .. rule_id .. " to query gdm package applicability")
        walk_assertion_nodes(rule.assertion, function(node)
            if node.actual == "%{probe.gdm_installed}"
                and node.key == "count"
                and node.compare == "equals"
                and node.expected == 0 then
                has_absent_branch = true
            end
        end)
        assert(has_absent_branch == true,
            "Expected " .. rule_id .. " to pass as not applicable when gdm is absent")
    end
end

function test_cis_profile_xdmcp_rule_is_section_aware()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "1.8.6")
    local probe = find_probe(rule, "xdmcp_check")

    assert(probe.func == "file.get_effective_key_value",
        "Expected XDMCP rule to parse the effective custom.conf value structurally")
    assert(probe.params.section == "xdmcp",
        "Expected XDMCP rule not to match Enable=true outside the xdmcp section")
    assert(probe.params.key == "Enable" and probe.params.expected_value == "true",
        "Expected XDMCP rule to detect Enable=true in the xdmcp section")
end

function test_cis_profile_gdm_followup_rules_use_structured_dconf_checks()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local screen_lock_rule = find_rule_by_id(profile, "1.8.3")
    local automount_rule = find_rule_by_id(profile, "1.8.4")
    local autorun_rule = find_rule_by_id(profile, "1.8.5")
    local xwayland_rule = find_rule_by_id(profile, "1.8.7")
    local idle_probe = find_probe(screen_lock_rule, "gdm_idle_delay")
    local lock_probe = find_probe(screen_lock_rule, "gdm_lock_delay")
    local automount_probe = find_probe(automount_rule, "gdm_automount")
    local autorun_probe = find_probe(autorun_rule, "gdm_autorun_never")
    local xwayland_probe = find_probe(xwayland_rule, "xwayland_check")

    assert(idle_probe.func == "file.get_effective_key_value"
        and idle_probe.params.section == "org/gnome/desktop/session"
        and idle_probe.params.numeric_min == 1
        and idle_probe.params.numeric_max == 900,
        "Expected GDM idle-delay to require a non-zero value of 900 seconds or less")
    assert(lock_probe.func == "file.get_effective_key_value"
        and lock_probe.params.section == "org/gnome/desktop/screensaver"
        and lock_probe.params.numeric_max == 5,
        "Expected GDM lock-delay to require 5 seconds or less")
    assert(automount_probe.func == "file.get_effective_key_value"
        and automount_probe.params.section == "org/gnome/desktop/media-handling"
        and automount_probe.params.expected_value == "false",
        "Expected GDM automount rule to require false in the media-handling section")
    assert(autorun_probe.func == "file.get_effective_key_value"
        and autorun_probe.params.section == "org/gnome/desktop/media-handling"
        and autorun_probe.params.expected_value == "true",
        "Expected GDM autorun-never rule to require true in the media-handling section")
    assert(xwayland_probe.func == "file.get_effective_key_value"
        and xwayland_probe.params.section == "daemon"
        and xwayland_probe.params.key == "WaylandEnable"
        and xwayland_probe.params.expected_value == "false",
        "Expected Xwayland rule to require WaylandEnable=false in the daemon section")
end

function test_cis_profile_sudo_rules_cover_v2_defaults()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local sudo_pkg_rule = find_rule_by_id(profile, "5.2.1")
    local use_pty_rule = find_rule_by_id(profile, "5.2.2")
    local logfile_rule = find_rule_by_id(profile, "5.2.3")
    local nopasswd_rule = find_rule_by_id(profile, "5.2.4")
    local reauth_rule = find_rule_by_id(profile, "5.2.5")
    local timestamp_rule = find_rule_by_id(profile, "5.2.6")
    local su_rule = find_rule_by_id(profile, "5.2.7")

    assert(find_probe(sudo_pkg_rule, "sudo_installed").func == "packages.get_installed",
        "Expected sudo package rule to query sudo package state")
    assert(find_probe(use_pty_rule, "sudo_use_pty_check").func == "sudo.find_use_pty",
        "Expected sudo use_pty rule to parse active sudoers configuration")
    assert(find_probe(logfile_rule, "sudo_logfile_check").func == "sudo.find_logfile_entries",
        "Expected sudo logfile rule to parse Defaults logfile entries structurally")
    assert(find_probe(nopasswd_rule, "sudo_nopasswd_check").func == "sudo.find_nopasswd_entries",
        "Expected sudo NOPASSWD rule to parse active sudoers configuration")
    assert(find_probe(reauth_rule, "sudo_global_reauth_disabled").func == "sudo.find_global_reauth_disabled",
        "Expected sudo re-authentication rule to reject global !authenticate Defaults entries structurally")
    assert(find_probe(timestamp_rule, "sudo_timestamp_timeout_invalid").func == "sudo.find_invalid_timestamp_timeout",
        "Expected sudo timestamp rule to reject disabled or excessive timestamp timeouts structurally")
    assert(find_probe(timestamp_rule, "sudo_timestamp_timeout_invalid").params.max_minutes == 15,
        "Expected CIS sudo timestamp timeout rule to cap configured values at 15 minutes")
    assert(find_probe(su_rule, "su_pam_wheel_check").func == "pam.inspect_wheel",
        "Expected su restriction rule to reuse the structured pam_wheel probe")
    assert(find_probe(su_rule, "su_pam_wheel_check").params.require_empty_group == true,
        "Expected su restriction rule to require an empty pam_wheel group")
    assert(su_rule.level[1] == "l1_server" and su_rule.level[2] == nil,
        "Expected su restriction rule to follow CIS Level 1 Server applicability")
end

function test_cis_profile_pam_rules_use_deep_package_authselect_and_pam_probes()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))

    assert(find_probe(find_rule_by_id(profile, "5.3.1.1"), "pam_version").func == "packages.inspect_min_version",
        "Expected pam version rule to use RPM minimum-version semantics")
    assert(find_probe(find_rule_by_id(profile, "5.3.1.2"), "authselect_version").params.minimum == "1.2.6-1",
        "Expected authselect version rule to encode the CIS minimum EVR, not an exact release string")
    assert(find_probe(find_rule_by_id(profile, "5.3.2.1"), "authselect_profile_modules").func
        == "authselect.inspect_profile_modules",
        "Expected active authselect profile module checks to stay out of YAML regexes")
    assert(find_probe(find_rule_by_id(profile, "5.3.2.2"), "faillock_module").func == "pam.inspect_module",
        "Expected pam_faillock enablement to use structured PAM stack inspection")
    assert(find_probe(find_rule_by_id(profile, "5.3.2.5"), "unix_module").func == "pam.inspect_unix",
        "Expected pam_unix enablement to use structured PAM stack inspection")
    assert(find_probe(find_rule_by_id(profile, "5.3.3.1.1"), "faillock_deny").func
        == "pam.inspect_faillock_setting",
        "Expected faillock argument controls to hide config/module precedence in a probe")
    assert(find_probe(find_rule_by_id(profile, "5.3.3.2.2"), "pwquality_minlen").params.config_paths[1]
        == "/etc/security/pwquality.conf.d/*.conf",
        "Expected pwquality config precedence to let /etc/security/pwquality.conf override conf.d files")
    assert(find_probe(find_rule_by_id(profile, "5.3.3.3.1"), "pwhistory_remember").func
        == "pam.inspect_pwhistory_setting",
        "Expected pwhistory controls to use a setting-level probe")
    assert(find_probe(find_rule_by_id(profile, "5.3.3.4.3"), "unix_strong_hash").params.check
        == "strong_hash",
        "Expected pam_unix hashing policy to be encapsulated by the pam_unix probe")

    assert(find_rule_by_id(profile, "5.3.3.1.3").level[1] == "l2_server",
        "Expected root faillock control to follow CIS Level 2 Server applicability")
    assert(find_rule_by_id(profile, "5.3.3.2.3") == nil,
        "Expected manual CIS password complexity control not to be represented as an automated rule")
end

function test_cis_profile_user_account_environment_rules_use_deep_account_probes()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))

    assert(find_rule_by_id(profile, "5.4.1.1").level[1] == "l1_server"
        and find_rule_by_id(profile, "5.4.1.1").level[2] == nil,
        "Expected CIS 5.4.1.1 to follow server-only PDF applicability")
    assert(find_probe(find_rule_by_id(profile, "5.4.1.4"), "login_defs").params.normalize_values == "lower",
        "Expected ENCRYPT_METHOD comparison to be case-insensitive through normalized values")
    assert(find_probe(find_rule_by_id(profile, "5.4.1.6"), "password_change_dates").func
        == "users.inspect_future_password_changes",
        "Expected future password-change dates to use structured shadow date evidence")
    assert(find_probe(find_rule_by_id(profile, "5.4.2.1"), "uid_zero_accounts").func
        == "users.inspect_identity",
        "Expected UID 0 checks to parse passwd structurally")
    assert(find_probe(find_rule_by_id(profile, "5.4.2.3"), "gid_zero_groups").params.check
        == "gid_zero_groups",
        "Expected GID 0 group checks to parse group identity structurally")
    assert(find_probe(find_rule_by_id(profile, "5.4.2.4"), "root_access").func
        == "users.inspect_root_access",
        "Expected root access control to inspect root shadow status structurally")
    assert(find_probe(find_rule_by_id(profile, "5.4.2.5"), "root_path").func
        == "users.inspect_root_path",
        "Expected root PATH integrity to be hidden behind a deep users probe")
    assert(find_probe(find_rule_by_id(profile, "5.4.2.7"), "system_account_shells").func
        == "users.inspect_system_account_shells",
        "Expected system account shell checks to use /etc/shells and passwd together")
    assert(find_probe(find_rule_by_id(profile, "5.4.2.8"), "nonlogin_accounts_locked").func
        == "users.inspect_nonlogin_accounts_locked",
        "Expected non-login-shell lock checks to join passwd, shells, and shadow")
    assert(find_rule_by_id(profile, "5.4.3.1").level[1] == "l2_server",
        "Expected nologin-in-shells control to follow CIS Level 2 Server applicability")
    assert(find_probe(find_rule_by_id(profile, "5.4.3.2"), "shell_timeout").func == "shell.inspect_tmout",
        "Expected default shell timeout to validate TMOUT value, readonly, and export in one probe")
    assert(find_probe(find_rule_by_id(profile, "5.4.3.3"), "login_defs_umask").func == "shell.check_umask_value",
        "Expected login.defs UMASK to use semantic umask comparison")
end

function test_cis_profile_ssh_access_rules_use_structured_probes()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local crypto_rule = find_rule_by_id(profile, "5.1.1")
    local config_rule = find_rule_by_id(profile, "5.1.2")
    local private_key_rule = find_rule_by_id(profile, "5.1.4")
    local public_key_rule = find_rule_by_id(profile, "5.1.5")
    local access_rule = find_rule_by_id(profile, "5.1.6")
    local banner_rule = find_rule_by_id(profile, "5.1.7")
    local ciphers_rule = find_rule_by_id(profile, "5.1.8")
    local alive_rule = find_rule_by_id(profile, "5.1.9")
    local kex_rule = find_rule_by_id(profile, "5.1.14")
    local loglevel_rule = find_rule_by_id(profile, "5.1.16")
    local macs_rule = find_rule_by_id(profile, "5.1.17")
    local max_startups_rule = find_rule_by_id(profile, "5.1.20")

    assert(find_probe(crypto_rule, "sshd_crypto_policy").func == "ssh.inspect_sysconfig_crypto_policy",
        "Expected sshd crypto policy rule to distinguish active and commented CRYPTO_POLICY lines structurally")
    assert(assertion_tree_contains_key(crypto_rule.assertion, "commented_present") == false,
        "Expected sshd crypto policy compliance not to require a commented remediation artifact")
    assert(find_probe(config_rule, "sshd_config_access").func == "ssh.inspect_config_file_access",
        "Expected sshd config access rule to check main config, drop-ins, and Include targets in one probe")
    assert(find_probe(private_key_rule, "ssh_private_host_key_access").func == "ssh.inspect_private_host_key_access",
        "Expected private host key rule to encapsulate root/ssh_keys ownership policy")
    assert(assertion_tree_contains_key(private_key_rule.assertion, "available"),
        "Expected private host key rule to fail when SSH key directory evidence is unavailable")
    assert(find_probe(public_key_rule, "ssh_public_host_key_access").func == "ssh.inspect_public_host_key_access",
        "Expected public host key rule to encapsulate public key access policy")
    assert(find_probe(access_rule, "sshd_access_restrictions").func == "ssh.inspect_access_restrictions",
        "Expected SSH access restriction rule to use effective sshd settings")
    assert(find_probe(banner_rule, "sshd_banner").func == "ssh.inspect_banner",
        "Expected SSH Banner rule to validate effective value, target file, and OS disclosure in one probe")
    assert(find_probe(ciphers_rule, "sshd_ciphers").func == "ssh.inspect_effective_algorithm_list",
        "Expected SSH Ciphers rule to parse effective algorithms structurally")
    assert(find_probe(alive_rule, "client_alive_interval").func == "ssh.inspect_effective_setting"
        and find_probe(alive_rule, "client_alive_count_max").func == "ssh.inspect_effective_setting",
        "Expected SSH ClientAlive rule to use bounded effective setting probes")
    assert(find_probe(kex_rule, "sshd_kex_algorithms").func == "ssh.inspect_effective_algorithm_list",
        "Expected SSH KexAlgorithms rule to parse effective algorithms structurally")
    assert(find_probe(loglevel_rule, "sshd_loglevel").params.allowed_values[2] == "VERBOSE",
        "Expected SSH LogLevel rule to allow INFO or VERBOSE")
    assert(find_probe(macs_rule, "sshd_macs").func == "ssh.inspect_effective_algorithm_list",
        "Expected SSH MACs rule to parse effective algorithms structurally")
    assert(find_probe(max_startups_rule, "max_startups").params.value_type == "colon_numbers",
        "Expected SSH MaxStartups rule to compare tuple values semantically")
end

function test_cis_profile_auditd_disk_full_rule_uses_v2_keys()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "6.3.2.3")
    local keys = {}

    walk_assertion_nodes(rule.assertion, function(node)
        if node.key then
            keys[node.key] = true
        end
    end)

    assert(keys.disk_full_action == true, "Expected 6.3.2.3 to validate disk_full_action")
    assert(keys.disk_error_action == true, "Expected 6.3.2.3 to validate disk_error_action")
    assert(keys.space_left_action ~= true, "Expected 6.3.2.3 not to use the wrong space_left_action key")
    assert(keys.action_mail_acct ~= true, "Expected 6.3.2.3 not to use the wrong action_mail_acct key")
    assert(keys.admin_space_left_action ~= true, "Expected 6.3.2.3 not to use the wrong admin_space_left_action key")
end

function test_cis_profile_cron_and_at_access_rules_match_v2_semantics()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local cron_rule = find_rule_by_id(profile, "2.4.1.9")
    local at_rule = find_rule_by_id(profile, "2.4.2.1")

    assert(find_probe(cron_rule, "crontab_group") ~= nil,
        "Expected cron access rule to allow the crontab group")
    assert(find_probe(at_rule, "daemon_group") ~= nil,
        "Expected at access rule to allow the daemon group")

    for _, rule in ipairs({ cron_rule, at_rule }) do
        local has_deny_absent_branch = false
        local has_0640_mode = false
        walk_assertion_nodes(rule.assertion, function(node)
            if node.key == "exists" and node.compare == "is_falsy" then
                has_deny_absent_branch = true
            end
            if node.key == "mode" and node.expected == octal("640") then
                has_0640_mode = true
                assert(node.compare == "mode_is_no_more_permissive",
                    "Expected cron/at allow and deny modes to use semantic mode comparisons")
            end
        end)
        assert(has_deny_absent_branch == true,
            "Expected deny files to be allowed when absent instead of required absent")
        assert(has_0640_mode == true,
            "Expected cron/at access files to allow 0640 or stricter modes")
    end
end

function test_cis_profile_account_aging_thresholds_match_v2()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local max_rule = find_rule_by_id(profile, "5.4.1.1")
    local inactive_rule = find_rule_by_id(profile, "5.4.1.5")
    local has_pass_max_positive = false
    local has_shadow_pass_max_positive = false
    local has_inactive_45 = false
    local has_inactive_nonnegative = false

    walk_assertion_nodes(max_rule.assertion, function(node)
        if node.key == "PASS_MAX_DAYS" and node.compare == "is_greater_than" and node.expected == 0 then
            has_pass_max_positive = true
        end
        if node.key == "pass_max_days" and node.compare == "is_greater_than" and node.expected == 0 then
            has_shadow_pass_max_positive = true
        end
    end)
    walk_assertion_nodes(inactive_rule.assertion, function(node)
        if (node.key == "INACTIVE" or node.key == "inactive")
            and node.compare == "is_less_than_or_equal_to"
            and node.expected == 45 then
            has_inactive_45 = true
        end
        if (node.key == "INACTIVE" or node.key == "inactive")
            and node.compare == "is_greater_than_or_equal_to"
            and node.expected == 0 then
            has_inactive_nonnegative = true
        end
    end)

    assert(has_pass_max_positive == true,
        "Expected PASS_MAX_DAYS to require values greater than 0")
    assert(has_shadow_pass_max_positive == true,
        "Expected password-bearing shadow entries to require pass_max_days greater than 0")
    assert(has_inactive_45 == true,
        "Expected inactive lock threshold to be 45 days")
    assert(has_inactive_nonnegative == true,
        "Expected inactive lock checks to reject disabled/negative values")
end

function test_cis_profile_uses_semantic_mode_comparisons_for_file_modes()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local offenders = {}

    for _, rule in ipairs(profile.rules or {}) do
        walk_assertion_nodes(rule.assertion, function(node)
            if node.key == "mode" and node.compare ~= "mode_is_no_more_permissive" then
                offenders[#offenders + 1] = rule.id .. ":" .. tostring(node.compare)
            end
        end)
    end

    assert(#offenders == 0,
        "Expected CIS file mode checks to use semantic mode comparisons, offenders: " ..
        table.concat(offenders, ", "))
end

function test_cis_profile_dotfile_rule_uses_full_interactive_user_audit_probe()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "7.2.9")

    assert(find_probe(rule, "dotfile_access").func == "users.inspect_dotfiles",
        "Expected dotfile rule to check forbidden files, ownership, groups, and per-file mode thresholds")
    assert(find_probe(rule, "rhosts_files_check") == nil,
        "Expected dotfile rule not to use the stale .rhosts filename")
end

function test_cis_profile_banner_patterns_match_literal_issue_escapes()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))

    for _, rule_id in ipairs({ "1.7.1", "1.7.2", "1.7.3" }) do
        local rule = find_rule_by_id(profile, rule_id)
        local probe = find_probe(rule, rule_id == "1.7.1" and "motd_info_leak_check"
            or rule_id == "1.7.2" and "issue_info_leak_check"
            or "issue_net_info_leak_check")
        local path = "/tmp/loongshield_test_banner.conf"

        assert(probe ~= nil, "Expected " .. rule_id .. " to define an information leak probe")

        write_temp_file(path, "Authorized access only\n")
        local clean_result, clean_err = file_probe.find_pattern({
            paths = { path },
            pattern = probe.params.pattern,
        })

        write_temp_file(path, "Kernel \\r on \\m\n")
        local escape_result, escape_err = file_probe.find_pattern({
            paths = { path },
            pattern = probe.params.pattern,
        })

        os.remove(path)

        assert(clean_err == nil, "Expected clean banner pattern evaluation to succeed for " .. rule_id)
        assert(clean_result.found == false,
            "Expected ordinary banner text not to match literal issue escape checks for " .. rule_id)
        assert(escape_err == nil, "Expected escaped banner pattern evaluation to succeed for " .. rule_id)
        assert(escape_result.found == true,
            "Expected literal issue escape sequences to be detected for " .. rule_id)
    end
end

function test_agentos_baseline_service_disable_rules_require_not_running_state()
    local profile = lyaml.load(read_file("profiles/seharden/agentos_baseline.yml"))
    local avahi_rule = find_rule_by_id(profile, "services.avahi_disabled")
    local cups_rule = find_rule_by_id(profile, "services.cups_disabled")

    for _, rule in ipairs({ avahi_rule, cups_rule }) do
        assert(rule ~= nil, "Expected agentos_baseline to define service disable rules")
        assert(type(rule.assertion.any_of) == "table" and #rule.assertion.any_of == 3,
            "Expected service disable rules to allow disabled, masked, or not-found outcomes")

        for index = 1, 2 do
            local branch = rule.assertion.any_of[index]
            assert(type(branch.all_of) == "table" and #branch.all_of == 2,
                "Expected disabled and masked branches to require both unit file and active state checks")
            assert(branch.all_of[1].key == "UnitFileState",
                "Expected the first branch condition to validate UnitFileState")
            assert(type(branch.all_of[2].any_of) == "table" and #branch.all_of[2].any_of == 3,
                "Expected the second branch condition to allow only specific non-running ActiveState values")
            assert(branch.all_of[2].any_of[1].key == "ActiveState",
                "Expected ActiveState checks for disabled and masked services")
            assert(branch.all_of[2].any_of[1].expected == "inactive",
                "Expected inactive services to be accepted")
            assert(branch.all_of[2].any_of[2].expected == "failed",
                "Expected failed services to be accepted as not running")
            assert(branch.all_of[2].any_of[3].expected == "unknown",
                "Expected unknown ActiveState to remain acceptable in constrained environments")
        end

        assert(rule.assertion.any_of[3].key == "UnitFileState"
            and rule.assertion.any_of[3].expected == "not-found",
            "Expected not-found units to remain compliant without an ActiveState check")
    end
end

function test_agentos_baseline_network_rules_cover_all_and_default_interfaces()
    local profile = lyaml.load(read_file("profiles/seharden/agentos_baseline.yml"))
    local rp_filter_rule = find_rule_by_id(profile, "net.rp_filter")
    local log_martians_rule = find_rule_by_id(profile, "net.log_martians")

    assert(rp_filter_rule ~= nil, "Expected agentos_baseline to define net.rp_filter")
    assert(find_probe(rp_filter_rule, "rpfilter_all").params.key == "net.ipv4.conf.all.rp_filter",
        "Expected net.rp_filter to probe the all-interface value")
    assert(find_probe(rp_filter_rule, "rpfilter_default").params.key == "net.ipv4.conf.default.rp_filter",
        "Expected net.rp_filter to probe the default-interface value")
    assert(type(rp_filter_rule.assertion.all_of) == "table" and #rp_filter_rule.assertion.all_of == 2,
        "Expected net.rp_filter to require both all and default settings")
    assert((rp_filter_rule.reinforce or {})[2].params.key == "net.ipv4.conf.default.rp_filter",
        "Expected net.rp_filter reinforce steps to persist the default-interface value")

    assert(log_martians_rule ~= nil, "Expected agentos_baseline to define net.log_martians")
    assert(find_probe(log_martians_rule, "martians_all").params.key == "net.ipv4.conf.all.log_martians",
        "Expected net.log_martians to probe the all-interface value")
    assert(find_probe(log_martians_rule, "martians_default").params.key == "net.ipv4.conf.default.log_martians",
        "Expected net.log_martians to probe the default-interface value")
    assert(type(log_martians_rule.assertion.all_of) == "table" and #log_martians_rule.assertion.all_of == 2,
        "Expected net.log_martians to require both all and default settings")
    assert((log_martians_rule.reinforce or {})[2].params.key == "net.ipv4.conf.default.log_martians",
        "Expected net.log_martians reinforce steps to persist the default-interface value")
end

function test_agentos_baseline_openclaw_level_inherits_baseline()
    local profile = lyaml.load(read_file("profiles/seharden/agentos_baseline.yml"))
    local openclaw_level

    assert(profile.default_level == "baseline",
        "Expected agentos_baseline to keep baseline as the default selected level")

    for _, level in ipairs(profile.levels or {}) do
        if level.id == "openclaw" then
            openclaw_level = level
            break
        end
    end

    assert(openclaw_level ~= nil, "Expected agentos_baseline to define an openclaw level")
    assert(type(openclaw_level.inherits_from) == "table" and openclaw_level.inherits_from[1] == "baseline",
        "Expected openclaw to inherit baseline protections")
end

function test_agentos_baseline_openclaw_host_hardening_rules_are_scoped_and_wired()
    local profile = lyaml.load(read_file("profiles/seharden/agentos_baseline.yml"))
    local bpf_rule = find_rule_by_id(profile, "kernel.unprivileged_bpf_disabled")
    local perf_rule = find_rule_by_id(profile, "kernel.perf_event_paranoid")
    local tmp_nosuid_rule = find_rule_by_id(profile, "fs.tmp_nosuid")
    local tmp_nodev_rule = find_rule_by_id(profile, "fs.tmp_nodev")
    local protected_symlinks_rule = find_rule_by_id(profile, "fs.protected_symlinks")
    local protected_hardlinks_rule = find_rule_by_id(profile, "fs.protected_hardlinks")

    for _, rule in ipairs({
        bpf_rule,
        perf_rule,
        tmp_nosuid_rule,
        tmp_nodev_rule,
        protected_symlinks_rule,
        protected_hardlinks_rule,
    }) do
        assert(rule ~= nil, "Expected agentos_baseline to include the remote OpenClaw host-hardening rules")
        assert(rule.level[1] == "openclaw", "Expected OpenClaw host-hardening rules to stay scoped to openclaw")
    end

    assert(find_probe(bpf_rule, "bpf").params.key == "kernel.unprivileged_bpf_disabled",
        "Expected BPF rule to use the unprivileged BPF sysctl")
    assert(bpf_rule.assertion.expected == 1,
        "Expected BPF rule to require the sysctl to be disabled")

    assert(find_probe(perf_rule, "perf").params.key == "kernel.perf_event_paranoid",
        "Expected perf rule to use the perf_event_paranoid sysctl")
    assert(perf_rule.assertion.expected == 2,
        "Expected perf rule to require a sufficiently paranoid setting")

    assert(find_probe(tmp_nosuid_rule, "tmp").params.path == "/tmp",
        "Expected /tmp nosuid rule to inspect the /tmp mount")
    assert(tmp_nosuid_rule.assertion.key == "options" and tmp_nosuid_rule.assertion.expected == "nosuid",
        "Expected /tmp nosuid rule to require the nosuid mount option")

    assert(find_probe(tmp_nodev_rule, "tmp").params.path == "/tmp",
        "Expected /tmp nodev rule to inspect the /tmp mount")
    assert(tmp_nodev_rule.assertion.key == "options" and tmp_nodev_rule.assertion.expected == "nodev",
        "Expected /tmp nodev rule to require the nodev mount option")

    assert(find_probe(protected_symlinks_rule, "protected_symlinks").params.key == "fs.protected_symlinks",
        "Expected symlink-protection rule to inspect the fs.protected_symlinks sysctl")
    assert(protected_symlinks_rule.assertion.expected == "1",
        "Expected symlink-protection rule to require value 1")

    assert(find_probe(protected_hardlinks_rule, "protected_hardlinks").params.key == "fs.protected_hardlinks",
        "Expected hardlink-protection rule to inspect the fs.protected_hardlinks sysctl")
    assert(protected_hardlinks_rule.assertion.expected == "1",
        "Expected hardlink-protection rule to require value 1")

    assert(find_rule_by_id(profile, "ssh.permit_root_login") == nil,
        "Expected OpenClaw profile to leave SSH root-login policy to manual review")
    assert(find_rule_by_id(profile, "ssh.max_auth_tries") == nil,
        "Expected OpenClaw profile to leave SSH MaxAuthTries policy to manual review")
end

function test_agentos_baseline_openclaw_rules_only_check_default_path_permissions()
    local profile = lyaml.load(read_file("profiles/seharden/agentos_baseline.yml"))
    local state_rule = find_rule_by_id(profile, "openclaw.state_dir_private")
    local config_rule = find_rule_by_id(profile, "openclaw.config_private")
    local credentials_rule = find_rule_by_id(profile, "openclaw.credentials_dir_private")

    for _, rule in ipairs({ state_rule, config_rule, credentials_rule }) do
        assert(rule ~= nil, "Expected agentos_baseline to define OpenClaw default-path rules")
        assert(rule.level[1] == "openclaw", "Expected OpenClaw rules to stay scoped to the openclaw level")
        assert(find_probe(rule, "login_users").func == "users.get_all",
            "Expected OpenClaw rules to enumerate login-shell accounts")
    end

    assert(find_probe(state_rule, "openclaw_state_dirs").func == "meta.map",
        "Expected state-dir rule to reuse meta.map")
    assert(find_probe(state_rule, "openclaw_state_dirs").params.params_template.path == "%{item.home}/.openclaw",
        "Expected state-dir rule to target the default ~/.openclaw path")
    assert(state_rule.assertion.compare == "for_all",
        "Expected state-dir rule to validate each discovered account path independently")
    assert(state_rule.assertion.expected.any_of[1].key == "exists"
        and state_rule.assertion.expected.any_of[1].compare == "is_false",
        "Expected missing default state directories to remain non-failing")
    assert(state_rule.assertion.expected.any_of[2].all_of[1].key == "uid"
        and state_rule.assertion.expected.any_of[2].all_of[1].expected == "%{item.user_uid}",
        "Expected ~/.openclaw to remain owned by the matched account uid")
    assert(state_rule.assertion.expected.any_of[2].all_of[2].expected == octal("700"),
        "Expected ~/.openclaw to be limited to 0700 or stricter")

    assert(find_probe(config_rule, "openclaw_configs").func == "meta.map",
        "Expected config rule to reuse meta.map")
    assert(find_probe(config_rule, "openclaw_configs").params.params_template.path ==
        "%{item.home}/.openclaw/openclaw.json",
        "Expected config rule to target the default openclaw.json path")
    assert(config_rule.assertion.expected.any_of[2].all_of[1].key == "uid"
        and config_rule.assertion.expected.any_of[2].all_of[1].expected == "%{item.user_uid}",
        "Expected openclaw.json to remain owned by the matched account uid")
    assert(config_rule.assertion.expected.any_of[2].all_of[2].expected == octal("600"),
        "Expected openclaw.json to be limited to 0600 or stricter")

    assert(find_probe(credentials_rule, "openclaw_credentials_dirs").func == "meta.map",
        "Expected credentials rule to reuse meta.map")
    assert(find_probe(credentials_rule, "openclaw_credentials_dirs").params.params_template.path ==
        "%{item.home}/.openclaw/credentials",
        "Expected credentials rule to target the default credentials directory")
    assert(credentials_rule.assertion.expected.any_of[2].all_of[1].key == "uid"
        and credentials_rule.assertion.expected.any_of[2].all_of[1].expected == "%{item.user_uid}",
        "Expected credentials directories to remain owned by the matched account uid")
    assert(credentials_rule.assertion.expected.any_of[2].all_of[2].expected == octal("700"),
        "Expected credentials directories to be limited to 0700 or stricter")
end

function test_agentos_baseline_openclaw_manual_review_items_are_level_scoped()
    local profile = seharden_profile.load("profiles/seharden/agentos_baseline.yml")
    local baseline_items = assert(seharden_profile.get_manual_review_items_for_level(profile, "baseline"))
    local openclaw_items = assert(seharden_profile.get_manual_review_items_for_level(profile, "openclaw"))

    assert(#baseline_items == 0, "Expected baseline runs to avoid OpenClaw-only manual review prompts")
    assert(#openclaw_items >= 7, "Expected openclaw level to disclose deployment-specific manual review items")

    local openclaw_profile = { manual_review_required = openclaw_items }
    assert(manual_review_contains(openclaw_profile, "trusted proxy"),
        "Expected manual review items to cover trusted proxy and non-loopback gateway exposure")
    assert(manual_review_contains(openclaw_profile, "OPENCLAW_STATE_DIR"),
        "Expected manual review items to cover custom state directory layouts")
    assert(manual_review_contains(openclaw_profile, "multi-instance"),
        "Expected manual review items to cover multi-instance trust-boundary separation")
    assert(manual_review_contains(openclaw_profile, "root login mode"),
        "Expected manual review items to cover SSH root-login and authentication policy review")
    assert(manual_review_contains(openclaw_profile, "security audit --deep"),
        "Expected manual review items to defer application-semantic audit interpretation to OpenClaw")
    assert(manual_review_contains(openclaw_profile, "cron jobs"),
        "Expected manual review items to cover scheduled automation inventory review")
    assert(manual_review_contains(openclaw_profile, "skill or MCP integrity"),
        "Expected manual review items to cover workspace DLP and skill integrity practices")
end

function test_profiles_define_localhost_conditions_for_ssh_effective_value()
    local profiles = {
        "profiles/seharden/agentos_baseline.yml",
        "profiles/seharden/cis_alinux_3.yml",
        "profiles/seharden/dengbao_3.yml",
    }
    local offenders = {}

    for _, path in ipairs(profiles) do
        local profile = lyaml.load(read_file(path))
        for _, rule_id in ipairs(find_ssh_probes_missing_localhost_conditions(profile)) do
            offenders[#offenders + 1] = path .. ":" .. rule_id
        end
    end

    assert(#offenders == 0,
        "Expected ssh.get_effective_value probes to define supported localhost conditions, offenders: " ..
        table.concat(offenders, ", "))
end

function test_dengbao_profile_loads_and_declares_automated_scope()
    local profile = seharden_profile.load("profiles/seharden/dengbao_3.yml")

    assert(profile ~= nil, "Expected dengbao profile to load successfully")
    assert(contains_text(profile.title, "Automated Profile"),
        "Expected dengbao profile title to describe automated scope explicitly")
    assert(contains_text(profile.description, "manual_review_required"),
        "Expected dengbao profile description to direct readers to manual review coverage notes")
end

function test_dengbao_profile_declares_l1_server_as_default_level()
    local profile = seharden_profile.load("profiles/seharden/dengbao_3.yml")

    assert(profile.default_level == "l1_server",
        "Expected dengbao_3 to default omitted --level selections to l1_server")
    assert(seharden_profile.resolve_target_level(profile, nil) == "l1_server",
        "Expected dengbao_3 default level resolution to return l1_server")
end

function test_dengbao_profile_avoids_site_specific_account_names()
    local text = read_file("profiles/seharden/dengbao_3.yml")

    assert(not contains_text(text, "ack_admin"), "Expected dengbao profile to avoid hardcoded admin account names")
    assert(not contains_text(text, "ack_audit"), "Expected dengbao profile to avoid hardcoded audit account names")
    assert(not contains_text(text, "ack_security"), "Expected dengbao profile to avoid hardcoded security account names")
end

function test_dengbao_profile_does_not_mix_alinux2_only_networkmanager_rule()
    local text = read_file("profiles/seharden/dengbao_3.yml")

    assert(not contains_text(text, "NetworkManager"),
        "Expected dengbao ALinux3 profile not to include the ALinux2-only NetworkManager removal rule")
end

function test_dengbao_profile_accepts_rsyslog_or_syslog_ng_for_audit_logging()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "3.1.2")

    assert(rule ~= nil, "Expected dengbao profile to define audit logging rule 3.1.2")
    assert(rule.desc == "Ensure rsyslog or syslog-ng is installed, enabled, and running",
        "Expected 3.1.2 to accept either rsyslog or syslog-ng")
    assert(find_probe(rule, "rsyslog_pkg") ~= nil, "Expected 3.1.2 to probe the rsyslog package")
    assert(find_probe(rule, "rsyslog_service") ~= nil, "Expected 3.1.2 to probe the rsyslog service")
    assert(find_probe(rule, "syslog_ng_pkg") ~= nil, "Expected 3.1.2 to probe the syslog-ng package")
    assert(find_probe(rule, "syslog_ng_service") ~= nil, "Expected 3.1.2 to probe the syslog-ng service")
    assert(type(rule.assertion) == "table" and type(rule.assertion.any_of) == "table" and #rule.assertion.any_of == 2,
        "Expected 3.1.2 to allow either rsyslog or syslog-ng")
end

function test_dengbao_profile_requires_audit_log_retention_configuration()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "3.1.3")
    local settings_probe

    assert(rule ~= nil, "Expected dengbao profile to define audit storage rule 3.1.3")
    assert(rule.desc == "Ensure audit log size and retention are configured",
        "Expected 3.1.3 to cover both audit log size and retention configuration")

    settings_probe = find_probe(rule, "auditd_conf_settings")
    assert(settings_probe ~= nil, "Expected 3.1.3 to parse auditd.conf settings")
    assert(settings_probe.func == "file.parse_key_values",
        "Expected 3.1.3 to parse auditd.conf instead of checking only key presence")
    assert(type(rule.assertion.all_of[2].any_of) == "table" and #rule.assertion.all_of[2].any_of == 2,
        "Expected 3.1.3 to accept either keep_logs retention or rotate with num_logs >= 2")
end

function test_dengbao_profile_requires_safe_audit_disk_full_actions()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "3.1.5")

    assert(rule ~= nil, "Expected dengbao profile to define audit disk-full rule 3.1.5")
    assert(rule.desc == "Ensure the system reacts safely when audit logs are full",
        "Expected 3.1.5 description to cover safe reactions to audit storage exhaustion")
    assert(type(rule.assertion.all_of[2].any_of) == "table" and #rule.assertion.all_of[2].any_of == 2,
        "Expected 3.1.5 to accept admin_space_left_action as single or halt")
    assert(type(rule.assertion.all_of[3].any_of) == "table" and #rule.assertion.all_of[3].any_of == 2,
        "Expected 3.1.5 to require disk_full_action to be single or halt")
    assert(type(rule.assertion.all_of[4].any_of) == "table" and #rule.assertion.all_of[4].any_of == 3,
        "Expected 3.1.5 to require disk_error_action to be syslog, single, or halt")
end

function test_dengbao_profile_normalizes_auditd_conf_values_for_case_insensitive_comparisons()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local retention_rule = find_rule_by_id(profile, "3.1.3")
    local retention_probe = find_probe(retention_rule, "auditd_conf_settings")
    local disk_full_rule = find_rule_by_id(profile, "3.1.5")
    local disk_full_probe = find_probe(disk_full_rule, "auditd_conf_settings")

    assert(retention_probe.params.normalize_values == "lower",
        "Expected 3.1.3 to normalize auditd.conf values before string comparisons")
    assert(disk_full_probe.params.normalize_values == "lower",
        "Expected 3.1.5 to normalize auditd.conf values before string comparisons")
end

function test_dengbao_profile_parses_ssh_duration_values_semantically()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "1.3.4")
    local probe = find_probe(rule, "login_grace_time_effective")

    assert(rule ~= nil, "Expected dengbao profile to define SSH LoginGraceTime rule 1.3.4")
    assert(probe ~= nil, "Expected 1.3.4 to define an SSH effective-value probe")
    assert(probe.func == "ssh.get_effective_value",
        "Expected 1.3.4 to use ssh.get_effective_value")
    assert(probe.params.value_type == "duration_seconds",
        "Expected 1.3.4 to normalize SSH duration values before comparison")
end

function test_dengbao_profile_detects_protocol_1_in_mixed_ssh_protocol_lists()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "1.2.1")
    local probe = find_probe(rule, "ssh_protocol1_ondisk")
    local path = "/tmp/loongshield_test_sshd_protocol.conf"

    assert(rule ~= nil, "Expected dengbao profile to define SSH protocol rule 1.2.1")
    assert(probe ~= nil, "Expected 1.2.1 to define an on-disk SSH protocol probe")

    write_temp_file(path, "Protocol 2,1\n")

    local result, err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    os.remove(path)

    assert(err == nil, "Expected 1.2.1 pattern evaluation to succeed")
    assert(result.found == true,
        "Expected 1.2.1 to flag mixed SSH protocol lists that still include protocol 1")
end

function test_dengbao_profile_detects_non_no_root_login_values_on_disk()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "1.3.2")
    local probe = find_probe(rule, "permit_root_login_ondisk_noncompliant")
    local path = "/tmp/loongshield_test_sshd_root_login.conf"

    assert(rule ~= nil, "Expected dengbao profile to define SSH root-login rule 1.3.2")
    assert(probe ~= nil, "Expected 1.3.2 to define an on-disk SSH root-login probe")

    write_temp_file(path, "PermitRootLogin prohibit-password\n")

    local result, err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    os.remove(path)

    assert(err == nil, "Expected 1.3.2 pattern evaluation to succeed")
    assert(result.found == true,
        "Expected 1.3.2 to flag explicit non-'no' PermitRootLogin values")
end

function test_dengbao_profile_ignores_commented_audit_boot_parameters()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "3.2.2")
    local probe = find_probe(rule, "audit_boot_param")
    local path = "/tmp/loongshield_test_grub_audit.conf"

    assert(rule ~= nil, "Expected dengbao profile to define audit boot rule 3.2.2")
    assert(probe ~= nil, "Expected 3.2.2 to define a boot parameter probe")

    write_temp_file(path, "# linux /vmlinuz audit=1\n")

    local commented_result, commented_err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    write_temp_file(path, "  linux /vmlinuz audit=1 quiet\n")

    local active_result, active_err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    os.remove(path)

    assert(commented_err == nil, "Expected 3.2.2 commented-line evaluation to succeed")
    assert(commented_result.found == false,
        "Expected 3.2.2 to ignore commented boot entries")
    assert(active_err == nil, "Expected 3.2.2 active-line evaluation to succeed")
    assert(active_result.found == true,
        "Expected 3.2.2 to match active boot entries that enable audit=1")
end

function test_cis_profile_ignores_commented_audit_boot_parameters()
    local profile = lyaml.load(read_file("profiles/seharden/cis_alinux_3.yml"))
    local rule = find_rule_by_id(profile, "6.3.1.2")
    local probe = find_probe(rule, "audit_boot_param")
    local path = "/tmp/loongshield_test_cis_grub_audit.conf"

    assert(rule ~= nil, "Expected cis_alinux_3 to define audit boot rule 6.3.1.2")
    assert(probe ~= nil, "Expected 6.3.1.2 to define a boot parameter probe")

    write_temp_file(path, "# linux /vmlinuz audit=1\n")

    local commented_result, commented_err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    write_temp_file(path, "  linux /vmlinuz audit=1 quiet\n")

    local active_result, active_err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    os.remove(path)

    assert(commented_err == nil, "Expected 6.3.1.2 commented-line evaluation to succeed")
    assert(commented_result.found == false,
        "Expected 6.3.1.2 to ignore commented boot entries")
    assert(active_err == nil, "Expected 6.3.1.2 active-line evaluation to succeed")
    assert(active_result.found == true,
        "Expected 6.3.1.2 to match active boot entries that enable audit=1")
end

function test_dengbao_profile_uses_semantic_mode_comparisons()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local home_rule = find_rule_by_id(profile, "2.1.1")
    local passwd_rule = find_rule_by_id(profile, "2.2.2")
    local ssh_pub_rule = find_rule_by_id(profile, "2.5.1")

    assert(home_rule.assertion.all_of[1].expected.all_of[1].compare == "mode_is_no_more_permissive",
        "Expected 2.1.1 to compare home directory permissions semantically")
    assert(passwd_rule.assertion.all_of[1].compare == "mode_is_no_more_permissive",
        "Expected 2.2.2 to compare passwd permissions semantically")
    assert(ssh_pub_rule.assertion.all_of[2].expected.all_of[1].compare == "mode_is_no_more_permissive",
        "Expected 2.5.1 to compare SSH public key permissions semantically")
end

function test_dengbao_profile_declares_manual_review_required_items()
    local profile = seharden_profile.load("profiles/seharden/dengbao_3.yml")

    assert(type(profile.manual_review_required) == "table" and #profile.manual_review_required >= 6,
        "Expected dengbao profile to disclose manual-review-only controls")
    assert(manual_review_contains(profile, "ordinary user, auditor, and security officer"),
        "Expected manual review notes to cover role separation requirements")
    assert(manual_review_contains(profile, "weak-password baseline"),
        "Expected manual review notes to cover weak-password baseline validation")
    assert(manual_review_contains(profile, "AllowUsers"),
        "Expected manual review notes to cover site-specific SSH source-address restrictions")
    assert(manual_review_contains(profile, "vulnerability management"),
        "Expected manual review notes to cover vulnerability management evidence")
    assert(manual_review_contains(profile, "malware protection"),
        "Expected manual review notes to cover malware protection evidence")
    assert(manual_review_contains(profile, "space_left and admin_space_left"),
        "Expected manual review notes to disclose site-specific audit threshold sizing")
    assert(manual_review_contains(profile, "unowned or ungrouped files and directories on the root filesystem"),
        "Expected manual review notes to disclose manual review for unowned-path coverage")
end

function test_dengbao_profile_covers_additional_access_audit_and_intrusion_controls()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local descs = collect_rule_descs(profile)
    local required_descs = {
        "Ensure non-root system accounts use non-login shells",
        "Ensure su access is restricted through pam_wheel",
        "Ensure SSH host public key permissions and ownership are configured",
        "Ensure SSH host private key permissions and ownership are configured",
        "Ensure auditing for processes that start prior to auditd is enabled",
        "Ensure high-risk management and sharing ports are not listening",
    }

    for _, expected in ipairs(required_descs) do
        local found = false
        for _, actual in ipairs(descs) do
            if actual == expected then
                found = true
                break
            end
        end
        assert(found, "Expected dengbao profile to cover additional control: " .. expected)
    end
end

function test_dengbao_profile_reports_unavailable_listening_port_probe_explicitly()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "4.2.1")
    local availability_assertion

    assert(rule ~= nil, "Expected dengbao profile to define high-risk listening port rule 4.2.1")

    for _, child in ipairs(rule.assertion.all_of or {}) do
        if child.key == "available" then
            availability_assertion = child
            break
        end
    end

    assert(availability_assertion ~= nil,
        "Expected 4.2.1 to check whether listening-port evidence is available")
    assert(availability_assertion.compare == "is_true",
        "Expected 4.2.1 to require available listening-port evidence before checking count")
    assert(availability_assertion.message:find("ss", 1, true),
        "Expected 4.2.1 unavailable-evidence message to mention ss")
end

function test_dengbao_profile_moves_unowned_path_review_to_manual_items()
    local profile = seharden_profile.load("profiles/seharden/dengbao_3.yml")

    assert(find_rule_by_id(profile, "2.1.15") == nil,
        "Expected dengbao profile not to keep the expensive unowned-path scan in automated rules")
    assert(manual_review_contains(profile, "root filesystem and any additional local filesystems"),
        "Expected dengbao profile to keep unowned-path coverage in manual review items")
end

function test_dengbao_profile_uses_structured_audit_rule_probes()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local delete_rule = find_rule_by_id(profile, "3.3.1")
    local sudoers_rule = find_rule_by_id(profile, "3.3.2")
    local identity_rule = find_rule_by_id(profile, "3.3.3")

    assert(find_probe(delete_rule, "audit_arches").func == "system.get_supported_audit_arches",
        "Expected 3.3.1 to detect host-supported audit arches before validating syscall coverage")
    assert(find_probe(delete_rule, "file_delete_audit_rule").func == "audit.find_syscall_rule",
        "Expected 3.3.1 to use structured syscall-rule parsing")
    assert(find_probe(delete_rule, "file_delete_audit_rule").params.required_arches == "%{probe.audit_arches.arches}",
        "Expected 3.3.1 to require syscall coverage for each supported host audit arch")
    assert(find_probe(delete_rule, "file_delete_audit_rule").params.syscalls[5] == "renameat2",
        "Expected 3.3.1 to include renameat2 in file deletion audit coverage on ALinux3")
    assert(find_probe(sudoers_rule, "sudoers_audit_paths").func == "sudo.collect_audit_paths",
        "Expected 3.3.2 to resolve active sudoers paths structurally")
    assert(find_probe(sudoers_rule, "sudoers_watch_rules").func == "meta.map",
        "Expected 3.3.2 to map audit watch checks across active sudoers paths")
    assert(find_probe(sudoers_rule, "sudoers_watch_rules").params.params_template.require_key == false,
        "Expected 3.3.2 to avoid requiring audit keys for sudoers watch coverage")
    assert(find_probe(identity_rule, "passwd_watch_rule").func == "audit.find_watch_rule",
        "Expected 3.3.3 to use structured audit watch parsing")
    assert(find_probe(identity_rule, "passwd_watch_rule").params.require_key == false,
        "Expected 3.3.3 to avoid requiring audit keys for passwd watch coverage")
end

function test_dengbao_profile_uses_structured_pam_shell_and_sudo_probes()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local pwquality_rule = find_rule_by_id(profile, "1.1.6")

    assert(find_probe(pwquality_rule, "pwquality_check").func == "pam.inspect_pwquality",
        "Expected 1.1.6 to use structured PAM pwquality parsing")
    assert(find_probe(pwquality_rule, "pwquality_check").params.min_minclass == 3,
        "Expected 1.1.6 to require a minimum pwquality class-complexity baseline")
    assert(find_probe(find_rule_by_id(profile, "1.1.3"), "pwquality_check").func == "pam.inspect_pwquality",
        "Expected 1.1.3 to use structured PAM pwquality parsing")
    assert(find_probe(find_rule_by_id(profile, "1.1.8"), "password_history_check").func == "pam.check_password_history",
        "Expected 1.1.8 to use structured PAM password-history parsing")
    assert(type(find_probe(find_rule_by_id(profile, "1.1.8"), "password_history_check").params.config_paths) == "table",
        "Expected 1.1.8 to evaluate layered pwhistory configuration paths")
    assert(find_probe(find_rule_by_id(profile, "1.3.1"), "faillock_check").func == "pam.inspect_faillock",
        "Expected 1.3.1 to use structured PAM faillock parsing")
    assert(find_probe(find_rule_by_id(profile, "1.1.4"), "shadow_entries").func == "users.get_login_shadow_entries",
        "Expected 1.1.4 to scope password expiration checks to login-capable accounts")
    assert(find_probe(find_rule_by_id(profile, "1.1.5"), "shadow_entries").func == "users.get_login_shadow_entries",
        "Expected 1.1.5 to scope password aging checks to login-capable accounts")
    assert(find_probe(find_rule_by_id(profile, "1.3.6"), "session_timeout_check").func == "shell.find_tmout_assignments",
        "Expected 1.3.6 to use structured TMOUT parsing")
    assert(find_probe(find_rule_by_id(profile, "2.1.2"), "login_defs_umask").func == "shell.check_umask_value",
        "Expected 2.1.2 to validate UMASK semantically")
    assert(find_probe(find_rule_by_id(profile, "2.1.3"), "shell_umask_check").func == "shell.find_umask_commands",
        "Expected 2.1.3 to use structured shell umask parsing")
    assert(find_probe(find_rule_by_id(profile, "2.2.1"), "sudoers_permission_paths").func == "sudo.collect_permission_paths",
        "Expected 2.2.1 to resolve active sudoers permission paths structurally")
    assert(find_probe(find_rule_by_id(profile, "2.1.1"), "local_user_home_directories").func == "users.get_existing_home_directories",
        "Expected 2.1.1 to scope home permission checks to existing home directories")
    assert(find_probe(find_rule_by_id(profile, "2.3.3"), "su_pam_wheel_check").func == "pam.inspect_wheel",
        "Expected 2.3.3 to use structured PAM wheel parsing")
    assert(find_probe(find_rule_by_id(profile, "2.3.1"), "sudo_use_pty_check").func == "sudo.find_use_pty",
        "Expected 2.3.1 to use structured sudo Defaults parsing")
    assert(find_probe(find_rule_by_id(profile, "2.3.2"), "sudo_nopasswd_check").func == "sudo.find_nopasswd_entries",
        "Expected 2.3.2 to use structured sudo rule parsing")
end

function test_dengbao_profile_requires_pwquality_character_class_complexity()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "1.1.6")

    assert(rule ~= nil, "Expected dengbao profile to define password complexity rule 1.1.6")
    assert(rule.desc == "Ensure password complexity policy is enabled",
        "Expected 1.1.6 to describe password complexity policy, not only module presence")
    assert(rule.assertion.all_of[2].key == "weak_complexity_count",
        "Expected 1.1.6 to assert pwquality character-class complexity coverage")
end

function test_dengbao_profile_scopes_root_uid_rule_to_uid_zero_only()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "1.1.7")
    local probe = find_probe(rule, "duplicate_uid_check")

    assert(rule ~= nil, "Expected dengbao profile to define root UID 0 rule 1.1.7")
    assert(probe ~= nil, "Expected 1.1.7 to define a duplicate UID probe")
    assert(tostring(probe.params.match_key) == "0",
        "Expected 1.1.7 to scope duplicate-UID detection to UID 0 only")
end

function test_dengbao_profile_allows_removed_or_locked_shutdown_halt_accounts()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "2.4.2")

    assert(rule ~= nil, "Expected dengbao profile to define shutdown and halt account handling")
    assert(find_probe(rule, "shutdown_account_present") ~= nil,
        "Expected 2.4.2 to distinguish between removed and locked shutdown accounts")
    assert(find_probe(rule, "halt_account_present") ~= nil,
        "Expected 2.4.2 to distinguish between removed and locked halt accounts")
end

function test_dengbao_profile_covers_core_identity_access_audit_and_intrusion_controls()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local descs = collect_rule_descs(profile)
    local required_descs = {
        "Ensure password fields are not empty",
        "Ensure no duplicate UIDs exist",
        "Ensure users must provide password for privilege escalation",
        "Ensure user home directory permissions are 750 or more restrictive",
        "Ensure non-root system accounts use non-login shells",
        "Ensure rsyslog or syslog-ng is installed, enabled, and running",
        "Ensure audit log size and retention are configured",
        "Ensure auditing for processes that start prior to auditd is enabled",
        "Ensure changes to sudoers configuration are collected by audit",
        "Ensure telnet packages are not installed",
        "Ensure wdaemon packages are not installed",
        "Ensure high-risk management and sharing ports are not listening",
    }

    for _, expected in ipairs(required_descs) do
        local found = false
        for _, actual in ipairs(descs) do
            if actual == expected then
                found = true
                break
            end
        end
        assert(found, "Expected dengbao profile to cover core control: " .. expected)
    end
end

function test_dengbao_profile_declares_stable_low_risk_reinforce_steps()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule_116 = find_rule_by_id(profile, "1.1.6")
    local rule_117 = find_rule_by_id(profile, "1.1.3")
    local rule_118 = find_rule_by_id(profile, "1.1.8")
    local rule_119 = find_rule_by_id(profile, "1.3.1")
    local rule_212 = find_rule_by_id(profile, "2.1.2")
    local rule_214 = find_rule_by_id(profile, "2.3.1")
    local rule_217 = find_rule_by_id(profile, "2.2.2")
    local rule_218 = find_rule_by_id(profile, "2.2.3")
    local rule_219 = find_rule_by_id(profile, "2.2.4")
    local rule_2110 = find_rule_by_id(profile, "2.2.5")
    local rule_2112 = find_rule_by_id(profile, "2.3.3")
    local rule_311 = find_rule_by_id(profile, "3.1.1")
    local rule_312 = find_rule_by_id(profile, "3.1.2")
    local rule_313 = find_rule_by_id(profile, "3.1.3")
    local rule_314 = find_rule_by_id(profile, "3.1.4")
    local rule_315 = find_rule_by_id(profile, "3.1.5")
    local rule_316 = find_rule_by_id(profile, "3.3.1")
    local rule_317 = find_rule_by_id(profile, "3.3.2")
    local rule_318 = find_rule_by_id(profile, "3.3.3")
    local rule_413 = find_rule_by_id(profile, "4.1.3")

    assert(find_reinforce_action(rule_116, "file.set_key_value").params.key == "minclass",
        "Expected 1.1.6 to reinforce pwquality minclass in configuration")
    assert(find_reinforce_action(rule_116, "pam.ensure_entry") ~= nil,
        "Expected 1.1.6 to ensure pam_pwquality is present in PAM stacks")
    assert(find_reinforce_action(rule_117, "file.set_key_value").params.key == "minlen",
        "Expected 1.1.3 to reinforce pwquality minlen in configuration")
    assert(find_reinforce_action(rule_117, "pam.ensure_entry") ~= nil,
        "Expected 1.1.3 to ensure pam_pwquality is present in PAM stacks")
    assert(find_reinforce_action(rule_118, "file.set_key_value").params.path == "/etc/security/pwhistory.conf",
        "Expected 1.1.8 to reinforce pwhistory defaults in the dedicated config file")
    assert(find_reinforce_action(rule_118, "pam.ensure_entry") ~= nil,
        "Expected 1.1.8 to ensure pam_pwhistory is present in PAM stacks")
    assert(find_reinforce_action(rule_119, "file.set_key_value").params.path == "/etc/security/faillock.conf",
        "Expected 1.3.1 to reinforce faillock defaults in the dedicated config file")
    assert(find_reinforce_action(rule_119, "pam.ensure_entry") ~= nil,
        "Expected 1.3.1 to ensure pam_faillock is present in PAM stacks")

    local umask_step = find_reinforce_action(rule_212, "file.set_key_value")
    assert(umask_step ~= nil, "Expected 2.1.2 to declare a login.defs reinforce step")
    assert(umask_step.params.path == "/etc/login.defs", "Expected 2.1.2 to target /etc/login.defs")
    assert(umask_step.params.key == "UMASK", "Expected 2.1.2 to set the UMASK key")
    assert(umask_step.params.value == "027", "Expected 2.1.2 to reinforce UMASK to 027")
    assert(umask_step.params.separator == " ", "Expected 2.1.2 to preserve login.defs whitespace-separated syntax")
    assert(find_reinforce_action(rule_214, "sudo.set_use_pty") ~= nil,
        "Expected 2.3.1 to declare the sudo use_pty enforcer")

    assert(find_reinforce_action(rule_217, "permissions.set_attributes").params.mode == 420,
        "Expected 2.2.2 to reinforce /etc/passwd to mode 0644")
    assert(find_reinforce_action(rule_218, "permissions.set_attributes").params.mode == 0,
        "Expected 2.2.3 to reinforce /etc/shadow to mode 0000")
    assert(find_reinforce_action(rule_219, "permissions.set_attributes").params.mode == 420,
        "Expected 2.2.4 to reinforce /etc/group to mode 0644")
    assert(find_reinforce_action(rule_2110, "permissions.set_attributes").params.mode == 0,
        "Expected 2.2.5 to reinforce /etc/gshadow to mode 0000")
    assert(find_reinforce_action(rule_2112, "pam.ensure_entry").params.module == "pam_wheel.so",
        "Expected 2.3.3 to reinforce su restrictions with pam_wheel")

    assert(find_reinforce_action(rule_311, "packages.install").params.name == "audit",
        "Expected 3.1.1 to install the audit package")
    assert(find_reinforce_action(rule_311, "services.set_filestate").params.state == "enable",
        "Expected 3.1.1 to enable auditd")
    assert(find_reinforce_action(rule_311, "services.set_active_state").params.state == "start",
        "Expected 3.1.1 to start auditd")
    assert(find_reinforce_action(rule_312, "packages.install").params.name == "rsyslog",
        "Expected 3.1.2 to prefer rsyslog for reinforce automation")

    assert(find_reinforce_action(rule_313, "file.set_key_value") ~= nil,
        "Expected 3.1.3 to declare auditd.conf reinforce steps")
    assert(find_reinforce_action(rule_314, "file.set_key_value").params.value == "keep_logs",
        "Expected 3.1.4 to preserve audit logs with keep_logs")

    local space_left_step = rule_315.reinforce and rule_315.reinforce[1] or nil
    assert(space_left_step ~= nil and space_left_step.params.value == "syslog",
        "Expected 3.1.5 to choose a low-disruption syslog action for space_left_action")
    assert(find_reinforce_action(rule_316, "audit.ensure_syscall_rule") ~= nil,
        "Expected 3.3.1 to declare structured syscall audit reinforcement")
    assert(type(rule_317.reinforce) == "table" and #rule_317.reinforce == 1,
        "Expected 3.3.2 to use one dynamic sudo audit-watch reinforce step")
    assert(find_reinforce_action(rule_317, "sudo.ensure_audit_watches").params.root_path == "/etc/sudoers",
        "Expected 3.3.2 to derive audit watches from the active sudoers root path")
    assert(find_reinforce_action(rule_318, "audit.ensure_watch_rule") ~= nil,
        "Expected 3.3.3 to declare audit watch reinforcement for identity files")
    assert(find_reinforce_action(rule_413, "packages.remove").params.name == "kexec-tools",
        "Expected 4.1.3 to remove the kexec-tools package")
end

function test_dengbao_profile_uses_pattern_based_package_removal_for_globbed_rules()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule_127 = find_rule_by_id(profile, "1.2.2")
    local rule_411 = find_rule_by_id(profile, "4.1.1")
    local rule_412 = find_rule_by_id(profile, "4.1.2")
    local rule_414 = find_rule_by_id(profile, "4.1.4")
    local rule_415 = find_rule_by_id(profile, "4.1.5")
    local rule_416 = find_rule_by_id(profile, "4.1.6")
    local rule_417 = find_rule_by_id(profile, "4.1.7")

    assert(find_reinforce_action(rule_127, "packages.remove_matching").params.pattern == "telnet*",
        "Expected 1.2.2 to remove matching telnet packages")
    assert(find_reinforce_action(rule_411, "packages.remove_matching").params.pattern == "avahi-daemon*",
        "Expected 4.1.1 to remove matching Avahi packages")
    assert(find_reinforce_action(rule_412, "packages.remove_matching").params.pattern == "bluez*",
        "Expected 4.1.2 to remove matching Bluetooth packages")
    assert(find_reinforce_action(rule_414, "packages.remove_matching").params.pattern == "firstboot*",
        "Expected 4.1.4 to remove matching firstboot packages")
    assert(find_reinforce_action(rule_415, "packages.remove_matching").params.pattern == "wdaemon*",
        "Expected 4.1.5 to remove matching wdaemon packages")
    assert(find_reinforce_action(rule_416, "packages.remove_matching").params.pattern == "wpa_supplicant*",
        "Expected 4.1.6 to remove matching wpa_supplicant packages")
    assert(find_reinforce_action(rule_417, "packages.remove_matching").params.pattern == "ypbind*",
        "Expected 4.1.7 to remove matching ypbind packages")
end
