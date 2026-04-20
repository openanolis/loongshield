local lyaml = require('lyaml')
local seharden_profile = require('seharden.profile')
local file_probe = require('seharden.probes.file')

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

local function find_ssh_probes_missing_localhost_conditions(profile)
    local offenders = {}

    for _, rule in ipairs(profile.rules or {}) do
        local probes = rule.probes
        if type(probes) == "table" and probes.func then
            probes = { probes }
        end

        if type(probes) == "table" then
            for _, probe in ipairs(probes) do
                if probe.func == "ssh.get_effective_value" then
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
    for _, probe in ipairs(rule.probes or {}) do
        if probe.name == probe_name then
            return probe
        end
    end
    return nil
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
    local rule = find_rule_by_id(profile, "1.2.5")
    local probe = find_probe(rule, "login_grace_time_effective")

    assert(rule ~= nil, "Expected dengbao profile to define SSH LoginGraceTime rule 1.2.5")
    assert(probe ~= nil, "Expected 1.2.5 to define an SSH effective-value probe")
    assert(probe.func == "ssh.get_effective_value",
        "Expected 1.2.5 to use ssh.get_effective_value")
    assert(probe.params.value_type == "duration_seconds",
        "Expected 1.2.5 to normalize SSH duration values before comparison")
end

function test_dengbao_profile_detects_protocol_1_in_mixed_ssh_protocol_lists()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "1.2.2")
    local probe = find_probe(rule, "ssh_protocol1_ondisk")
    local path = "/tmp/loongshield_test_sshd_protocol.conf"

    assert(rule ~= nil, "Expected dengbao profile to define SSH protocol rule 1.2.2")
    assert(probe ~= nil, "Expected 1.2.2 to define an on-disk SSH protocol probe")

    write_temp_file(path, "Protocol 2,1\n")

    local result, err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    os.remove(path)

    assert(err == nil, "Expected 1.2.2 pattern evaluation to succeed")
    assert(result.found == true,
        "Expected 1.2.2 to flag mixed SSH protocol lists that still include protocol 1")
end

function test_dengbao_profile_detects_non_no_root_login_values_on_disk()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "1.2.3")
    local probe = find_probe(rule, "permit_root_login_ondisk_noncompliant")
    local path = "/tmp/loongshield_test_sshd_root_login.conf"

    assert(rule ~= nil, "Expected dengbao profile to define SSH root-login rule 1.2.3")
    assert(probe ~= nil, "Expected 1.2.3 to define an on-disk SSH root-login probe")

    write_temp_file(path, "PermitRootLogin prohibit-password\n")

    local result, err = file_probe.find_pattern({
        paths = { path },
        pattern = probe.params.pattern,
    })

    os.remove(path)

    assert(err == nil, "Expected 1.2.3 pattern evaluation to succeed")
    assert(result.found == true,
        "Expected 1.2.3 to flag explicit non-'no' PermitRootLogin values")
end

function test_dengbao_profile_ignores_commented_audit_boot_parameters()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "3.1.5.1")
    local probe = find_probe(rule, "audit_boot_param")
    local path = "/tmp/loongshield_test_grub_audit.conf"

    assert(rule ~= nil, "Expected dengbao profile to define audit boot rule 3.1.5.1")
    assert(probe ~= nil, "Expected 3.1.5.1 to define a boot parameter probe")

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

    assert(commented_err == nil, "Expected 3.1.5.1 commented-line evaluation to succeed")
    assert(commented_result.found == false,
        "Expected 3.1.5.1 to ignore commented boot entries")
    assert(active_err == nil, "Expected 3.1.5.1 active-line evaluation to succeed")
    assert(active_result.found == true,
        "Expected 3.1.5.1 to match active boot entries that enable audit=1")
end

function test_dengbao_profile_uses_semantic_mode_comparisons()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local home_rule = find_rule_by_id(profile, "2.1.1")
    local passwd_rule = find_rule_by_id(profile, "2.1.7")
    local ssh_pub_rule = find_rule_by_id(profile, "2.1.13")

    assert(home_rule.assertion.all_of[1].expected.all_of[1].compare == "mode_is_no_more_permissive",
        "Expected 2.1.1 to compare home directory permissions semantically")
    assert(passwd_rule.assertion.all_of[1].compare == "mode_is_no_more_permissive",
        "Expected 2.1.7 to compare passwd permissions semantically")
    assert(ssh_pub_rule.assertion.all_of[2].expected.all_of[1].compare == "mode_is_no_more_permissive",
        "Expected 2.1.13 to compare SSH public key permissions semantically")
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

function test_dengbao_profile_moves_unowned_path_review_to_manual_items()
    local profile = seharden_profile.load("profiles/seharden/dengbao_3.yml")

    assert(find_rule_by_id(profile, "2.1.15") == nil,
        "Expected dengbao profile not to keep the expensive unowned-path scan in automated rules")
    assert(manual_review_contains(profile, "root filesystem and any additional local filesystems"),
        "Expected dengbao profile to keep unowned-path coverage in manual review items")
end

function test_dengbao_profile_uses_structured_audit_rule_probes()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local delete_rule = find_rule_by_id(profile, "3.1.6")
    local sudoers_rule = find_rule_by_id(profile, "3.1.7")
    local identity_rule = find_rule_by_id(profile, "3.1.8")

    assert(find_probe(delete_rule, "audit_arches").func == "system.get_supported_audit_arches",
        "Expected 3.1.6 to detect host-supported audit arches before validating syscall coverage")
    assert(find_probe(delete_rule, "file_delete_audit_rule").func == "audit.find_syscall_rule",
        "Expected 3.1.6 to use structured syscall-rule parsing")
    assert(find_probe(delete_rule, "file_delete_audit_rule").params.required_arches == "%{probe.audit_arches.arches}",
        "Expected 3.1.6 to require syscall coverage for each supported host audit arch")
    assert(find_probe(delete_rule, "file_delete_audit_rule").params.syscalls[5] == "renameat2",
        "Expected 3.1.6 to include renameat2 in file deletion audit coverage on ALinux3")
    assert(find_probe(sudoers_rule, "sudoers_audit_paths").func == "sudo.collect_audit_paths",
        "Expected 3.1.7 to resolve active sudoers paths structurally")
    assert(find_probe(sudoers_rule, "sudoers_watch_rules").func == "meta.map",
        "Expected 3.1.7 to map audit watch checks across active sudoers paths")
    assert(find_probe(sudoers_rule, "sudoers_watch_rules").params.params_template.require_key == false,
        "Expected 3.1.7 to avoid requiring audit keys for sudoers watch coverage")
    assert(find_probe(identity_rule, "passwd_watch_rule").func == "audit.find_watch_rule",
        "Expected 3.1.8 to use structured audit watch parsing")
    assert(find_probe(identity_rule, "passwd_watch_rule").params.require_key == false,
        "Expected 3.1.8 to avoid requiring audit keys for passwd watch coverage")
end

function test_dengbao_profile_uses_structured_pam_shell_and_sudo_probes()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local pwquality_rule = find_rule_by_id(profile, "1.1.6")

    assert(find_probe(pwquality_rule, "pwquality_check").func == "pam.inspect_pwquality",
        "Expected 1.1.6 to use structured PAM pwquality parsing")
    assert(find_probe(pwquality_rule, "pwquality_check").params.min_minclass == 3,
        "Expected 1.1.6 to require a minimum pwquality class-complexity baseline")
    assert(find_probe(find_rule_by_id(profile, "1.1.7"), "pwquality_check").func == "pam.inspect_pwquality",
        "Expected 1.1.7 to use structured PAM pwquality parsing")
    assert(find_probe(find_rule_by_id(profile, "1.1.8"), "password_history_check").func == "pam.check_password_history",
        "Expected 1.1.8 to use structured PAM password-history parsing")
    assert(type(find_probe(find_rule_by_id(profile, "1.1.8"), "password_history_check").params.config_paths) == "table",
        "Expected 1.1.8 to evaluate layered pwhistory configuration paths")
    assert(find_probe(find_rule_by_id(profile, "1.1.9"), "faillock_check").func == "pam.inspect_faillock",
        "Expected 1.1.9 to use structured PAM faillock parsing")
    assert(find_probe(find_rule_by_id(profile, "1.1.4"), "shadow_entries").func == "users.get_login_shadow_entries",
        "Expected 1.1.4 to scope password expiration checks to login-capable accounts")
    assert(find_probe(find_rule_by_id(profile, "1.1.5"), "shadow_entries").func == "users.get_login_shadow_entries",
        "Expected 1.1.5 to scope password aging checks to login-capable accounts")
    assert(find_probe(find_rule_by_id(profile, "1.2.1"), "session_timeout_check").func == "shell.find_tmout_assignments",
        "Expected 1.2.1 to use structured TMOUT parsing")
    assert(find_probe(find_rule_by_id(profile, "2.1.2"), "login_defs_umask").func == "shell.check_umask_value",
        "Expected 2.1.2 to validate UMASK semantically")
    assert(find_probe(find_rule_by_id(profile, "2.1.3"), "shell_umask_check").func == "shell.find_umask_commands",
        "Expected 2.1.3 to use structured shell umask parsing")
    assert(find_probe(find_rule_by_id(profile, "2.1.6"), "sudoers_permission_paths").func == "sudo.collect_permission_paths",
        "Expected 2.1.6 to resolve active sudoers permission paths structurally")
    assert(find_probe(find_rule_by_id(profile, "2.1.1"), "local_user_home_directories").func == "users.get_existing_home_directories",
        "Expected 2.1.1 to scope home permission checks to existing home directories")
    assert(find_probe(find_rule_by_id(profile, "2.1.12"), "su_pam_wheel_check").func == "pam.inspect_wheel",
        "Expected 2.1.12 to use structured PAM wheel parsing")
    assert(find_probe(find_rule_by_id(profile, "2.1.4"), "sudo_use_pty_check").func == "sudo.find_use_pty",
        "Expected 2.1.4 to use structured sudo Defaults parsing")
    assert(find_probe(find_rule_by_id(profile, "2.1.5"), "sudo_nopasswd_check").func == "sudo.find_nopasswd_entries",
        "Expected 2.1.5 to use structured sudo rule parsing")
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
    local rule = find_rule_by_id(profile, "1.1.3")
    local probe = find_probe(rule, "duplicate_uid_check")

    assert(rule ~= nil, "Expected dengbao profile to define root UID 0 rule 1.1.3")
    assert(probe ~= nil, "Expected 1.1.3 to define a duplicate UID probe")
    assert(tostring(probe.params.match_key) == "0",
        "Expected 1.1.3 to scope duplicate-UID detection to UID 0 only")
end

function test_dengbao_profile_allows_removed_or_locked_shutdown_halt_accounts()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule = find_rule_by_id(profile, "2.2.1")

    assert(rule ~= nil, "Expected dengbao profile to define shutdown and halt account handling")
    assert(find_probe(rule, "shutdown_account_present") ~= nil,
        "Expected 2.2.1 to distinguish between removed and locked shutdown accounts")
    assert(find_probe(rule, "halt_account_present") ~= nil,
        "Expected 2.2.1 to distinguish between removed and locked halt accounts")
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
    local rule_117 = find_rule_by_id(profile, "1.1.7")
    local rule_118 = find_rule_by_id(profile, "1.1.8")
    local rule_119 = find_rule_by_id(profile, "1.1.9")
    local rule_212 = find_rule_by_id(profile, "2.1.2")
    local rule_214 = find_rule_by_id(profile, "2.1.4")
    local rule_217 = find_rule_by_id(profile, "2.1.7")
    local rule_218 = find_rule_by_id(profile, "2.1.8")
    local rule_219 = find_rule_by_id(profile, "2.1.9")
    local rule_2110 = find_rule_by_id(profile, "2.1.10")
    local rule_2112 = find_rule_by_id(profile, "2.1.12")
    local rule_311 = find_rule_by_id(profile, "3.1.1")
    local rule_312 = find_rule_by_id(profile, "3.1.2")
    local rule_313 = find_rule_by_id(profile, "3.1.3")
    local rule_314 = find_rule_by_id(profile, "3.1.4")
    local rule_315 = find_rule_by_id(profile, "3.1.5")
    local rule_316 = find_rule_by_id(profile, "3.1.6")
    local rule_317 = find_rule_by_id(profile, "3.1.7")
    local rule_318 = find_rule_by_id(profile, "3.1.8")
    local rule_413 = find_rule_by_id(profile, "4.1.3")

    assert(find_reinforce_action(rule_116, "file.set_key_value").params.key == "minclass",
        "Expected 1.1.6 to reinforce pwquality minclass in configuration")
    assert(find_reinforce_action(rule_116, "pam.ensure_entry") ~= nil,
        "Expected 1.1.6 to ensure pam_pwquality is present in PAM stacks")
    assert(find_reinforce_action(rule_117, "file.set_key_value").params.key == "minlen",
        "Expected 1.1.7 to reinforce pwquality minlen in configuration")
    assert(find_reinforce_action(rule_117, "pam.ensure_entry") ~= nil,
        "Expected 1.1.7 to ensure pam_pwquality is present in PAM stacks")
    assert(find_reinforce_action(rule_118, "file.set_key_value").params.path == "/etc/security/pwhistory.conf",
        "Expected 1.1.8 to reinforce pwhistory defaults in the dedicated config file")
    assert(find_reinforce_action(rule_118, "pam.ensure_entry") ~= nil,
        "Expected 1.1.8 to ensure pam_pwhistory is present in PAM stacks")
    assert(find_reinforce_action(rule_119, "file.set_key_value").params.path == "/etc/security/faillock.conf",
        "Expected 1.1.9 to reinforce faillock defaults in the dedicated config file")
    assert(find_reinforce_action(rule_119, "pam.ensure_entry") ~= nil,
        "Expected 1.1.9 to ensure pam_faillock is present in PAM stacks")

    local umask_step = find_reinforce_action(rule_212, "file.set_key_value")
    assert(umask_step ~= nil, "Expected 2.1.2 to declare a login.defs reinforce step")
    assert(umask_step.params.path == "/etc/login.defs", "Expected 2.1.2 to target /etc/login.defs")
    assert(umask_step.params.key == "UMASK", "Expected 2.1.2 to set the UMASK key")
    assert(umask_step.params.value == "027", "Expected 2.1.2 to reinforce UMASK to 027")
    assert(umask_step.params.separator == " ", "Expected 2.1.2 to preserve login.defs whitespace-separated syntax")
    assert(find_reinforce_action(rule_214, "sudo.set_use_pty") ~= nil,
        "Expected 2.1.4 to declare the sudo use_pty enforcer")

    assert(find_reinforce_action(rule_217, "permissions.set_attributes").params.mode == 420,
        "Expected 2.1.7 to reinforce /etc/passwd to mode 0644")
    assert(find_reinforce_action(rule_218, "permissions.set_attributes").params.mode == 0,
        "Expected 2.1.8 to reinforce /etc/shadow to mode 0000")
    assert(find_reinforce_action(rule_219, "permissions.set_attributes").params.mode == 420,
        "Expected 2.1.9 to reinforce /etc/group to mode 0644")
    assert(find_reinforce_action(rule_2110, "permissions.set_attributes").params.mode == 0,
        "Expected 2.1.10 to reinforce /etc/gshadow to mode 0000")
    assert(find_reinforce_action(rule_2112, "pam.ensure_entry").params.module == "pam_wheel.so",
        "Expected 2.1.12 to reinforce su restrictions with pam_wheel")

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
        "Expected 3.1.6 to declare structured syscall audit reinforcement")
    assert(type(rule_317.reinforce) == "table" and #rule_317.reinforce == 1,
        "Expected 3.1.7 to use one dynamic sudo audit-watch reinforce step")
    assert(find_reinforce_action(rule_317, "sudo.ensure_audit_watches").params.root_path == "/etc/sudoers",
        "Expected 3.1.7 to derive audit watches from the active sudoers root path")
    assert(find_reinforce_action(rule_318, "audit.ensure_watch_rule") ~= nil,
        "Expected 3.1.8 to declare audit watch reinforcement for identity files")
    assert(find_reinforce_action(rule_413, "packages.remove").params.name == "kexec-tools",
        "Expected 4.1.3 to remove the kexec-tools package")
end

function test_dengbao_profile_uses_pattern_based_package_removal_for_globbed_rules()
    local profile = lyaml.load(read_file("profiles/seharden/dengbao_3.yml"))
    local rule_127 = find_rule_by_id(profile, "1.2.7")
    local rule_411 = find_rule_by_id(profile, "4.1.1")
    local rule_412 = find_rule_by_id(profile, "4.1.2")
    local rule_414 = find_rule_by_id(profile, "4.1.4")
    local rule_415 = find_rule_by_id(profile, "4.1.5")
    local rule_416 = find_rule_by_id(profile, "4.1.6")
    local rule_417 = find_rule_by_id(profile, "4.1.7")

    assert(find_reinforce_action(rule_127, "packages.remove_matching").params.pattern == "telnet*",
        "Expected 1.2.7 to remove matching telnet packages")
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
