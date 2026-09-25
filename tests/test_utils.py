"""Tests for ReconX Framework utilities."""

import re
from pathlib import Path
from unittest.mock import patch

from recon import (
    escape_domain,
    normalize_host,
    host_in_scope,
    url_in_scope,
    safe_count,
    write_lines,
    read_lines,
    append_line,
    ReconConfig,
    NullLogger,
    ReconLogger,
    CONFIG,
    _extract_version,
    clean_output,
    _is_banner_line,
    _manual_update_hint,
    parse_args,
    print_banner,
    Tool,
    TOOL_REGISTRY,
    MODE_CONFIG,
    SPECIAL_PARSERS,
    ALL_PORTS,
    SENSITIVE_PORTS,
    PhaseRunner,
    ReconPipeline,
    tool_available,
    _parse_crtsh_json,
    _parse_hackertarget,
    _parse_otx_json,
    _parse_bufferover_json,
    _parse_wayback_json,
    passive_fallback,
    build_urlfinder_cmd,
    build_fallparams_cmd,
)


# ── Utility functions ─────────────────────────────────────────────────

def test_escape_domain():
    assert escape_domain("example.com") == r"example\.com"
    assert escape_domain("sub.example.com") == r"sub\.example\.com"
    assert escape_domain("test-domain.com") == r"test\-domain\.com"


# ── Scope filtering (domain + subdomains) ─────────────────────────────

def test_normalize_host():
    assert normalize_host("  B.BBPOS.com. ") == "b.bbpos.com"
    assert normalize_host("bbpos.com") == "bbpos.com"


def test_host_in_scope_apex_and_subdomains():
    d = "bbpos.com"
    assert host_in_scope("bbpos.com", d)
    assert host_in_scope("www.bbpos.com", d)
    assert host_in_scope("deep.sub.api.bbpos.com", d)
    assert host_in_scope("B.BBPOS.com.", d)  # case + trailing dot
    assert host_in_scope("http://x", d) is False  # not a hostname


def test_host_in_scope_rejects_foreign_and_lookalikes():
    d = "bbpos.com"
    assert not host_in_scope("evil-bbpos.com", d)   # suffix but NOT label boundary
    assert not host_in_scope("evilbbpos.com", d)    # substring
    assert not host_in_scope("cdn.cloudfront.net", d)
    assert not host_in_scope("1.2.3.4", d)          # bare IP
    assert not host_in_scope("", d)
    assert not host_in_scope(None, d)


def test_url_in_scope():
    d = "bbpos.com"
    assert url_in_scope("https://bbpos.com/x?y=1", d)
    assert url_in_scope("http://app.bbpos.com/api", d)
    assert url_in_scope("https://deep.sub.api.bbpos.com/path", d)
    assert not url_in_scope("https://cdn.cloudfront.net/x", d)
    assert not url_in_scope("ftp://bbpos.com/x", d)          # non-http scheme
    assert not url_in_scope("http://1.2.3.4/x", d)           # IP host
    assert not url_in_scope("https://evil-bbpos.com/x", d)   # lookalike
    assert not url_in_scope("/relative/path", d)             # no host
    assert not url_in_scope("", d)


def test_safe_count(tmp_path):
    f = tmp_path / "test.txt"
    assert safe_count(f) == 0

    f.write_text("line1\nline2\nline3\n")
    assert safe_count(f) == 3

    f.write_text("")
    assert safe_count(f) == 0


def test_write_lines(tmp_path):
    f = tmp_path / "out" / "test.txt"
    write_lines(f, ["line1", "line2", "line3"])
    assert f.read_text() == "line1\nline2\nline3\n"


def test_read_lines(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("line1\nline2\n\nline3\n")
    assert read_lines(f) == ["line1", "line2", "line3"]


def test_read_lines_missing(tmp_path):
    assert read_lines(tmp_path / "missing.txt") == []


def test_append_line(tmp_path):
    f = tmp_path / "append.txt"
    append_line(f, "first")
    append_line(f, "second")
    assert f.read_text() == "first\nsecond\n"


# ── Version extraction ────────────────────────────────────────────────

def test_extract_version():
    assert _extract_version("subfinder v2.6.3") == "v2.6.3"
    assert _extract_version("httpx v1.3.7\nsome other line") == "v1.3.7"
    assert _extract_version("nuclei 3.1.0") == "3.1.0"
    assert _extract_version("no version here") == "?"


# ── clean_output ──────────────────────────────────────────────────────

def test_clean_output():
    assert clean_output("") == "-"
    assert clean_output("\x1b[1;32mhello\x1b[0m") == "hello"
    assert clean_output("  spaces  \n  around  ") == "spaces"
    assert clean_output("line1\nline2") == "line1"


def test_clean_output_truncation():
    long = "a" * 40
    result = clean_output(long)
    assert len(result) == 38  # 35 + "..."
    assert result.endswith("...")


# ── _is_banner_line ──────────────────────────────────────────────────

def test_is_banner_line():
    assert _is_banner_line("") is False
    assert _is_banner_line("   ") is False
    assert _is_banner_line("═══════════") is True
    assert _is_banner_line("---###---") is True
    assert _is_banner_line("normal text here") is False
    assert _is_banner_line("subfinder v2.6.3") is False
    assert _is_banner_line("===>>") is True
    assert _is_banner_line("|  Tool  |  Ver  |") is False
    assert _is_banner_line("@#$%^&*()") is True


# ── _manual_update_hint ──────────────────────────────────────────────

def test_manual_update_hint():
    hint = _manual_update_hint("subfinder")
    assert "go install" in hint
    assert "subfinder" in hint

    hint = _manual_update_hint("nuclei")
    assert "go install" in hint
    assert "nuclei/v3" in hint

    hint = _manual_update_hint("unknown_tool")
    assert "manually" in hint


# ── parse_args ────────────────────────────────────────────────────────

def test_parse_args_domain():
    args = parse_args(["example.com"])
    assert args.domain == "example.com"
    assert args.mode == "stealth"


def test_parse_args_domain_and_mode():
    args = parse_args(["example.com", "aggressive"])
    assert args.domain == "example.com"
    assert args.mode == "aggressive"


def test_parse_args_check():
    args = parse_args(["--check"])
    assert args.check is True
    assert args.domain is None


def test_parse_args_update():
    args = parse_args(["--update"])
    assert args.update is True


def test_parse_args_verbose():
    args = parse_args(["example.com", "-v"])
    assert args.verbose == 1
    args = parse_args(["example.com", "-vv"])
    assert args.verbose == 2


def test_parse_args_quiet():
    args = parse_args(["example.com", "--quiet"])
    assert args.quiet is True


def test_parse_args_output():
    args = parse_args(["example.com", "-o", "/tmp/out"])
    assert args.output == "/tmp/out"


def test_parse_args_no_domain():
    args = parse_args([])
    assert args.domain is None


# ── print_banner ──────────────────────────────────────────────────────

def test_print_banner(capsys):
    print_banner()
    output = capsys.readouterr().out
    assert "E C O N X" in output
    assert "Mohamed Abd almalek" in output
    assert "2.0.0" in output


# ── Tool class ────────────────────────────────────────────────────────

def test_tool_attributes():
    t = Tool("nmap", "optional", ["nmap", "--version"])
    assert t.name == "nmap"
    assert t.category == "optional"
    assert t.version_cmd == ["nmap", "--version"]
    assert t.update_cmd is None
    assert t.required is False


def test_tool_required():
    t = Tool("subfinder", "core", ["subfinder", "-version"], required=True)
    assert t.required is True


def test_tool_with_update_cmd():
    cmd = ["subfinder", "-update"]
    t = Tool("subfinder", "core", ["subfinder", "-version"], update_cmd=cmd)
    assert t.update_cmd == cmd


# ── Constants ─────────────────────────────────────────────────────────

def test_mode_config_keys():
    assert "stealth" in MODE_CONFIG
    assert "aggressive" in MODE_CONFIG
    assert MODE_CONFIG["stealth"]["threads"] < MODE_CONFIG["aggressive"]["threads"]


def test_tool_registry():
    assert len(TOOL_REGISTRY) > 15
    required_tools = [t for t in TOOL_REGISTRY if t.required]
    assert len(required_tools) >= 3
    required_names = {t.name for t in required_tools}
    assert "subfinder" in required_names
    assert "dnsx" in required_names
    assert "httpx" in required_names


def test_tool_registry_names_unique():
    names = [t.name for t in TOOL_REGISTRY]
    assert len(names) == len(set(names))


def test_special_parsers_keys():
    expected = {"subfinder", "nuclei", "dnsx", "httpx", "naabu",
                "katana", "shuffledns", "assetfinder", "fallparams"}
    assert expected.issubset(set(SPECIAL_PARSERS.keys()))
    for name in expected:
        assert SPECIAL_PARSERS[name] is _extract_version


def test_all_ports_format():
    ports = ALL_PORTS.split(",")
    assert all(p.isdigit() for p in ports)
    assert len(ports) > 20


def test_sensitive_ports_format():
    ports = SENSITIVE_PORTS.split(",")
    assert all(p.isdigit() for p in ports)
    sensitive_set = set(ports)
    all_set = set(ALL_PORTS.split(","))
    assert sensitive_set.issubset(all_set)


# ── ReconConfig ───────────────────────────────────────────────────────

def test_config_defaults():
    cfg = ReconConfig()
    assert cfg.verbose == 1
    assert cfg.phase_total == 8
    assert cfg.current_phase == 0
    assert cfg.domain == ""
    assert cfg.mode == "stealth"
    assert cfg.out_dir is None
    assert isinstance(cfg.logger, NullLogger)


def test_config_singleton():
    assert isinstance(CONFIG, ReconConfig)
    assert CONFIG.logger is not None


def test_config_custom_values(tmp_path):
    cfg = ReconConfig(
        out_dir=tmp_path,
        verbose=2,
        domain="test.com",
        mode="aggressive",
    )
    assert cfg.verbose == 2
    assert cfg.domain == "test.com"
    assert cfg.mode == "aggressive"
    assert cfg.out_dir == tmp_path


# ── NullLogger ────────────────────────────────────────────────────────

def test_null_logger_noop():
    nl = NullLogger()
    nl.log("test")
    nl.warn("test")
    nl.error("test")
    nl.info("test")
    nl.debug("test")
    nl.finding("CRITICAL", "test")
    nl.phase_header(1, "test")
    nl.phase_footer(1, 1.0)
    nl.progress_bar(1, 10)
    assert nl.tool_logs == Path()


# ── ReconLogger ───────────────────────────────────────────────────────

def test_recon_logger_init(tmp_path):
    log_dir = tmp_path / "logs"
    logger = ReconLogger(log_dir, verbose=1)
    assert log_dir.exists()
    assert (log_dir / "tools").exists()
    assert (log_dir / "phases").exists()
    assert logger.verbose == 1


def test_recon_logger_log(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.log("hello world")
    out = capsys.readouterr().out
    assert "hello world" in out


def test_recon_logger_warn(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.warn("warning msg")
    err = capsys.readouterr().err
    assert "warning msg" in err


def test_recon_logger_error(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.error("error msg")
    err = capsys.readouterr().err
    assert "error msg" in err


def test_recon_logger_info_shown(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.info("visible")
    out = capsys.readouterr().out
    assert "visible" in out


def test_recon_logger_info_quiet(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=0)
    logger.info("hidden")
    out = capsys.readouterr().out
    assert "hidden" not in out


def test_recon_logger_debug_shown(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=2)
    logger.debug("debug msg")
    out = capsys.readouterr().out
    assert "debug msg" in out


def test_recon_logger_debug_hidden(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.debug("hidden debug")
    out = capsys.readouterr().out
    assert "hidden debug" not in out


def test_recon_logger_finding(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.finding("CRITICAL", "SQL injection")
    out = capsys.readouterr().out
    assert "SQL injection" in out
    assert "CRITICAL" in out


def test_recon_logger_phase_header(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    old_phase = CONFIG.current_phase
    logger.phase_header(3, "Network Scanning")
    out = capsys.readouterr().out
    assert "Phase 3" in out
    assert "Network Scanning" in out
    assert CONFIG.current_phase == 3
    CONFIG.current_phase = old_phase


def test_recon_logger_phase_footer(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.phase_footer(1, 125.7)
    out = capsys.readouterr().out
    assert "2m 5s" in out


def test_recon_logger_progress_bar(capsys, tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.progress_bar(5, 10, "test")
    out = capsys.readouterr().out
    assert "5/10" in out


def test_recon_logger_file_output(tmp_path):
    logger = ReconLogger(tmp_path / "logs", verbose=1)
    logger.log("file test message")
    log_file = tmp_path / "logs" / "recon.log"
    assert log_file.exists()
    content = log_file.read_text()
    assert "file test message" in content


# ── PhaseRunner ───────────────────────────────────────────────────────

def test_phase_runner_is_done_false(tmp_path):
    runner = PhaseRunner(tmp_path)
    assert runner.is_done(1) is False


def test_phase_runner_mark_done(tmp_path):
    runner = PhaseRunner(tmp_path)
    runner.mark_done(1)
    assert runner.is_done(1) is True


def test_phase_runner_mark_done_different_phases(tmp_path):
    runner = PhaseRunner(tmp_path)
    runner.mark_done(1)
    runner.mark_done(3)
    assert runner.is_done(1) is True
    assert runner.is_done(2) is False
    assert runner.is_done(3) is True


def test_phase_runner_run_executes(tmp_path):
    runner = PhaseRunner(tmp_path)
    called = []
    runner.run(1, "Dummy", lambda: called.append(True))
    assert called == [True]


def test_phase_runner_run_marks_done(tmp_path):
    runner = PhaseRunner(tmp_path)
    runner.run(1, "Dummy", lambda: None)
    assert runner.is_done(1) is True


def test_phase_runner_run_skips_done(tmp_path):
    runner = PhaseRunner(tmp_path)
    runner.mark_done(1)
    called = []
    runner.run(1, "Dummy", lambda: called.append(True))
    assert called == []


# ── ReconPipeline ─────────────────────────────────────────────────────

def test_pipeline_init_creates_dirs(tmp_path):
    pipeline = ReconPipeline("example.com", "stealth", tmp_path, verbose=1)
    assert pipeline.d_sub.exists()
    assert pipeline.d_live.exists()
    assert pipeline.d_net.exists()
    assert pipeline.d_tech.exists()
    assert pipeline.d_content.exists()
    assert pipeline.d_params.exists()
    assert pipeline.d_js.exists()
    assert pipeline.d_vulns.exists()
    assert pipeline.d_screens.exists()


def test_pipeline_init_attributes(tmp_path):
    pipeline = ReconPipeline("example.com", "stealth", tmp_path, verbose=1)
    assert pipeline.domain == "example.com"
    assert pipeline.mode == "stealth"
    assert pipeline.verbose == 1
    assert pipeline.cfg == MODE_CONFIG["stealth"]


def test_pipeline_init_shared_paths(tmp_path):
    pipeline = ReconPipeline("test.io", "stealth", tmp_path, verbose=0)
    assert pipeline.f_final_subdomains == tmp_path / "subdomains" / "final.txt"
    assert pipeline.f_httpx_urls == tmp_path / "live_hosts" / "httpx.txt"
    assert pipeline.f_httpx_web == tmp_path / "live_hosts" / "httpx_web.txt"
    assert pipeline.f_live_urls == tmp_path / "content" / "live_urls.txt"
    assert pipeline.f_live_urls_200 == tmp_path / "content" / "live_urls_200_only.txt"


def test_pipeline_report_empty(tmp_path):
    pipeline = ReconPipeline("example.com", "stealth", tmp_path, verbose=0)
    pipeline._report()

    report = (tmp_path / "REPORT.md").read_text()
    assert "example.com" in report
    assert "stealth" in report
    assert "Subdomains" in report

    summary = (tmp_path / "SUMMARY.txt").read_text()
    assert "TARGET : example.com" in summary
    assert "MODE   : stealth" in summary


def test_pipeline_report_with_data(tmp_path):
    pipeline = ReconPipeline("example.com", "stealth", tmp_path, verbose=0)
    write_lines(pipeline.f_final_subdomains, ["a.example.com", "b.example.com"])
    write_lines(pipeline.f_httpx_urls, ["a.example.com"])
    write_lines(pipeline.d_tech / "full_stack.txt", ["nginx", "php", "jquery"])

    pipeline._report()

    report = (tmp_path / "REPORT.md").read_text()
    assert "2" in report  # 2 subdomains
    assert "1" in report  # 1 live host
    assert "3" in report  # 3 techs


# ── tool_available ────────────────────────────────────────────────────

def test_tool_available_true():
    with patch("recon.shutil.which", return_value="/usr/bin/python"):
        assert tool_available("python") is True


def test_tool_available_false():
    with patch("recon.shutil.which", return_value=None):
        assert tool_available("nonexistent_tool_xyz") is False


# ── which ─────────────────────────────────────────────────────────────

def test_which_found():
    from recon import which
    with patch("recon.shutil.which", return_value="/usr/bin/something"):
        assert which("something") == "/usr/bin/something"


def test_which_not_found():
    from recon import which
    with patch("recon.shutil.which", return_value=None):
        assert which("nonexistent") is None


# ── find_wordlist ─────────────────────────────────────────────────────

def test_find_wordlist_not_found():
    from recon import find_wordlist
    result = find_wordlist()
    assert result is None or isinstance(result, Path)


# ── Integration: ReconPipeline with PhaseRunner ───────────────────────

def test_pipeline_runner_integration(tmp_path):
    pipeline = ReconPipeline("example.com", "aggressive", tmp_path, verbose=0)
    results = []

    def phase_a():
        results.append("a")

    def phase_b():
        results.append("b")

    pipeline.runner.run(1, "Phase A", phase_a)
    pipeline.runner.run(2, "Phase B", phase_b)

    assert results == ["a", "b"]
    assert pipeline.runner.is_done(1)
    assert pipeline.runner.is_done(2)


# ── Passive fallback parsers ───────────────────────────────────────────

CRTSH_SAMPLE = (
    '[{"name_value":"*.emms.bbpos.com\\nappstore.prod.bbpos.com"},'
    '{"name_value":"api-sign.uat.bbpos.com"},'
    '{"name_value":null}]'
)

def test_parse_crtsh_json():
    hosts = _parse_crtsh_json(CRTSH_SAMPLE)
    assert "appstore.prod.bbpos.com" in hosts
    assert "api-sign.uat.bbpos.com" in hosts
    assert "emms.bbpos.com" in hosts
    assert len(hosts) == 3


def test_parse_crtsh_json_wildcard_lstrip():
    hosts = _parse_crtsh_json('[{"name_value":"*.fwsim.emms.bbpos.com"}]')
    assert hosts == ["fwsim.emms.bbpos.com"]


def test_parse_crtsh_json_invalid():
    assert _parse_crtsh_json("not json") == []
    assert _parse_crtsh_json("[1,2,3]") == []


def test_parse_hackertarget():
    text = "www.bbpos.com,1.2.3.4\napi.bbpos.com,5.6.7.8\nerror,invalid\n"
    assert _parse_hackertarget(text) == ["api.bbpos.com", "www.bbpos.com"]


def test_parse_otx_json():
    text = '{"passive_dns":[{"hostname":"a.bbpos.com"},{"hostname":"b.bbpos.com"},{"hostname":"bad"}]}]'
    # intentionally malformed closing to exercise exception path
    assert _parse_otx_json(text) == []


def test_parse_otx_json_valid():
    text = '{"passive_dns":[{"hostname":"a.bbpos.com"},{"hostname":"B.BBPOS.com"}]}'
    assert _parse_otx_json(text) == ["a.bbpos.com", "b.bbpos.com"]


def test_parse_bufferover_json():
    text = '{"FDNS_A":["foo.bbpos.com,1.2.3.4", "bar.bbpos.com,5.6.7.8"],"RDNS":["baz.bbpos.com,9.9.9.9"]}'
    assert _parse_bufferover_json(text) == ["bar.bbpos.com", "baz.bbpos.com", "foo.bbpos.com"]


def test_parse_wayback_json():
    text = '[["http://www.bbpos.com/x","20190101"],["https://api.bbpos.com/y","20200101"]]'
    hosts = _parse_wayback_json(text)
    assert "www.bbpos.com" in hosts
    assert "api.bbpos.com" in hosts


def test_passive_fallback_validates_and_dedupes():
    sample_crt = '[{"name_value":"a.bbpos.com\\nB.BBPOS.com\\nother.org"}]'
    with patch("recon._http_get", return_value=sample_crt):
        res = passive_fallback("bbpos.com", re.compile(r"([a-zA-Z0-9_-]+\.)+bbpos\.com$"))
    assert res == ["a.bbpos.com", "b.bbpos.com"]
    assert "other.org" not in res


def test_passive_fallback_all_unreachable():
    with patch("recon._http_get", return_value=None):
        res = passive_fallback("bbpos.com", re.compile(r"([a-zA-Z0-9_-]+\.)+bbpos\.com$"))
    assert res == []


# ── Phase 1: per-tool output files must not clobber each other ──────────

def test_phase1_assetfinder_does_not_truncate_subfinder(tmp_path):
    """Regression: assetfinder failing (empty stdout) must not wipe passive.txt.
    subfinder and assetfinder write to separate files that are both merged."""
    pipeline = ReconPipeline("example.com", "stealth", tmp_path, verbose=0)

    def fake_run_tool(name, cmd, stdout_path=None, **kwargs):
        if name == "subfinder" and stdout_path is not None:
            stdout_path.write_text("a.example.com\nb.example.com\n")
        # assetfinder writes nothing — passive.txt must survive
        return None

    with patch("recon.run_tool", side_effect=fake_run_tool):
        with patch("recon.tool_available", return_value=True):
            with patch("recon.passive_fallback", return_value=[]) as fb:
                pipeline._phase1()
                fb.assert_not_called()

    assert set(read_lines(pipeline.f_final_subdomains)) == {"a.example.com", "b.example.com"}


def test_phase1_fallback_fills_when_tools_empty(tmp_path):
    pipeline = ReconPipeline("example.com", "stealth", tmp_path, verbose=0)
    with patch("recon.run_tool", return_value=None):
        with patch("recon.passive_fallback", return_value=["x.example.com"]) as fb:
            pipeline._phase1()
    fb.assert_called_once()
    assert read_lines(pipeline.f_final_subdomains) == ["x.example.com"]
    assert read_lines(pipeline.d_sub / "fallback.txt") == ["x.example.com"]


# ── Phase 5: urlfinder command builder ────────────────────────────────

def test_build_urlfinder_cmd_per_domain_flags(tmp_path):
    out = tmp_path / "urlfinder.txt"
    cmd = build_urlfinder_cmd(["a.example.com", "b.example.com"], out)
    assert cmd[0] == "urlfinder"
    # one -d per domain — never a file path
    d_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-d"]
    assert d_values == ["a.example.com", "b.example.com"]
    assert not any(str(v).endswith(".txt") and v != str(out) for v in d_values)
    assert "-o" in cmd and str(out) in cmd


def test_build_urlfinder_cmd_no_max_time(tmp_path):
    """-max-time truncated multi-domain runs — it must stay out."""
    cmd = build_urlfinder_cmd(["a.example.com"], tmp_path / "o.txt")
    assert "-max-time" not in cmd
    assert "-max" not in " ".join(cmd)


def test_build_urlfinder_cmd_skips_blanks(tmp_path):
    cmd = build_urlfinder_cmd([" a.example.com ", "", "  "], tmp_path / "o.txt")
    d_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-d"]
    assert d_values == ["a.example.com"]


# ── Phase 6: fallparams command builder ───────────────────────────────

def test_build_fallparams_cmd_input_file(tmp_path):
    inp = tmp_path / "urls.txt"
    out = tmp_path / "fp.txt"
    cmd = build_fallparams_cmd(inp, out, threads=8)
    assert cmd[0] == "fallparams"
    assert "-u" in cmd and str(inp) in cmd
    assert "-o" in cmd and str(out) in cmd
    assert "-t" in cmd and "8" in cmd
    # no crawl — bounded runtime, uses only the collected live URLs
    assert "-c" not in cmd


def test_phase6_fallparams_merges_with_arjun(tmp_path):
    """from_fallparams.txt must land in all.txt alongside other sources."""
    pipeline = ReconPipeline("example.com", "stealth", tmp_path, verbose=0)
    p_dir = pipeline.d_params

    def fake_run_tool(name, cmd, stdout_path=None, **kwargs):
        if name == "arjun":
            (p_dir / "from_arjun.txt").write_text("arj_param\n")
        if name == "fallparams":
            (p_dir / "from_fallparams.txt").write_text("fp_param\n")
        return None

    (p_dir / "from_urls.txt").write_text("url_param\n")
    pipeline.f_live_urls.write_text("http://a.example.com/x?url_param=1\n")
    pipeline.f_live_urls_200.write_text("http://a.example.com/x\n")

    with patch("recon.run_tool", side_effect=fake_run_tool):
        with patch("recon.tool_available", return_value=True):
            pipeline._phase6()

    params = set(read_lines(p_dir / "all.txt"))
    assert {"url_param", "arj_param", "fp_param"}.issubset(params)
