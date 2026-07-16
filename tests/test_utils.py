"""Tests for ReconX Framework utilities."""

import re
import sys
from pathlib import Path
from unittest.mock import patch

from recon import (
    escape_domain,
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
)


# ── Utility functions ─────────────────────────────────────────────────

def test_escape_domain():
    assert escape_domain("example.com") == r"example\.com"
    assert escape_domain("sub.example.com") == r"sub\.example\.com"
    assert escape_domain("test-domain.com") == r"test\-domain\.com"


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
                "katana", "shuffledns", "chaos"}
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
