# Changelog

All notable changes to ReconX Framework are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.0.1] - 2026-07-16

### Fixed
- **Phase 1 subdomain loss** -- rewrote merge/clean logic to split on whitespace and validate hostname suffix with regex, fixing the critical bug where subfinder found hundreds of subdomains but only 1 survived
- **dnsx `-wd` flag removed** -- the wildcard detection flag was silently dropping valid subdomains during validation
- **Resolver fallback** -- added `config/resolvers.txt` fallback when `~/resolvers.txt` is missing
- **Phase 3 nmap gnmap parsing** -- replaced fragile `split()` with `re.compile` patterns for robust Host/port extraction
- **Phase 5 httpx output parsing** -- replaced bracket parsing with regex for reliable status code extraction
- **Phase 7 JS download** -- added `requests` library with fallback to `curl`, plus redirect/timeout handling
- **Ambiguous variable names** -- renamed `l` to `host`/`line`/`err_line`/`chunk_path` throughout

### Changed
- **Global state replaced** -- `OUT_DIR`, `VERBOSE_LEVEL`, `CURRENT_PHASE`, `PHASE_TOTAL` replaced with `ReconConfig` dataclass (`CONFIG` singleton)
- **All `logger.` references** updated to `CONFIG.logger.` throughout the codebase
- **NullLogger** -- added no-op logger class so `CONFIG.logger` is never `None`, eliminating 99 mypy errors
- **Version extraction** -- `SPECIAL_PARSERS` lambdas replaced with `_extract_version()` helper that returns `"?"` on failure instead of crashing
- **Python requirement** -- raised minimum from 3.8 to 3.10 (dataclass `field()` with `default_factory`)

### Added
- **Type hints** -- full annotations on all methods, `ReconConfig` dataclass fields
- **mypy** -- passes with zero errors via `--ignore-missing-imports`
- **ruff** -- passes with zero warnings (config migrated to `[tool.ruff.lint]` section)
- **63 unit tests** covering utilities, logging, PhaseRunner, ReconPipeline, CLI parsing, constants, tool registry
- **GitHub Actions CI** -- lint (ruff + mypy), test matrix (Python 3.10-3.13), syntax check, coverage upload
- **Pre-commit hooks** -- `.pre-commit-config.yaml` with ruff + mypy
- **Windows installer** -- `install.ps1` PowerShell script (mirrors `install.sh`)
- **CLI entry point** -- `reconx` command via `pyproject.toml [project.scripts]`
- **`python -m recon`** -- `__main__.py` for module execution
- **`pyproject.toml`** -- full packaging config with dev/ui/tools optional dependencies
- **Coverage config** -- `pytest-cov` with `fail_under = 50` and XML report for Codecov
- **`config/resolvers.txt`** -- bundled DNS resolvers for shuffledns fallback

### Removed
- Unused imports (`os`, `as_completed`) -- ruff auto-fix

## [2.0.0] - 2025-06-19

### Added
- Initial 8-phase pipeline release
- 25+ tool integrations
- Stealth and aggressive modes
- Phase-level resume markers
- Markdown + text reporting
- `--check` tool doctor
- `--update` auto-updater
- Rich terminal output (optional)
- Cross-platform support (Linux/macOS/WSL)
