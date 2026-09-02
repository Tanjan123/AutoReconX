from unittest.mock import patch

from typer.testing import CliRunner

from autoreconx.cli import app

runner = CliRunner()


def test_ip_passive_profile_does_not_run_ip_pipeline():
    with (
        patch("autoreconx.cli.run_ip_pipeline") as run_ip_pipeline,
        patch("autoreconx.cli.finalize_scan") as finalize_scan,
        patch("autoreconx.cli.print_scan_summary"),
    ):
        finalize_scan.return_value = object()

        result = runner.invoke(
            app,
            ["scan", "127.0.0.1", "--profile", "passive"],
        )

    assert result.exit_code == 0
    assert "passive profile is intended for domain targets" in result.stdout
    run_ip_pipeline.assert_not_called()


def test_ip_standard_profile_runs_ip_pipeline():
    with (
        patch("autoreconx.cli.run_ip_pipeline") as run_ip_pipeline,
        patch("autoreconx.cli.finalize_scan") as finalize_scan,
        patch("autoreconx.cli.print_scan_summary"),
        patch("autoreconx.cli.prioritize_scan") as prioritize_scan,
        patch("autoreconx.cli.print_priority_summary"),
        patch("autoreconx.cli.generate_reports") as generate_reports,
    ):
        finalize_scan.return_value = object()
        prioritize_scan.return_value = []
        generate_reports.return_value = (
            "report.json",
            "report.html",
        )

        result = runner.invoke(
            app,
            ["scan", "127.0.0.1", "--profile", "standard"],
        )

    assert result.exit_code == 0

    run_ip_pipeline.assert_called_once()

    kwargs = run_ip_pipeline.call_args.kwargs

    assert kwargs["ports"] is False
    assert kwargs["services"] is False
    assert kwargs["web"] is True
    assert kwargs["crawl"] is False
    assert kwargs["allow_public"] is False
