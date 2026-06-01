from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_requirements_do_not_include_native_ldap_package():
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")

    assert "python" + "-ldap" not in requirements


def test_exchange_path_keeps_certificate_validation_enabled():
    exchange_source = (ROOT / "app" / "exchange.py").read_text(encoding="utf-8")

    disabled_validation_tokens = [
        "ServerCertificate" + "ValidationCallback",
        "SkipCA" + "Check",
        "SkipCN" + "Check",
    ]
    assert "server_cert_validation='validate'" in exchange_source
    for token in disabled_validation_tokens:
        assert token not in exchange_source


def test_build_script_does_not_install_systemd_service_on_import():
    build_source = (ROOT / "build.py").read_text(encoding="utf-8")
    build_shell_source = (ROOT / "build.sh").read_text(encoding="utf-8")

    assert "setup_service()" not in build_source
    assert "systemctl" not in build_source
    assert "systemctl" not in build_shell_source


def test_build_runner_propagates_failed_substep(monkeypatch):
    import build

    runner = build.GEEKSBuildSystem()

    def fake_run(command, **kwargs):
        if command == ["venv/bin/python", "-m", "pytest", "-q"]:
            return subprocess.CompletedProcess(command, 2, stdout="", stderr="pytest failed")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(build.subprocess, "run", fake_run)

    assert runner.run_tests() is False


def test_gpo_startup_script_does_not_bypass_execution_policy():
    source_paths = [
        ROOT / "app" / "views.py",
        ROOT / "windows-credential-provider" / "gpo-deploy.ps1",
    ]

    for source_path in source_paths:
        source = source_path.read_text(encoding="utf-8")
        assert "-ExecutionPolicy " + "Bypass" not in source


def test_credential_provider_requires_https_portal_url():
    source_paths = [
        ROOT / "windows-credential-provider" / "install.ps1",
        ROOT / "windows-credential-provider" / "gpo-deploy.ps1",
        ROOT / "app" / "templates" / "gpo_deployment.html",
    ]

    for source_path in source_paths:
        source = source_path.read_text(encoding="utf-8")
        assert "https://" in source
        assert "http://localhost:5000" + "/reset-password" not in source
