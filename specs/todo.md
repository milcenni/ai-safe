Build: ai-safe — AI Secrets Protection & Sanitization Toolkit

Act as a Senior Security Engineer, DevSecOps Architect, and Python CLI Developer.

Build a production-ready CLI tool named ai-safe that prevents AI coding agents (Claude Code, Cursor, GitHub Copilot, etc.) from accessing sensitive credentials in software repositories.

The primary objective:

AI must never receive real passwords, API keys, access tokens, private keys, or other sensitive credentials from the developer's project or Git history.

The tool must discover, sanitize, verify, and safely integrate code changes without exposing original credentials to AI.

Do not just create a design document. Implement the actual working application, tests, documentation, and Claude Code skills.

1. Core Architecture

Implement the following workflow:

Developer Repository → Secret Discovery → Secret Classification → Sanitization → AI Workspace Creation → AI Development → Change Extraction → Change Validation → Controlled Integration → Final Security Verification

Maintain two separate environments:

A. Original Workspace

Contains original source code.
Contains real credentials.
Contains original Git repository and history.
Never directly exposed to AI.

B. AI Sanitized Workspace

Contains sanitized source code.
Contains placeholder credentials.
Does not contain original Git history.
Does not contain actual secrets.
Is the only workspace accessible to AI.

Never modify the original Git history during normal operation.

Never automatically push code to a remote repository.

2. Technology Stack

Use:

Python 3.12+
Typer for CLI
Rich for terminal UI
Pydantic for configuration validation
Gitleaks for secret detection
PyYAML for configuration
Pytest for automated testing
Git CLI for repository operations

Use a modular architecture with clear separation of responsibilities.

3. CLI Commands

Implement these commands:

Scan

ai-safe scan

Requirements:

Detect secrets in tracked files.
Detect secrets in untracked files.
Detect secrets in staged changes.
Detect secrets in unstaged changes.
Scan complete Git history.
Detect secrets in ignored files where accessible.
Detect credentials in common configuration files.
Support Gitleaks JSON reports.
Categorize findings.
Generate a sanitized report without printing actual secret values.

Categories:

API_KEY
ACCESS_TOKEN
PASSWORD
DATABASE_CREDENTIAL
PRIVATE_KEY
SSH_KEY
CLOUD_CREDENTIAL
JWT_SECRET
GENERIC_SECRET

Never expose actual secret values in logs or terminal output.

Sanitize

ai-safe sanitize

Requirements:

Create an isolated temporary AI workspace.
Copy permitted source files.
Detect and replace credentials with deterministic placeholders.
Exclude .env files.
Exclude private keys.
Exclude credential stores.
Exclude sensitive configuration files.
Exclude original .git directory.
Exclude Git metadata and hooks.
Maintain original source file permissions where safe.
Generate a sanitization manifest.

Example:

Original: OPENAI_API_KEY=sk-real-secret DB_PASSWORD=real-password

Sanitized: OPENAI_API_KEY=${AI_SAFE_SECRET_OPENAI_API_KEY} DB_PASSWORD=${AI_SAFE_SECRET_DB_PASSWORD}

Use deterministic placeholders so the same secret has consistent replacement references.

Do not store actual secrets in the manifest.

Do not use simple regex replacement alone. Use Gitleaks findings, configurable detection rules, file classification, and additional validation.

Important: Gitleaks is a detector, not a complete redaction engine. Implement a separate redaction engine that can identify exact secret locations and safely handle different file formats.

If a secret cannot be confidently identified or replaced, fail closed and exclude the affected file from the AI workspace.

Never silently leave unresolved secrets in the sanitized workspace.

Verify

ai-safe verify

Requirements:

Scan the entire AI workspace.
Scan text files, configuration files, scripts, and hidden files.
Detect secrets using Gitleaks.
Check for private keys.
Check for unexpected binary files.
Check for symlinks escaping the workspace.
Check for original Git metadata.
Check for credential files.
Generate a verification report.

Return non-zero exit status if any unresolved secrets are detected.

Only allow AI access when verification passes.

Start

ai-safe start

Requirements:

Run scan.
Create sanitized workspace.
Run verification.
Display workspace location.
Display a security summary.
Provide clear instructions for launching Claude Code inside the sanitized workspace.

Do not launch AI automatically unless explicitly configured.

Review

ai-safe review

Requirements:

Collect changes made by AI.
Compare sanitized workspace against its initial snapshot.
Detect modifications to sensitive configuration files.
Detect hardcoded credentials introduced by AI.
Detect placeholder misuse.
Detect unexpected file creation.
Run Gitleaks on generated changes.
Produce a review report.

Never automatically restore credentials into AI-generated files.

Integrate

ai-safe integrate

Requirements:

Apply approved AI changes to the original repository.
Use a patch-based integration process.
Preserve real credentials in the original workspace.
Never overwrite original credential files.
Reject changes attempting to modify excluded sensitive files.
Reject unexpected symlinks.
Detect path traversal.
Validate patch paths before application.
Run final Gitleaks scans.
Require explicit developer confirmation.

Do not automatically commit or push.

4. Git History Protection

Git history is a critical attack surface.

Implement protection for:

Current HEAD.
All reachable branches.
All reachable tags.
Previous commits.
Deleted files still present in history.
Secrets removed from current source but retained in previous commits.

Use:

gitleaks git --report-format json

Or the appropriate supported Gitleaks version and command.

Do not expose the original .git directory to AI.

Do not copy original commit objects into the AI workspace.

Provide an option to generate sanitized historical summaries without including original secrets.

Never rewrite Git history automatically.

If a real credential has already been exposed in Git history, warn that the credential must be rotated. Sanitization does not undo prior exposure.

5. Credential Mapping and Restoration

Create a secure credential mapping mechanism.

Example:

Original: API_KEY=sk-secret-123

AI Workspace: API_KEY=${AI_SAFE_SECRET_001}

Store mappings outside the AI workspace with restrictive filesystem permissions.

Requirements:

Never log actual secret values.
Never expose mapping files to AI.
Never automatically inject original credentials into AI workspace.
Support encrypted mapping storage.
Use OS-protected permissions.
Provide an explicit cleanup command.
Do not require credential restoration for normal integration.

Prefer keeping credentials in environment variables or a dedicated secret manager rather than hardcoding them back into source code.

6. Claude Code Integration

Create native Claude Code integration.

Generate:

.claude/skills/ai-safe/SKILL.md

The skill should instruct Claude Code to:

Confirm it is operating inside an AI-safe workspace.
Never request real credentials.
Never attempt to access parent directories containing the original repository.
Never search outside the approved workspace for secrets.
Use environment variable placeholders.
Avoid generating hardcoded credentials.
Never create or modify .env files.
Never attempt to recover sanitized credentials.
Run security checks after implementation.
Report any missing configuration as a placeholder requirement.

Create additional reusable skills:

ai-safe-scan/SKILL.md
ai-safe-sanitize/SKILL.md
ai-safe-review/SKILL.md
ai-safe-integrate/SKILL.md
ai-safe-security-audit/SKILL.md

Each skill must include clear instructions, execution boundaries, expected inputs, outputs, and failure conditions.

Important: Claude Code skills are instructions, not a security boundary. Enforce isolation using OS permissions, sandboxing, and separate workspace access.

7. Security Requirements

Follow security-by-design principles.

Mandatory controls:

Fail-closed architecture.
No automatic Git push.
No automatic Git commit.
No original Git history exposed.
No secret values in logs.
No secret values in error messages.
No credentials in temporary filenames.
Secure temporary directory creation.
Restrictive filesystem permissions.
Symlink validation.
Path traversal protection.
Secure cleanup.
Explicit user approval for integration.
No execution of untrusted AI-generated scripts during review.
No automatic execution of project hooks.
No network access required for sanitization.
No telemetry.

Do not claim that Gitleaks alone guarantees that all secrets have been found.

Support configurable custom detection rules.

Document detection limitations, including secrets that cannot be recognized by pattern matching.

8. Configuration

Create:

ai-safe.yaml

Example:

yaml
version: 1

scanner:
  engine: gitleaks
  scan_git_history: true
  scan_untracked: true
  scan_ignored: true

sanitization:
  exclude:
    - .env
    - .env.*
    - "*.pem"
    - "*.key"
    - credentials.json
    - secrets/
    - .ssh/

  placeholders:
    enabled: true
    deterministic: true

workspace:
  isolated: true
  include_git_history: false
  verify_before_ai_access: true

integration:
  require_approval: true
  auto_commit: false
  auto_push: false

security:
  fail_closed: true
  redact_logs: true
  reject_symlinks: true


Validate all configuration before execution.

9. Project Structure

Use a structure similar to:

text
ai-safe/
├── pyproject.toml
├── README.md
├── LICENSE
├── ai-safe.yaml
├── src/
│   └── ai_safe/
│       ├── cli.py
│       ├── scanner.py
│       ├── classifier.py
│       ├── sanitizer.py
│       ├── verifier.py
│       ├── git_history.py
│       ├── workspace.py
│       ├── credential_map.py
│       ├── patch_manager.py
│       ├── integration.py
│       ├── security.py
│       └── reporting.py
├── skills/
│   ├── ai-safe/
│   │   └── SKILL.md
│   ├── ai-safe-scan/
│   │   └── SKILL.md
│   ├── ai-safe-sanitize/
│   │   └── SKILL.md
│   ├── ai-safe-review/
│   │   └── SKILL.md
│   ├── ai-safe-integrate/
│   │   └── SKILL.md
│   └── ai-safe-security-audit/
│       └── SKILL.md
├── tests/
│   ├── test_scanner.py
│   ├── test_sanitizer.py
│   ├── test_verifier.py
│   ├── test_git_history.py
│   ├── test_integration.py
│   └── test_security.py
└── examples/
    └── sample-project/


Adjust the architecture where necessary but maintain modularity.

10. Testing Requirements

Build comprehensive automated tests.

Test at least these scenarios:

API key in Python source code.
Database password in .env.
AWS-style access credentials.
SSH private key.
Password in YAML configuration.
Credentials in JSON.
Secret in an untracked file.
Secret in a staged Git change.
Secret in an unstaged Git change.
Secret in previous Git commit.
Secret removed from latest commit but retained in history.
Secret introduced by AI-generated code.
Placeholder incorrectly replaced.
Symlink pointing outside workspace.
Path traversal attack.
AI attempting to modify .env.
AI attempting to access original Git history.
Sanitization failure.
Integration preserving original credentials.
Cleanup of temporary workspaces.

Use synthetic test credentials only.

Never use real credentials in tests.

11. Documentation

Create a detailed README covering:

What ai-safe does.
Threat model.
Architecture.
Installation.
CLI usage.
Claude Code integration.
Configuration.
Sanitization process.
Git history handling.
Security limitations.
Recovery and cleanup.
Example workflow.

Include a Mermaid architecture diagram.

Include a practical example:

bash
# Install
pip install -e .

# Scan
ai-safe scan

# Sanitize
ai-safe sanitize

# Verify
ai-safe verify

# Start AI-safe workflow
ai-safe start

# Review AI changes
ai-safe review

# Integrate approved changes
ai-safe integrate

12. Implementation Instructions

Work incrementally.

Phase 1:

Inspect the environment.
Create project structure.
Implement scanner.
Implement Git history scanner.

Phase 2:

Implement sanitization.
Implement placeholder mapping.
Implement isolated workspace.

Phase 3:

Implement verification.
Implement AI workspace security controls.

Phase 4:

Implement review and patch-based integration.

Phase 5:

Generate Claude Code skills.
Add tests and documentation.

Phase 6:

Run the complete test suite.
Fix all failures.
Perform a security review.
Verify that the original repository and credentials remain unchanged.

Do not use real project credentials during testing.

Do not automatically install dependencies without approval.

Do not push anything to a remote repository.

Do not claim security guarantees without evidence.

If a feature cannot be implemented safely, document the limitation and fail closed rather than implementing an insecure workaround.

Final Deliverables

At completion, provide:

Working ai-safe CLI.
All Claude Code skills.
Configuration template.
Automated tests.
README and architecture documentation.
Security threat model.
Test execution report.
Known limitations.
Example end-to-end workflow.

Final acceptance criterion:

Claude Code must only be able to access a verified, sanitized workspace. The original credentials, original Git history, and secret mapping must remain outside its accessible environment. AI-generated changes must be reviewed before being integrated into the original repository.