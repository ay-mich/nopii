🧭 no-pii Package Publication Guide

A comprehensive guide for building, testing, and publishing Python packages using modern tools like uv, Hatch, MkDocs, and GitHub Trusted Publishing.

⸻

🚀 Initial Setup & Prerequisites

1️⃣ Development Environment Setup

# Sync all dependencies, including dev, bigquery, and snowflake extras

uv sync --all-groups --all-extras

# Install and activate pre-commit hooks

pre-commit install

# Run pre-commit on all files once

pre-commit run -a

⸻

2️⃣ GitHub Repository Setup

Required GitHub Secrets (if not using Trusted Publishing)

Go to Settings → Secrets and variables → Actions:
• PYPI_API_TOKEN – PyPI token (for manual publishing, if you’re not using Trusted Publishing).
• Get from: https://pypi.org/manage/account/token/
• Scope: “Entire account” or “Specific project”
• CODECOV_TOKEN – For code coverage (required for private repos).
• Get from: https://codecov.io/

Enable GitHub Pages (for docs) 1. Settings → Pages 2. Source: Deploy from branch 3. Branch: gh-pages 4. Folder: / (root)

⸻

🔒 Trusted Publishing (Recommended)

Instead of using API tokens, enable Trusted Publishing for secure, tokenless uploads. 1. On PyPI → Manage project → Publishing → Add publisher 2. Select GitHub Actions and link your repo 3. Remove PYPI_API_TOKEN from GitHub secrets 4. Your GitHub Action can now publish directly to PyPI securely

⸻

📋 Pre-Publication Checklist

1️⃣ Code Quality Checks

# Type checking

uv run mypy src

# Tests

uv run pytest -q

# Coverage

uv run pytest --cov=no-pii --cov-report=term-missing

# Format, lint, and pre-commit

uv run ruff check .
pre-commit run -a

⸻

2️⃣ Documentation Checks

# Preview docs locally

uv run mkdocs serve

# Build docs to confirm success

uv run mkdocs build

⸻

3️⃣ Version Management

Update version

Edit pyproject.toml:

[project]
version = "0.1.1"

Update changelog

## [0.1.1] - 2025-01-XX

### Added

- Example feature

### Fixed

- Example bug

⸻

🏗️ Build and Test Package

1️⃣ Clean previous builds

rm -rf dist/ build/ \*.egg-info/

2️⃣ Build package

uv build

3️⃣ Test built wheel

# Create isolated test environment

python -m venv test_env
source test_env/bin/activate

# Install the built wheel

pip install dist/no-pii-\*.whl

# Verify import and CLI

python -c "import no-pii; print('Import successful')"
no-pii --help

deactivate && rm -rf test_env

⸻

📦 PyPI Publication

1️⃣ Test on TestPyPI (first!)

uv publish --repository testpypi
uv pip install -i https://test.pypi.org/simple no-pii

2️⃣ Publish to production PyPI

uv publish

3️⃣ Verify
• PyPI: https://pypi.org/project/no-pii/
• Install test:

uv pip install no-pii

⸻

🔄 Git Workflow

1️⃣ Prepare and commit release

git add .
git commit -m "chore: bump version to 0.1.1"
git push origin main

2️⃣ Tag the release

git tag -a v0.1.1 -m "Release version 0.1.1"
git push origin v0.1.1

3️⃣ Release automation

When tag v\* is pushed:
• Builds and publishes to PyPI
• Creates GitHub release with changelog
• Deploys docs to GitHub Pages

If manual release needed: 1. GitHub → Releases → New release 2. Tag: v0.1.1 3. Title: Release 0.1.1 4. Paste changelog section

⸻

🔧 Maintenance Workflows

Regular Development

git pull origin main
uv run mypy src
uv run pytest
pre-commit run -a

Dependency Updates (modern uv flow)

# Update all dependencies to latest compatible

uv lock --upgrade
uv sync

# Upgrade a specific package

uv lock --upgrade-package pandas
uv sync

# Check what’s outdated

uvx uv-outdated

Security Updates

pip audit

⸻

📊 Monitoring & Analytics
• PyPI downloads: https://pypistats.org/packages/no-pii
• GitHub insights: Repo → Insights → Traffic
• Codecov: https://codecov.io/gh/ay-mich/no-pii
• Docs analytics: GitHub Pages Insights

⸻

🐛 Troubleshooting

Build Failures

pip cache purge
rm -rf dist/ build/ \*.egg-info/
uv build

If Hatch errors:

# Ensure your hatch config uses:

[tool.hatch.build.targets.wheel]
packages = ["src/no-pii"]

Test Failures

uv run pytest -v
uv run pytest --pdb
uv run pytest --cov=no-pii --cov-report=term-missing

Docs Issues

uv run mkdocs build --strict
uv run mkdocs serve --dev-addr=127.0.0.1:8001

PyPI Upload Issues

uv run twine check dist/\*
uv publish --verbose

⸻

📋 Release Checklist Template

Copy this for each release:
• Update version in pyproject.toml
• Update CHANGELOG.md
• Run tests (pytest)
• Type check (mypy src)
• Lint (ruff check .)
• Build package (uv build)
• Test install locally
• Upload to TestPyPI
• Tag and push release
• Publish to PyPI
• Verify PyPI + docs
• Verify GitHub release
• Verify test install (uv pip install no-pii)

⸻

📎 Useful Links
• PyPI Project: https://pypi.org/project/no-pii/
• TestPyPI: https://test.pypi.org/project/no-pii/
• GitHub: https://github.com/ay-mich/no-pii
• Docs: https://no-pii.readthedocs.io
• Codecov: https://codecov.io/gh/ay-mich/no-pii
• API Tokens: https://pypi.org/manage/account/token/

⸻

🧠 Notes & Best Practices
• Always test on TestPyPI before production
• Use semantic versioning (MAJOR.MINOR.PATCH)
• Keep your CHANGELOG up to date
• Use Trusted Publishing to avoid token leaks
• Include runnable examples in examples/
• Monitor your PyPI downloads and GitHub insights

⸻

🧾 One-Page Printable Publishing Checklist

Use this quick version before every release:

# 1️⃣ Environment

uv sync --all-groups --all-extras

# 2️⃣ Quality gates

ruff check .
mypy src
pytest --cov=no-pii

# 3️⃣ Docs

mkdocs build

# 4️⃣ Version bump

vim pyproject.toml # update version
vim CHANGELOG.md # update log

# 5️⃣ Build

uv build

# 6️⃣ Test install

uv pip install dist/no-pii-\*.whl
no-pii --help

# 7️⃣ Publish to TestPyPI

uv publish --repository testpypi
uv pip install -i https://test.pypi.org/simple no-pii==X.Y.Z

# 8️⃣ Publish to PyPI

uv publish

# 9️⃣ Tag + release

git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0

# 🔟 Verify

pip install no-pii

⸻

Last updated: 2025-10-20
Package version: 0.1.0
Maintainer: Ayden Mich

⸻

✅ Highlights of this version
• Fully GitHub-renderable Markdown (no broken fences)
• All code blocks closed cleanly
• Section headers consistent for navigation
• Ends with a concise one-page checklist for print or reuse
