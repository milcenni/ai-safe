#!/usr/bin/env bash
# ai-safe installer
#
#   ./install.sh --global                 # per-user: ~/.local/share/ai-safe, ~/.local/bin/ai-safe, ~/.claude/skills
#   ./install.sh --local /path/to/project # project:  <project>/.ai-safe/, <project>/.claude/skills, ai-safe.yaml
#   ./install.sh --uninstall --global|--local DIR
#
# Options:
#   --yes            consent to downloads (PyPI packages, gitleaks release) without prompting
#   --no-gitleaks    do not install gitleaks (ai-safe then refuses to run until gitleaks is
#                    available or you explicitly set scanner.engine: builtin)
#   --force          overwrite an existing installation / ai-safe skills
#   --php            also install the optional PHP function tracing extra (tree-sitter,
#                    tree-sitter-php from PyPI); without it PHP tracing covers variables,
#                    includes and constants only
#
# Nothing is installed system-wide and no sudo is used. Supported: Linux and macOS (x64/arm64).
set -euo pipefail

GITLEAKS_VERSION="8.21.2"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=""
PROJECT=""
YES=0
WITH_GITLEAKS=1
FORCE=0
UNINSTALL=0
WITH_PHP=0

say()  { printf '\033[1;36m[ai-safe]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ai-safe] warning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ai-safe] error:\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --global) MODE="global" ;;
    --local)
      MODE="local"
      if [ $# -gt 1 ] && [ "${2#--}" = "$2" ]; then PROJECT="$2"; shift; else PROJECT="."; fi ;;
    --yes|-y) YES=1 ;;
    --no-gitleaks) WITH_GITLEAKS=0 ;;
    --force) FORCE=1 ;;
    --php) WITH_PHP=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) usage 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

is_tty() { [ -t 0 ] && [ -t 1 ]; }

confirm() {  # confirm "question"  -> 0 yes / 1 no
  [ "$YES" -eq 1 ] && return 0
  is_tty || return 1
  local ans
  read -r -p "$1 [y/N] " ans
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------- mode ----
if [ -z "$MODE" ]; then
  is_tty || die "choose --global or --local <project-dir> (no terminal to ask interactively)"
  echo "Install ai-safe:"
  echo "  1) globally for your user   (~/.local/bin/ai-safe, skills in ~/.claude/skills)"
  echo "  2) locally in one project   (<project>/.ai-safe/, skills in <project>/.claude/skills)"
  read -r -p "Choose 1 or 2: " choice
  case "$choice" in
    1) MODE="global" ;;
    2) MODE="local"; read -r -p "Project directory [.]: " PROJECT; PROJECT="${PROJECT:-.}" ;;
    *) die "aborted" ;;
  esac
fi

if [ "$MODE" = "global" ]; then
  DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/ai-safe"
  BIN_DIR="$HOME/.local/bin"
  SKILLS_ROOT="$HOME"
else
  [ -d "$PROJECT" ] || die "project directory not found: $PROJECT"
  PROJECT="$(cd "$PROJECT" && pwd)"
  [ "$PROJECT" = "$SRC_DIR" ] && die "install into your project, not into the ai-safe source tree"
  DATA_DIR="$PROJECT/.ai-safe"
  BIN_DIR="$DATA_DIR/bin"
  SKILLS_ROOT="$PROJECT"
fi
VENV="$DATA_DIR/venv"
WRAPPER="$BIN_DIR/ai-safe"
SKILLS=(ai-safe ai-safe-scan ai-safe-sanitize ai-safe-review ai-safe-integrate ai-safe-security-audit)

# ----------------------------------------------------------- uninstall ----
if [ "$UNINSTALL" -eq 1 ]; then
  say "uninstalling ($MODE)"
  rm -rf "$VENV"
  [ -f "$WRAPPER" ] && grep -q "ai-safe wrapper" "$WRAPPER" && rm -f "$WRAPPER"
  [ -f "$BIN_DIR/gitleaks" ] && [ -f "$DATA_DIR/.gitleaks-installed-by-ai-safe" ] && rm -f "$BIN_DIR/gitleaks" "$DATA_DIR/.gitleaks-installed-by-ai-safe"
  for s in "${SKILLS[@]}"; do rm -rf "$SKILLS_ROOT/.claude/skills/$s"; done
  [ "$MODE" = "local" ] && rmdir "$BIN_DIR" "$DATA_DIR" 2>/dev/null || true
  say "removed. Session data in ~/.local/state/ai-safe is kept: run 'ai-safe cleanup --all' first to remove it."
  exit 0
fi

# -------------------------------------------------------- prerequisites ----
case "$(uname -s)" in
  Linux) OS=linux ;; Darwin) OS=darwin ;; *) die "unsupported OS: $(uname -s) (Linux/macOS only)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=x64 ;; arm64|aarch64) ARCH=arm64 ;; *) die "unsupported CPU: $(uname -m)" ;;
esac
command -v git >/dev/null || die "git is required"

PY=""
for cand in python3.13 python3.12 python3.11 python3; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PY="$(command -v "$cand")"; break
  fi
done
[ -n "$PY" ] || die "Python 3.11+ is required (3.12+ recommended)"
"$PY" -c 'import venv' 2>/dev/null || die "the Python venv module is missing (e.g. apt install python3-venv)"

if [ -e "$VENV" ] && [ "$FORCE" -ne 1 ]; then
  die "ai-safe already installed at $VENV (use --force to reinstall)"
fi

say "mode: $MODE"
say "python: $PY ($("$PY" -V 2>&1))"
say "install dir: $DATA_DIR"

PY_DEPS="typer, rich, pydantic, PyYAML, cryptography"
[ "$WITH_PHP" = 1 ] && PY_DEPS="$PY_DEPS, tree-sitter, tree-sitter-php"
confirm "Download and install ai-safe's Python dependencies ($PY_DEPS) from PyPI into $VENV?" \
  || die "dependency installation not approved - nothing was installed"

# ---------------------------------------------------------- python pkg ----
mkdir -p "$DATA_DIR" "$BIN_DIR"
chmod 700 "$DATA_DIR"
rm -rf "$VENV"
"$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
if [ "$WITH_PHP" = 1 ]; then
  "$VENV/bin/python" -m pip install --quiet "$SRC_DIR[php]"
else
  "$VENV/bin/python" -m pip install --quiet "$SRC_DIR"
fi
say "installed ai-safe into $VENV"

# ------------------------------------------------------------ gitleaks ----
GITLEAKS_BIN=""
version_ok() {  # >= 8.19 (needs the 'dir' subcommand)
  local v; v="$("$1" version 2>/dev/null | sed 's/^v//')" || return 1
  local major minor; major="${v%%.*}"; minor="$(echo "$v" | cut -d. -f2)"
  [ "${major:-0}" -gt 8 ] || { [ "${major:-0}" -eq 8 ] && [ "${minor:-0}" -ge 19 ]; }
}
if command -v gitleaks >/dev/null 2>&1 && version_ok "$(command -v gitleaks)"; then
  GITLEAKS_BIN="$(command -v gitleaks)"
  say "using existing gitleaks: $GITLEAKS_BIN ($("$GITLEAKS_BIN" version))"
elif [ "$WITH_GITLEAKS" -eq 1 ]; then
  if confirm "Download gitleaks v$GITLEAKS_VERSION ($OS/$ARCH) from github.com/gitleaks/gitleaks and verify its SHA-256 checksum?"; then
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
    tarball="gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.tar.gz"
    curl -fsSL -o "$TMP/$tarball" "$base/$tarball" || die "download failed: $tarball"
    curl -fsSL -o "$TMP/checksums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" || die "checksum download failed"
    expected="$(grep " $tarball\$" "$TMP/checksums.txt" | awk '{print $1}')"
    [ -n "$expected" ] || die "no checksum published for $tarball"
    if command -v sha256sum >/dev/null; then actual="$(sha256sum "$TMP/$tarball" | awk '{print $1}')"
    else actual="$(shasum -a 256 "$TMP/$tarball" | awk '{print $1}')"; fi
    [ "$expected" = "$actual" ] || die "gitleaks checksum mismatch - refusing to install"
    tar -xzf "$TMP/$tarball" -C "$TMP" gitleaks
    install -m 0755 "$TMP/gitleaks" "$BIN_DIR/gitleaks"
    : > "$DATA_DIR/.gitleaks-installed-by-ai-safe"
    GITLEAKS_BIN="$BIN_DIR/gitleaks"
    say "installed gitleaks $("$GITLEAKS_BIN" version) (checksum verified)"
  else
    warn "gitleaks not installed. ai-safe will refuse to scan until gitleaks is available"
    warn "(or until you deliberately set 'scanner.engine: builtin' in ai-safe.yaml)."
  fi
else
  warn "--no-gitleaks: ai-safe will refuse to scan until gitleaks is available or scanner.engine: builtin is set."
fi

# ------------------------------------------------------------- wrapper ----
{
  echo "#!/bin/sh"
  echo "# ai-safe wrapper (generated by install.sh)"
  if [ -n "$GITLEAKS_BIN" ]; then
    printf 'if [ -z "$AI_SAFE_GITLEAKS" ]; then AI_SAFE_GITLEAKS=%q; export AI_SAFE_GITLEAKS; fi\n' "$GITLEAKS_BIN"
  fi
  printf 'exec %q "$@"\n' "$VENV/bin/ai-safe"
} > "$WRAPPER"
chmod 0755 "$WRAPPER"

# -------------------------------------------------------------- skills ----
for s in "${SKILLS[@]}"; do
  if [ -e "$SKILLS_ROOT/.claude/skills/$s" ] && [ "$FORCE" -ne 1 ] && ! cmp -s "$SRC_DIR/skills/$s/SKILL.md" "$SKILLS_ROOT/.claude/skills/$s/SKILL.md"; then
    warn "skill $s exists and differs - keeping yours (use --force to overwrite)"
    continue
  fi
  mkdir -p "$SKILLS_ROOT/.claude/skills/$s"
  install -m 0644 "$SRC_DIR/skills/$s/SKILL.md" "$SKILLS_ROOT/.claude/skills/$s/SKILL.md"
done
say "skills installed in $SKILLS_ROOT/.claude/skills/"

# ------------------------------------------------------ project config ----
if [ "$MODE" = "local" ]; then
  if [ ! -e "$PROJECT/ai-safe.yaml" ]; then
    "$WRAPPER" init "$PROJECT" >/dev/null && say "wrote $PROJECT/ai-safe.yaml"
  fi
  if git -C "$PROJECT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if ! git -C "$PROJECT" check-ignore -q .ai-safe/venv 2>/dev/null; then
      if confirm "Add '.ai-safe/' to $PROJECT/.gitignore so the local install is never committed?"; then
        printf '\n# ai-safe local install\n.ai-safe/\n' >> "$PROJECT/.gitignore"
        say "added .ai-safe/ to .gitignore"
      else
        warn "add '.ai-safe/' to your .gitignore so the local install is not committed"
      fi
    fi
  fi
fi

# --------------------------------------------------------------- check ----
"$WRAPPER" version >/dev/null || die "post-install check failed"
say "done: $("$WRAPPER" version)"
echo
if [ "$MODE" = "global" ]; then
  case ":$PATH:" in
    *":$BIN_DIR:"*) say "run: ai-safe start   (inside the repository you want to protect)" ;;
    *) warn "$BIN_DIR is not on your PATH. Add:  export PATH=\"$BIN_DIR:\$PATH\""
       say "then run: ai-safe start   (inside the repository you want to protect)" ;;
  esac
else
  say "run: $WRAPPER start   (from $PROJECT)"
  say "tip: alias ai-safe=\"$WRAPPER\""
fi
say "ai-safe never commits, pushes or launches an AI agent on its own. Run 'ai-safe integrate' yourself."
