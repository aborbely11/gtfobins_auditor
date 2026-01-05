#!/usr/bin/env bash
set -euo pipefail

# ----------------------------
# GTFOBins Auditor (SAFE) Installer
# Supports: Ubuntu/Debian, RHEL/CentOS/Rocky/Alma/Fedora, Gentoo, Arch, SUSE, Alpine, and more.
# ----------------------------

APP_NAME="gtfobins-auditor"
DEFAULT_PREFIX="/opt/${APP_NAME}"
GTFO_REPO_URL="https://github.com/GTFOBins/GTFOBins.github.io.git"
GTFO_DIR_NAME="GTFOBins.github.io"
SCRIPT_NAME="gtfobins_auditor.py"

# If your gtfobins_auditor.py is in the same directory as install.sh, it will be copied.
INSTALL_VENV="${INSTALL_VENV:-1}"     # 1 = create venv, 0 = skip
CLONE_GTFObins="${CLONE_GTFObins:-1}" # 1 = clone GTFOBins repo, 0 = skip
PREFIX="${PREFIX:-$DEFAULT_PREFIX}"

log()  { echo -e "[+] $*"; }
warn() { echo -e "[!] $*" >&2; }
die()  { echo -e "[x] $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_root_or_sudo() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    SUDO=""
    return
  fi

  if need_cmd sudo; then
    SUDO="sudo"
    return
  fi

  die "This installer needs root privileges (run as root or install/use sudo)."
}

detect_pkg_manager() {
  # Prefer explicit package managers
  if need_cmd apt-get; then echo "apt"; return; fi
  if need_cmd dnf; then echo "dnf"; return; fi
  if need_cmd yum; then echo "yum"; return; fi
  if need_cmd emerge; then echo "emerge"; return; fi
  if need_cmd pacman; then echo "pacman"; return; fi
  if need_cmd zypper; then echo "zypper"; return; fi
  if need_cmd apk; then echo "apk"; return; fi
  if need_cmd xbps-install; then echo "xbps"; return; fi
  if need_cmd pkg; then echo "pkg"; return; fi

  # Fallback: try /etc/os-release hint (best-effort)
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release || true
    case "${ID:-}" in
      debian|ubuntu|linuxmint|pop) echo "apt"; return ;;
      rhel|centos|rocky|almalinux|fedora) echo "dnf"; return ;;
      gentoo) echo "emerge"; return ;;
      arch|manjaro) echo "pacman"; return ;;
      opensuse*|sles) echo "zypper"; return ;;
      alpine) echo "apk"; return ;;
      void) echo "xbps"; return ;;
      freebsd) echo "pkg"; return ;;
    esac
  fi

  echo "unknown"
}

install_packages() {
  local pm="$1"
  log "Detected package manager: ${pm}"

  case "$pm" in
    apt)
      $SUDO apt-get update -y
      # getcap is in libcap2-bin on Debian/Ubuntu
      $SUDO apt-get install -y \
        python3 python3-venv git findutils sudo libcap2-bin ca-certificates
      ;;
    dnf)
      $SUDO dnf -y install \
        python3 python3-virtualenv git findutils sudo libcap ca-certificates
      ;;
    yum)
      $SUDO yum -y install \
        python3 git findutils sudo libcap ca-certificates || true
      # Some older RHEL/CentOS may not have python3-venv packaged the same way
      warn "If python3 venv is missing, you may need: yum install python3-virtualenv or use system python."
      ;;
    emerge)
      # Gentoo: packages are typically already present in base, but ensure:
      $SUDO emerge --sync || true
      $SUDO emerge -av dev-vcs/git dev-lang/python sys-apps/findutils sys-libs/libcap app-admin/sudo || true
      ;;
    pacman)
      $SUDO pacman -Sy --noconfirm \
        python git findutils sudo libcap ca-certificates
      ;;
    zypper)
      $SUDO zypper --non-interactive refresh
      $SUDO zypper --non-interactive install \
        python3 python3-virtualenv git findutils sudo libcap-progs ca-certificates
      ;;
    apk)
      $SUDO apk update
      # Alpine: getcap provided by libcap / libcap-utils depending on repo
      $SUDO apk add --no-cache \
        python3 py3-virtualenv git findutils sudo libcap ca-certificates
      ;;
    xbps)
      $SUDO xbps-install -Sy \
        python3 python3-virtualenv git findutils sudo libcap ca-certificates
      ;;
    pkg)
      # FreeBSD best-effort
      $SUDO pkg update -f
      $SUDO pkg install -y python3 git findutils sudo libcap || true
      warn "FreeBSD support is best-effort; GTFOBins is Linux-focused."
      ;;
    *)
      die "Unsupported/unknown package manager. Install manually: python3, git, findutils, (optional) sudo, and getcap (libcap)."
      ;;
  esac
}

create_dirs() {
  log "Creating install directory: ${PREFIX}"
  $SUDO mkdir -p "${PREFIX}"
  $SUDO chown -R "${USER:-root}":"${USER:-root}" "${PREFIX}" 2>/dev/null || true
}

install_script() {
  local src_dir
  src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  if [[ -f "${src_dir}/${SCRIPT_NAME}" ]]; then
    log "Copying ${SCRIPT_NAME} into ${PREFIX}"
    $SUDO cp -f "${src_dir}/${SCRIPT_NAME}" "${PREFIX}/${SCRIPT_NAME}"
  else
    warn "Could not find ${SCRIPT_NAME} in the same folder as install.sh."
    warn "Place ${SCRIPT_NAME} next to install.sh or copy it manually to: ${PREFIX}/"
  fi
}

setup_venv() {
  if [[ "${INSTALL_VENV}" != "1" ]]; then
    warn "Skipping venv creation (INSTALL_VENV=0)."
    return
  fi

  if ! need_cmd python3; then
    die "python3 not found after installation."
  fi

  log "Creating Python venv at ${PREFIX}/.venv"
  python3 -m venv "${PREFIX}/.venv" || {
    warn "Failed to create venv. Continuing without venv."
    return
  }

  # No pip dependencies required, but keep pip updated if possible
  if [[ -x "${PREFIX}/.venv/bin/python" ]]; then
    "${PREFIX}/.venv/bin/python" -m pip install --upgrade pip >/dev/null 2>&1 || true
  fi
}

clone_gtfobins() {
  if [[ "${CLONE_GTFObins}" != "1" ]]; then
    warn "Skipping GTFOBins clone (CLONE_GTFObins=0)."
    return
  fi

  if ! need_cmd git; then
    die "git not found after installation."
  fi

  local dst="${PREFIX}/${GTFO_DIR_NAME}"
  if [[ -d "${dst}/.git" ]]; then
    log "GTFOBins repo already exists. Pulling latest updates..."
    (cd "${dst}" && git pull --ff-only) || warn "Could not pull latest GTFOBins updates."
  else
    log "Cloning GTFOBins repo into ${dst}"
    git clone "${GTFO_REPO_URL}" "${dst}"
  fi
}

print_next_steps() {
  echo
  log "Installation complete."
  echo
  echo "Location: ${PREFIX}"
  echo "  - Script: ${PREFIX}/${SCRIPT_NAME}"
  echo "  - GTFOBins repo: ${PREFIX}/${GTFO_DIR_NAME}"
  echo

  if [[ -d "${PREFIX}/.venv" ]]; then
    echo "Run using venv (recommended):"
    echo "  ${PREFIX}/.venv/bin/python ${PREFIX}/${SCRIPT_NAME} --gtfopath ${PREFIX}/${GTFO_DIR_NAME} --scan-suid --sudo-check --export report.json"
  else
    echo "Run using system python:"
    echo "  python3 ${PREFIX}/${SCRIPT_NAME} --gtfopath ${PREFIX}/${GTFO_DIR_NAME} --scan-suid --sudo-check --export report.json"
  fi

  echo
  echo "Tip: You can customize behavior via env vars:"
  echo "  INSTALL_VENV=0   (skip venv)"
  echo "  CLONE_GTFObins=0 (skip GTFOBins clone)"
  echo "  PREFIX=/custom/path"
  echo
}

main() {
  require_root_or_sudo

  local pm
  pm="$(detect_pkg_manager)"
  if [[ "$pm" == "unknown" ]]; then
    die "Could not detect a supported package manager."
  fi

  install_packages "$pm"
  create_dirs
  install_script
  setup_venv
  clone_gtfobins
  print_next_steps
}

main "$@"
