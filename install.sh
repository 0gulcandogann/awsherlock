#!/usr/bin/env sh
set -eu

case "$(uname -s)" in
  Linux*|Darwin*) ;;
  *) echo "AWSherlock install.sh supports Linux and macOS only." >&2; exit 1 ;;
esac

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_bin=${PYTHON:-python3}
install_root=${AWSHERLOCK_INSTALL_ROOT:-"$HOME/.local/share/awsherlock"}
bin_dir=${AWSHERLOCK_BIN_DIR:-"$HOME/.local/bin"}
venv_dir="$install_root/venv"
command_path="$bin_dir/awsherlock"

printf '%s\n' \
  '⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⣦⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠠⣾⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣤⣤⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⠋⠁⠀⠀⠈⠹⣿⣿⣿⣿⣿⡿⠋⠀⠀⠈⠻⣿⣿⣿⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⣿⣿⣿⣿⠃⠀⠀⠀⣴⣶⡄⢹⣿⣿⣿⣿⠃⢰⣶⡄⠀⠀⣿⣿⣿⠀⠀⠀⠀⠀⠀' \
  '⠀⠀⠀⠀⠀⣿⣿⣿⣿⡆⠀⠀⠀⠹⠿⠁⣸⣿⣿⣿⣿⡀⠘⡿⠃⠀⢀⣿⣿⣿⡆⠀⠀⠀⠀⠀' \
  ''

if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo "Python 3.11 or newer is required. Install python3 and run this script again." >&2
  exit 1
fi

if ! "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required." >&2
  exit 1
fi

if [ -e "$command_path" ] && [ ! -L "$command_path" ]; then
  echo "Refusing to replace existing non-symlink: $command_path" >&2
  exit 1
fi

mkdir -p "$install_root" "$bin_dir"
"$python_bin" -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install "$project_dir"
ln -sfn "$venv_dir/bin/awsherlock" "$command_path"

echo "AWSherlock installed at $command_path"
if case ":${PATH:-}:" in *":$bin_dir:"*) true ;; *) false ;; esac; then
  echo "Run: awsherlock --version"
else
  echo "Add this directory to PATH, then open a new terminal:"
  echo "  export PATH=\"$bin_dir:\$PATH\""
  echo "Run: $command_path --version"
fi
