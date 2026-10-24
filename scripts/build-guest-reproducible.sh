#!/usr/bin/env bash
#
# Reproducible build of the dash-username SP1 guest ELF, the one whose vkey is pinned in
# DashPlatformVerifier on Ethereum mainnet.
#
# `cargo prove build` without --docker embeds the build machine's paths in the ELF: cargo derives
# each path package's -Cmetadata from its absolute source path, which changes symbol names, the
# length of .strtab, and the section-header offset in the ELF header. The guest's first PT_LOAD
# segment starts at file offset 0, so that header is part of the loaded program and the vkey moves
# with it. `cargo prove build --docker` mounts the repository at a fixed container path
# (/root/program) with a fixed /root/.cargo, so the ELF is the same wherever the checkout lives.
#
# `--workspace-directory` is part of the pin. It decides where the mount root lands, and so the
# in-container path of every crate. This script always passes the repository root, which puts the
# program at /root/program/zkvm/dash/program. That is the layout the mainnet ELF was built with.
#
# USAGE
#   scripts/build-guest-reproducible.sh dash-username
#   scripts/build-guest-reproducible.sh dash-username --expect <sha256>
#   scripts/build-guest-reproducible.sh dash-username --twice    # also rebuild from a second path
#   scripts/build-guest-reproducible.sh dash-username --plan     # print the setup, build nothing
#   scripts/build-guest-reproducible.sh --list
#
# `--twice` copies the repository to a second, differently named path, rebuilds there, and
# requires the two ELFs to be byte-identical. The source label printed next to the sha256 is
# provenance only and never enters the build.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Pins. Change these only deliberately — every one of them moves every vkey.
# ---------------------------------------------------------------------------
SP1_TAG="v6.8.1"
# A ghcr tag can be repointed, so the local image is verified against this
# digest before every build.
SP1_IMAGE_DIGEST="sha256:e672d7160039916f40a6a4c2ea4cb0c8cd3dab120fdb24d08560d386ad8f59c2"
SP1_IMAGE="ghcr.io/succinctlabs/sp1:${SP1_TAG}"
CARGO_PROVE="${CARGO_PROVE:-$HOME/.sp1/bin/cargo-prove}"
REPRO_TMP=""   # scratch checkout for --twice; cleaned by the EXIT trap

# ---------------------------------------------------------------------------
# Guest registry: <short name> <program dir, relative to repo root> <elf name>
# ---------------------------------------------------------------------------
read -r -d '' GUESTS <<'EOF' || true
dash-username zkvm/dash/program                              dash-username-program
EOF

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[36m==>\033[0m %s\n' "$*" >&2; }

list_guests() {
  printf '%-14s %-48s %s\n' NAME PROGRAM-DIR ELF
  printf '%s\n' "$GUESTS"
}

lookup() {  # $1 = short name; echoes "<dir> <elf>"
  local name="$1" n d e
  while read -r n d e; do
    [ -z "${n:-}" ] && continue
    if [ "$n" = "$name" ]; then printf '%s %s\n' "$d" "$e"; return 0; fi
  done <<< "$GUESTS"
  return 1
}

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

# ---------------------------------------------------------------------------
# Repo root, without requiring git: this script's parent directory, checked for
# the layout below. When git can answer, its answer must match, because
# `--workspace-directory` is part of the pin.
# ---------------------------------------------------------------------------
repo_root() {
  local here root
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  root="$(cd "$here/.." && pwd -P)"
  [ -d "$root/zkvm/dash/program" ] && [ -f "$root/zkvm/dash/Cargo.toml" ] ||
    die "$root does not look like this repository (want zkvm/dash/) — \
this script must stay at <root>/scripts/"
  if command -v git >/dev/null && git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1; then
    local gitroot
    gitroot="$(cd "$(git -C "$root" rev-parse --show-toplevel)" && pwd -P)"
    [ "$gitroot" = "$root" ] ||
      die "git says the repo root is $gitroot but this script sits under $root — \
--workspace-directory is part of the vkey, so refusing to guess"
  fi
  printf '%s\n' "$root"
}

# ---------------------------------------------------------------------------
# The source label. Provenance only — it never enters the build, and the ELF is
# byte-identical whatever this says. Explicit UNKNOWN over a fabricated value.
# ---------------------------------------------------------------------------
source_label() {  # $1 = repo root, $2 = --source-label override (may be empty)
  local root="$1" override="${2:-}"
  if [ -n "$override" ]; then printf '%s\n' "$override"; return; fi
  if command -v git >/dev/null && git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1; then
    local sha dirty=""
    sha="$(git -C "$root" rev-parse HEAD 2>/dev/null || true)"
    if [ -n "$sha" ]; then
      git -C "$root" diff --quiet HEAD 2>/dev/null || dirty="-dirty"
      printf 'git:%s%s\n' "$sha" "$dirty"; return
    fi
  fi
  printf 'UNKNOWN-SOURCE-LABEL\n'
}

# ---------------------------------------------------------------------------
# Copy the tree for leg B. With git, tracked files only, so an untracked stray
# cannot silently change the ELF. Without git there is no such distinction —
# everything present IS the source — so copy it minus build output, and say so.
# ---------------------------------------------------------------------------
copy_tree() {  # $1 = src root, $2 = dst root
  local src="$1" dst="$2"
  mkdir -p "$dst"
  if command -v git >/dev/null && git -C "$src" rev-parse --show-toplevel >/dev/null 2>&1; then
    ( cd "$src" && git ls-files -z ) | ( cd "$src" && rsync -a --files-from=- --from0 ./ "$dst/" )
    ( cd "$dst" && git init -q . && git add -A && git -c user.email=r@r -c user.name=r commit -qm repro )
  else
    note "no git index here: leg B copies the WORKING TREE minus build output."
    note "in an archive checkout that IS the source; there are no untracked strays."
    rsync -a --exclude '.git/' --exclude 'target/' --exclude 'elf-compilation/' \
      --exclude 'node_modules/' "$src/" "$dst/"
  fi
}

# ---------------------------------------------------------------------------
# Build one guest out of an arbitrary repo root. Echoes the ELF path.
# ---------------------------------------------------------------------------
build_at() {  # $1 = repo root, $2 = program dir (rel), $3 = elf name
  local root="$1" pdir="$2" elf="$3"
  ( cd "$root/$pdir" && "$CARGO_PROVE" prove build \
      --docker \
      --tag "$SP1_TAG" \
      --locked \
      --workspace-directory "$root" ) >&2
  # sp1-build puts --docker output under <guest target>/elf-compilation/docker/...
  local out
  out="$(find "$root" -path "*/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/$elf" \
         -type f 2>/dev/null | head -1)"
  [ -n "$out" ] || die "docker build produced no ELF named '$elf' under $root"
  printf '%s\n' "$out"
}

# ---------------------------------------------------------------------------
main() {
  [ "${1:-}" = "--list" ] && { list_guests; exit 0; }
  local guest="${1:-}"
  [ -n "$guest" ] || die "usage: $0 <guest>|--list [--expect <sha256>] [--twice]"
  shift

  local expect="" twice=0 plan=0 label_override=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --expect) expect="${2:-}"; shift 2 ;;
      --twice)  twice=1; shift ;;
      --plan)   plan=1; shift ;;
      --source-label) label_override="${2:-}"; shift 2 ;;
      *) die "unknown flag: $1" ;;
    esac
  done

  local dir elf
  read -r dir elf < <(lookup "$guest") || die "unknown guest '$guest' (try --list)"

  local root
  root="$(repo_root)"
  [ -d "$root/$dir" ] || die "guest dir missing: $root/$dir"

  local label
  label="$(source_label "$root" "$label_override")"

  if [ "$plan" = "1" ]; then
    printf '%s\n' "----------------------------------------------------------------"
    printf 'PLAN ONLY — nothing is built, no docker is contacted.\n'
    printf 'guest        %s\n' "$guest"
    printf 'repo root    %s\n' "$root"
    printf 'program dir  %s\n' "$root/$dir"
    printf 'elf name     %s\n' "$elf"
    printf 'image        %s @ %s\n' "$SP1_IMAGE" "$SP1_IMAGE_DIGEST"
    printf 'in-container /root/program/%s\n' "$dir"
    printf 'source       %s\n' "$label"
    printf '%s\n' "----------------------------------------------------------------"
    exit 0
  fi

  command -v docker >/dev/null || die "docker not installed — a non-docker build MUST NOT be pinned"
  docker info >/dev/null 2>&1 || die "docker daemon not running — start Docker Desktop"

  # Verify the image is the pinned digest, pulling if absent.
  docker image inspect "$SP1_IMAGE" >/dev/null 2>&1 \
    || docker pull --platform linux/amd64 "$SP1_IMAGE" >&2
  local have
  have="$(docker image inspect --format '{{index .RepoDigests 0}}' "$SP1_IMAGE" 2>/dev/null | sed 's/.*@//')"
  if [ -n "$have" ] && [ "$have" != "$SP1_IMAGE_DIGEST" ]; then
    die "SP1 image digest drift: have $have, pinned $SP1_IMAGE_DIGEST — do not pin an ELF from this"
  fi

  note "guest        $guest ($dir)"
  note "repo root    $root"
  note "source       $label   (provenance only — never enters the build)"
  note "image        $SP1_IMAGE @ $SP1_IMAGE_DIGEST"
  note "in-container /root/program/$dir   (fixed — this is what makes it reproducible)"

  local elf_a; elf_a="$(build_at "$root" "$dir" "$elf")"
  local sha_a; sha_a="$(sha256_of "$elf_a")"
  local sz_a;  sz_a="$(wc -c < "$elf_a" | tr -d ' ')"

  printf '\n%s\n' "----------------------------------------------------------------"
  printf 'guest      %s\n' "$guest"
  printf 'source     %s\n' "$label"
  printf 'elf        %s\n' "$elf_a"
  printf 'bytes      %s\n' "$sz_a"
  printf 'sha256     %s\n' "$sha_a"
  printf '%s\n' "----------------------------------------------------------------"

  if [ "$twice" = "1" ]; then
    # Second leg at a deliberately different host path. Byte-identity across the
    # two is the whole claim; a mismatch means DO NOT PIN.
    REPRO_TMP="$(mktemp -d "${TMPDIR:-/tmp}/dash-repro-XXXXXXXXXXXXXXXXXXXX")"
    trap 'rm -rf "${REPRO_TMP:-}"' EXIT
    local root_b="$REPRO_TMP/a-deliberately-differently-named-checkout"
    note "second leg   $root_b"
    copy_tree "$root" "$root_b"
    local elf_b; elf_b="$(build_at "$root_b" "$dir" "$elf")"
    local sha_b; sha_b="$(sha256_of "$elf_b")"
    local sz_b;  sz_b="$(wc -c < "$elf_b" | tr -d ' ')"
    printf 'leg B      %s bytes  sha256 %s\n' "$sz_b" "$sha_b"
    if [ "$sha_a" = "$sha_b" ]; then
      printf '\033[32mREPRODUCIBLE\033[0m — byte-identical across two host checkout paths.\n'
    else
      printf '\033[31mNOT REPRODUCIBLE\033[0m — legs differ. DO NOT PIN.\n'; exit 1
    fi
  fi

  if [ -n "$expect" ]; then
    if [ "$sha_a" = "$expect" ]; then
      printf '\033[32mMATCHES\033[0m expected sha256.\n'
    else
      printf '\033[31mDRIFT\033[0m — expected %s, got %s\n' "$expect" "$sha_a"; exit 1
    fi
  fi
}

main "$@"
