# lmount

Mount, unmount, and create LUKS-encrypted devices and file-backed containers. Automatically detects LUKS encryption — when present, `luksOpen`/`luksClose` are used; plain sources are mounted directly.

## Requirements

This tool is **Linux-only**. It relies on Linux-specific tools and interfaces
(`cryptsetup`, `mount`, `findmnt`, `mkfs.ext4`, `resize2fs`, `fsck.ext4`, `dd`,
`truncate`, `sudo`, and the Device Mapper `/dev/mapper`), none of which are
available or compatible on macOS or Windows.

- `sudo` access, ideally passwordless for the commands below.
- Go 1.21+ (to build from source).

## Recommended sudoers configuration

`lmount` invokes several privileged tools through `sudo`. To run it without
password prompts, install a `sudoers` drop-in (the exact paths vary by
distribution — verify with `command -v`):

```sh
sudo tee /etc/sudoers.d/lmount >/dev/null <<'EOF'
# Non-interactive use of the tools lmount runs with sudo.
# Adjust these to your distribution's actual paths and to a more restrictive
# group if you prefer.
%sudo ALL=(root) NOPASSWD: /usr/bin/cryptsetup, /usr/bin/mount, /usr/bin/umount, /usr/bin/chown, /usr/sbin/mkfs.ext4, /usr/sbin/fsck.ext4, /usr/sbin/resize2fs
EOF
sudo chmod 0440 /etc/sudoers.d/lmount
```

The privileged commands are `cryptsetup` (for `isLuks`, `luksOpen`, and
`luksClose`), `mount`, `umount`, `chown`, `mkfs.ext4`, `fsck.ext4`, and
`resize2fs`. The mount-table probe (`findmnt`) runs unprivileged. Container
creation (`dd`) and sizing (`truncate`) also run as the invoking user and do
not need `sudo`.

> **Security note:** granting passwordless `sudo` for these binaries allows
> anyone with access to your account to run them as root. In particular,
> avoiding the `chown` entry (or restricting it) is recommended on shared
> systems, since `chown` can be used to change ownership of arbitrary files.
> The narrowest rule that still works is to grant only the commands you
> actually use, and to prefer running `lmount` as a dedicated or unprivileged
> user where possible.

## Installation

```sh
make install
```

Or build manually:

```sh
go build -o lmount .
sudo install -m 0755 lmount /usr/local/bin/
```

## Usage

### Mount

```sh
lmount -s <source>
lmount -s <source> -k <keyfile> -m <mountpoint>
```

- `-s` / `--source` — path to a block device (e.g. `sda1` or `/dev/sda1`) or a file-backed container.
- `-k` / `--key` — optional path to a LUKS key file (ignored for non-LUKS sources).
- `-m` / `--mount` — mount point (default: `~/<source-basename>`). If a file already exists at the path, `.mnt` is appended automatically.

Source resolution: if the source path does not exist as a file or directory, `/dev/<source>` is tried. The first existing path wins; if neither exists, the original value is passed through to `mount`.

Encryption is auto-detected via `cryptsetup isLuks`. LUKS sources are opened with `luksOpen` before mounting; plain sources are mounted directly.

### Unmount

```sh
lmount -u <source>
```

Unmounts all mount points backed by the source (or `/dev/mapper/<source>` for LUKS), removes the mount directories, and closes the LUKS mapping if present.

### Create

```sh
lmount -c <name> -cs <size> [-ck <keyfile>] [-cks <key-size>]
```

Creates a LUKS-encrypted file-backed container:

1. Creates the backing file with `dd` (zero-filled, progress shown).
2. Formats it as a LUKS device with `cryptsetup luksFormat --batch-mode` (without `-ck`/`-k` you are prompted for a passphrase; the YES confirmation is skipped via `--batch-mode`).
3. When `-ck`/`-k` is set, the key file is installed as the container's initial key (no passphrase prompt).
4. Opens the device, creates an `ext4` filesystem (no reserved blocks), and closes it.

Minimum container size is 32M.

- `-c` / `--create` — name of the container file to create.
- `-cs` / `--size` — size with suffix `M` or `G` (e.g. `100M`, `2G`). The block size is chosen by tier to balance speed and waste: ≤1 GiB uses 1–32 MiB blocks, 1–10 GiB uses 256 MiB, 10–100 GiB uses 512 MiB, >100 GiB uses 1024 MiB. The image is allocated to exactly the requested size (a `truncate` extension is used when the size is not a multiple of the tier's block size).
- `-ck` / `--create-key-file` — optional path for a key file. When set, a random key file is generated (mode `0600`, owner-only) and installed as the container's initial key.
- `-cks` / `--key-size` — key file size in bytes (default: 512). Only valid when `-ck` is also used.
- `-k` / `--key` — an existing key file to key the container from, instead of `-ck`. `-k` and `-ck` are mutually exclusive.

`-c` cannot be combined with `-s`, `-u`, or `-x` (the operation flags are mutually exclusive).

### Expand

```sh
lmount -x <filename> -xs <size> [-k <keyfile>]
```

Expands an existing LUKS-encrypted file-backed container by appending zero-filled space:

1. Grows the backing file by the requested amount (`truncate`, zero-filled).
2. Opens the LUKS device (`--key-file` is respected when `-k` is set).
3. Checks and resizes the ext4 filesystem to fill the available space, then checks again.
4. Closes the LUKS device. If a step fails while the mapping is open, `lmount` warns so you can close it manually before touching the container.
5. Prints the old and new file sizes.

The container must already be a LUKS device with an ext4 filesystem.

- `-x` / `--expand` — path to the LUKS container file to expand.
- `-xs` / `--expand-size` — additional size with suffix `M` or `G` (e.g. `100M`, `2G`).
- `-k` / `--key` — optional path to a LUKS key file.

`-x` cannot be combined with `-s`, `-u`, or `-c` (the operation flags are mutually exclusive).

### Expand with key file

```sh
lmount -x container.img -xs 500M -k mykeyfile
```

## Examples

```sh
# Mount a LUKS-encrypted device
lmount -s sda1

# Mount a plain device
lmount -s /dev/sdb1

# Mount with a key file and custom mount point
lmount -s sdb2 -k /etc/luks/key -m /mnt/data

# Mount a file-backed container (LUKS or plain)
lmount -s /path/to/container.img

# Unmount and close
lmount -u sda1

# Create a 100 MiB LUKS container
lmount -c mycontainer.img -cs 100M

# Create a 2 GiB LUKS container with a key file
lmount -c mycontainer.img -cs 2G -ck mykeyfile -cks 1024
```

## Development

```sh
make build   # compile
make test    # run tests
make clean   # remove binary
```

### Test Fixtures

```
test/
  test        32 MiB LUKS v2 container (passphrase: 1234)
  test.key    512-byte key file for ./test/test
```

The volume contains a `test` text file with `"test"` inside. Mount with:

```sh
lmount -s test/test -k test/test.key
```
