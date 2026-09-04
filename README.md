# lmount

Mount, unmount, and create LUKS-encrypted devices and file-backed containers. Automatically detects LUKS encryption — when present, `luksOpen`/`luksClose` are used; plain sources are mounted directly.

## Requirements

This tool is **Linux-only**. It relies on Linux-specific tools and interfaces
(`cryptsetup`, `mount`, `findmnt`, `mkfs.ext4`, `resize2fs`, `fsck.ext4`, `dd`,
`truncate`, `sudo`, and the Device Mapper `/dev/mapper`), none of which are
available or compatible on macOS or Windows.
- `sudo` access without password prompt for the relevant commands
- Go 1.21+ (to build from source)

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
2. Formats it as a LUKS device with `cryptsetup luksFormat` (you will be prompted for a passphrase; the YES confirmation is skipped via `--batch-mode`).
3. Optionally adds a key file to the LUKS slot.
4. Opens the device, creates an `ext4` filesystem (no reserved blocks), and closes it.

Minimum container size is 32M.

- `-c` / `--create` — name of the container file to create.
- `-cs` / `--size` — size with suffix `M` or `G` (e.g. `100M`, `2G`). The block size is chosen by tier to balance speed and waste: ≤1 GiB uses 1–32 MiB blocks, 1–10 GiB uses 256 MiB, 10–100 GiB uses 512 MiB, >100 GiB uses 1024 MiB. The image is allocated to exactly the requested size (a `truncate` extension is used when the size is not a multiple of the tier's block size).
- `-ck` / `--create-key-file` — optional path for a key file. When set, a random key file is generated and added to the LUKS slots.
- `-cks` / `--key-size` — key file size in bytes (default: 512). Ignored if `-ck` is not used.

When `-c` is used, `-s` and `-u` are ignored.

### Expand

```sh
lmount -x <filename> -xs <size> [-k <keyfile>]
```

Expands an existing LUKS-encrypted file-backed container by appending zero-filled space:

1. Grows the backing file by the requested amount (`truncate`), sizing it to exactly the requested amount.
2. Opens the LUKS device (`--key-file` is respected when `-k` is set).
3. Checks and resizes the ext4 filesystem to fill the available space, then checks again.
4. Closes the LUKS device.
5. Prints the old and new file sizes.

The container must already be a LUKS device with an ext4 filesystem.

- `-x` / `--expand` — path to the LUKS container file to expand.
- `-xs` / `--expand-size` — additional size with suffix `M` or `G` (e.g. `100M`, `2G`).
- `-k` / `--key` — optional path to a LUKS key file.

When `-x` is used, `-s`, `-u`, and `-c` are ignored.

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
