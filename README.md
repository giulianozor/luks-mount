# lmount

Mount and unmount devices and file-backed containers. Automatically detects LUKS encryption — when present, `luksOpen`/`luksClose` are used; plain sources are mounted directly.

## Requirements

- Linux with `cryptsetup` and `mount` installed
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
lmount <source>
lmount -k <keyfile> -m <mountpoint> <source>
```

- `<source>` — path to a block device (e.g. `sda1` or `/dev/sda1`) or a file-backed container.
- `-k` / `--key` — optional path to a LUKS key file (ignored for non-LUKS sources).
- `-m` / `--mount` — mount point (default: `~/<source-basename>`).

Source resolution: if `<source>` does not exist as a file or directory, `/dev/<source>` is tried. The first existing path wins; if neither exists, the original value is passed through to `mount`.

Encryption is auto-detected via `cryptsetup isLuks`. LUKS sources are opened with `luksOpen` before mounting; plain sources are mounted directly.

### Unmount

```sh
lmount -u <source>
```

Unmounts all mount points backed by the source (or `/dev/mapper/<source>` for LUKS), removes the mount directories, and closes the LUKS mapping if present.

## Examples

```sh
# Mount a LUKS-encrypted device
lmount sda1

# Mount a plain device
lmount /dev/sdb1

# Mount with a key file and custom mount point
lmount -k /etc/luks/key -m /mnt/data sdb2

# Mount a file-backed container (LUKS or plain)
lmount /path/to/container.img

# Unmount and close
lmount -u sda1
```

## Development

```sh
make build   # compile
make test    # run tests
make clean   # remove binary
```
