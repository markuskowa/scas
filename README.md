[![Build Pakage](https://github.com/markuskowa/scas/actions/workflows/nix-build.yml/badge.svg)](https://github.com/markuskowa/scas/actions/workflows/nix-build.yml)

# SCAS - Simple Content Addressed Storage

Filesystem based content addressed storage with garbage collection written in C++.

## Concepts

* Files are identified by its SHA256 hash
* Files are store under /data with a base64 encoded name in read-only mode
* Garbage collection protection is done via symlinks
* GC root are kept in gc-roots/<hash>/

## command line utility, scas

Usage:

```
- Create a new store directory structure:
  scas init <new_store_directory>

- Add file to the store:
  scas add -d store directory [-s] [file(s) to add]

  -d directory  specify store path
  -s            move file to store and create gc protected symlink
  If no file name is give input from stdin is read

- Create link point to content:
  scas link -d store directory [-s] <linkname> <hash>
  -d directory  specify store path
  -s            create gc protected symlink

- Run garbage collection:
  scas gc <store directory>
```

