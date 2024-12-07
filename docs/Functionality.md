# Functionality

Some of these are still being worked on and marked with `[WIP]`.

- It keeps all `encrypted` data and `master encryption key` in a dedicated directory with files structured on `inodes` (with
  metadata info), files for binary content, and directories with files/directories entries. All data, metadata, and filenames
  are encrypted. It generates unique inodes for new files in a multi-instance run and offline mode.
- The password is collected from CLI and saved in the OS's `keyring` while the app runs. This is because, for security concerns, we
  clear the password from memory on inactivity, and we derive it again from the password just when needed.
- Master encryption key is also encrypted with another key derived from the password. This gives the ability to change
  the
  password without re-encrypting all data, we just `re-encrypt` the `master key`.
- Files are `encrypted` in `chunks` of `256KB`, so when making a change, we just re-encrypt that chunks.
- `Fast seek` on read and write, so if you're watching a movie, you can seek any position, and that would be instant.
  This is because we can seek a particular chunk.
- The encryption key is `zeroize` in the mem when disposing and idle. Also, it's `mlock`ed while used to prevent being moved to swap. It's
  also `mprotect`ed while not in use.
- `[WIP]` Ensure file integrity by saving each change to WAL, so for crashes or power loss, we apply the pending
changes at the next start. This makes the write operations atomic.
- Multiple writes in parallel to the same file, ideal for torrent-like applications.