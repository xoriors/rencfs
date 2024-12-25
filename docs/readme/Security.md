# ⚠️ Security Warning: Hazmat!

- **Phantom reads**: Reading older content from a file is not possible. Data is written with WAL and periodically
  flushed to file. This ensures data integrity and maintains change order.
  One problem that may occur is if we do a truncation, we change the content of the file, but the process is killed before
  we write the metadata with the new file size. In this case, the next time we mount the system, we will still see the old
files. However, the content of the file could be bigger, and we read until the old size offset, so we would not
  pick up
  the new zeros bytes are written on truncating by increasing the size. If content is smaller, the read would stop and
  end-of-file of the actual content, so this would not be such a big issue
- **What kind of metadata does it leak**: None, we encrypt filename, content, and metadata and we hide file count, size, and all-time fields
- It's always recommended to use encrypted disks for at least your sensitive data; this project is not a replacement for
  that
- To reduce the risk of the encryption key being exposed from memory, it's recommended to disable memory dumps on the
  OS level. Please see [here](https://www.cyberciti.biz/faq/disable-core-dumps-in-linux-with-systemd-sysctl/) how to do
  it on Linux
- **Cold boot attacks**: to reduce the risk of this, we keep the encryption key in memory just as long as we really
  need it to encrypt/decrypt data, and we are zeroing it after that. We also remove it from memory after a period of
  inactivity
- Please note that no security expert audited this project. It's built with security in mind and tries to
  follow all the best practices, but it's not guaranteed to be secure
- **Also, please back up your data; the project is still in development, and there might be bugs that can lead to data
  loss**