APEX fixtures for the native payload readers. Each carries `javalib/big.jar` (four
fixture dex files, stored, so it spans more than one block) and `javalib/small.jar`
(one dex, fits inline), plus a non-jar file.

- `erofs.apex`: payload built with `mkfs.erofs -z lz4hc,9` (LZ4, compact indexes).
- `erofs.capex`: the compressed-APEX wrapper (`original_apex` = `erofs.apex`).
- `ext4.apex`: payload built with `mke2fs -t ext4 -d root -O ^has_journal,^resize_inode -b 1024 -I 128 -N 32 img 96`.
