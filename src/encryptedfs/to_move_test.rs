// #[test]
// fn test_rename() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_rename") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//
//         // file to existing file in same directory
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr(FileType::RegularFile), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &file_2, create_attr(FileType::RegularFile), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &file_2).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_2), true);
//         let new_attr = fs.find_by_name(new_parent, &file_2).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_2.expose_secret()).count(), 1);
//
//         // directory to existing directory in same directory
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_1, create_attr(FileType::Directory), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &dir_2, create_attr(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_2).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_2), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_2).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_2.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // file to existing file in another directory
//         let new_parent = new_parent_attr.ino;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr(FileType::RegularFile), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &file_1, create_attr(FileType::RegularFile), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &file_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_1), true);
//         let new_attr = fs.find_by_name(new_parent, &file_1).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 1);
//
//         // directory to existing directory in another directory
//         let new_parent = new_parent_attr.ino;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_1, create_attr(FileType::Directory), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &dir_1, create_attr(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_1), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_1).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // overwriting directory with file
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr(FileType::RegularFile), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &dir_1, create_attr(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &dir_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_1), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_1).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 1);
//
//         // overwriting file with directory
//         let new_parent = ROOT_INODE;
//         let dir_3 = SecretString::from_str("dir-3").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_3, create_attr(FileType::Directory), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &file_1, create_attr(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_3, new_parent, &file_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_3), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_1), true);
//         let new_attr = fs.find_by_name(new_parent, &file_1).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_3.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // overwriting non-empty directory
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_3, create_attr(FileType::Directory), false, false).unwrap();
//         let _attr_2 = new_parent_attr;
//         let name_2 = dir_new_parent;
//         assert!(matches!(fs.rename(ROOT_INODE, &dir_3, new_parent, &name_2), Err(FsError::NotEmpty)));
//         assert_eq!(fs.exists_by_name(ROOT_INODE, &dir_3), true);
//         assert_eq!(fs.exists_by_name(new_parent, &name_2), true);
//         let attr_3 = fs.find_by_name(ROOT_INODE, &dir_3).unwrap().unwrap();
//         assert_eq!(fs.is_dir(attr_3.ino), true);
//         let attr_2 = fs.find_by_name(new_parent, &name_2).unwrap().unwrap();
//         assert_eq!(fs.is_dir(attr_2.ino), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_3).unwrap().unwrap();
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         let new_attr_2 = fs.find_by_name(new_parent, &name_2).unwrap().unwrap();
//         assert_eq!(new_attr_2.ino, attr_2.ino);
//         assert_eq!(new_attr_2.kind, attr_2.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_3.expose_secret()).count(), 1);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == name_2.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr_2.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr_2.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr_2.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // same file in same directory
//         let new_parent = ROOT_INODE;
//         let file_3 = SecretString::from_str("file-3").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_3, create_attr(FileType::RegularFile), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_3, new_parent, &file_3).unwrap();
//         assert_eq!(fs.exists_by_name(new_parent, &file_3), true);
//         let new_attr = fs.find_by_name(new_parent, &file_3).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_3.expose_secret()).count(), 1);
//
//         // same directory in same directory
//         let new_parent = ROOT_INODE;
//         let dir_5 = SecretString::from_str("dir-5").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_5, create_attr(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_5, new_parent, &dir_5).unwrap();
//         assert_eq!(fs.exists_by_name(new_parent, &dir_5), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_5).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_5.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // invalid nodes and name
//         let invalid = SecretString::from_str("invalid").unwrap();
//         assert!(matches!(fs.rename(0, &invalid, 0, &invalid), Err(FsError::InodeNotFound)));
//         let existing_file = SecretString::from_str("existing-file").unwrap();
//         let (_, attr_file) = fs.create_nod(ROOT_INODE, &existing_file, create_attr(FileType::RegularFile), false, false).unwrap();
//         assert!(matches!(fs.rename(attr_file.ino, &invalid, 0, &invalid), Err(FsError::InvalidInodeType)));
//         assert!(matches!(fs.rename(ROOT_INODE, &invalid, ROOT_INODE, &invalid), Err(FsError::NotFound(_))));
//         assert!(matches!(fs.rename(ROOT_INODE, &existing_file, 0, &invalid), Err(FsError::InodeNotFound)));
//         assert!(matches!(fs.rename(ROOT_INODE, &existing_file, attr_file.ino, &invalid), Err(FsError::InvalidInodeType)));
//     });
// }
//
// #[test]
// fn test_open() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_open") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         let test_file = SecretString::from_str("test-file").unwrap();
//         let (_fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr(FileType::RegularFile), false, false).unwrap();
//         // single read
//         let fh = fs.open(attr.ino, true, false).unwrap();
//         assert_ne!(fh, 0);
//         // multiple read
//         let fh_2 = fs.open(attr.ino, true, false).unwrap();
//         assert_ne!(fh_2, 0);
//         // write and read
//         let _fh_w = fs.open(attr.ino, false, true).unwrap();
//         // ensure cannot open multiple write
//         assert!(matches!(fs.open(attr.ino, false, true), Err(FsError::AlreadyOpenForWrite)));
//     });
// }
//
// #[allow(dead_code)]
// // #[test]
// fn test_sample() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_sample") }, |setup| {
//         let _fs = setup.fs.as_mut().unwrap();
//     });
// }
