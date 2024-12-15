use std::ffi::OsStr;
use std::path::Component;
use std::time::SystemTime;

use shush_rs::{SecretBox, SecretString};

use crate::crypto::path::*;
use crate::encryptedfs::{CreateFileAttr, FileType, PasswordProvider};
use crate::test_common::{get_fs, run_test, TestSetup};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_path_methods() {
    run_test(
        TestSetup {
            key: "test_path_methods",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            // Test the `new` method
            let path = Path::new("test/path");
            assert_eq!(path.as_os_str(), std::ffi::OsStr::new("test/path"));

            let string = String::from("foo.txt");
            let from_string = Path::new(&string);
            let from_path = Path::new(&from_string);
            assert_eq!(from_string, from_path);

            // Test the `as_os_str` method
            let os_str = Path::new("foo.txt");
            let os_str = os_str.as_os_str();
            assert_eq!(os_str, std::ffi::OsStr::new("foo.txt"));

            // Test the `as_mut_os_str` method
            let mut path = PathBuf::from("Foo.TXT");
            assert_ne!(path, Path::new("foo.txt"));

            path.as_mut_os_str().make_ascii_lowercase();
            assert_eq!(path, Path::new("foo.txt"));

            // Test the `to_str` method
            let path = Path::new("foo.txt");
            assert_eq!(path.to_str(), Some("foo.txt"));

            // Test the `to_str` method
            let path = Path::new("foo.txt");
            assert_eq!(path.to_string_lossy(), "foo.txt");

            // Test the `to_path_buf` method
            let path_buf = Path::new("foo.txt").to_path_buf();
            assert_eq!(path_buf, PathBuf::from("foo.txt"));

            // Test the `is_absolute` method
            assert!(!Path::new("foo.txt").is_absolute());

            // Test the `is_relative` method
            assert!(Path::new("foo.txt").is_relative());

            // Test the `has_root` method
            assert!(Path::new("/etc/passwd").has_root());

            // Test the `parent` method
            let path = Path::new("/foo/bar");
            let parent = path.parent().unwrap();
            assert_eq!(parent, Path::new("/foo"));

            let grand_parent = parent.parent().unwrap();
            assert_eq!(grand_parent, Path::new("/"));
            assert_eq!(grand_parent.parent(), None);

            let relative_path = Path::new("foo/bar");
            let parent = relative_path.parent();
            assert_eq!(parent, Some(Path::new("foo")));
            let grand_parent = parent.and_then(|p| p.parent());
            assert_eq!(grand_parent, Some(Path::new("")));
            let great_grand_parent = grand_parent.and_then(|p| p.parent());
            assert_eq!(great_grand_parent, None);

            // Test the `ancestors` method
            let ancestors = Path::new("/foo/bar");
            let mut ancestors = ancestors.ancestors();
            assert_eq!(ancestors.next(), Some(Path::new("/foo/bar")));
            assert_eq!(ancestors.next(), Some(Path::new("/foo")));
            assert_eq!(ancestors.next(), Some(Path::new("/")));
            assert_eq!(ancestors.next(), None);

            let ancestors = Path::new("../foo/bar");
            let mut ancestors = ancestors.ancestors();
            assert_eq!(ancestors.next(), Some(Path::new("../foo/bar")));
            assert_eq!(ancestors.next(), Some(Path::new("../foo")));
            assert_eq!(ancestors.next(), Some(Path::new("..")));
            assert_eq!(ancestors.next(), Some(Path::new("")));
            assert_eq!(ancestors.next(), None);

            // Test the `file_name` method
            assert_eq!(Some(OsStr::new("bin")), Path::new("/usr/bin/").file_name());
            assert_eq!(
                Some(OsStr::new("foo.txt")),
                Path::new("tmp/foo.txt").file_name()
            );
            assert_eq!(
                Some(OsStr::new("foo.txt")),
                Path::new("foo.txt/.").file_name()
            );
            assert_eq!(
                Some(OsStr::new("foo.txt")),
                Path::new("foo.txt/.//").file_name()
            );
            assert_eq!(None, Path::new("foo.txt/..").file_name());
            assert_eq!(None, Path::new("/").file_name());

            // Test the `strip_prefix` method
            let path = Path::new("/test/haha/foo.txt");
            assert_eq!(path.strip_prefix("/"), Ok(Path::new("test/haha/foo.txt")));
            assert_eq!(path.strip_prefix("/test"), Ok(Path::new("haha/foo.txt")));
            assert_eq!(path.strip_prefix("/test/"), Ok(Path::new("haha/foo.txt")));
            assert_eq!(path.strip_prefix("/test/haha/foo.txt"), Ok(Path::new("")));
            assert_eq!(path.strip_prefix("/test/haha/foo.txt/"), Ok(Path::new("")));

            assert!(path.strip_prefix("test").is_err());
            assert!(path.strip_prefix("/haha").is_err());

            let prefix = PathBuf::from("/test/");
            assert_eq!(path.strip_prefix(prefix), Ok(Path::new("haha/foo.txt")));

            // Test the `starts_with` method
            let path = Path::new("/etc/passwd");

            assert!(path.starts_with("/etc"));
            assert!(path.starts_with("/etc/"));
            assert!(path.starts_with("/etc/passwd"));
            assert!(path.starts_with("/etc/passwd/")); // extra slash is okay
            assert!(path.starts_with("/etc/passwd///")); // multiple extra slashes are okay

            assert!(!path.starts_with("/e"));
            assert!(!path.starts_with("/etc/passwd.txt"));

            assert!(!Path::new("/etc/foo.rs").starts_with("/etc/foo"));

            // Test the `ends_with` method
            let path = Path::new("/etc/resolv.conf");

            assert!(path.ends_with("resolv.conf"));
            assert!(path.ends_with("etc/resolv.conf"));
            assert!(path.ends_with("/etc/resolv.conf"));

            assert!(!path.ends_with("/resolv.conf"));
            assert!(!path.ends_with("conf"));

            // Test the `file_stem` method
            assert_eq!("foo", Path::new("foo.rs").file_stem().unwrap());
            assert_eq!("foo.tar", Path::new("foo.tar.gz").file_stem().unwrap());

            // Test the `extension` method
            assert_eq!("rs", Path::new("foo.rs").extension().unwrap());
            assert_eq!("gz", Path::new("foo.tar.gz").extension().unwrap());

            // Test the `join` method
            assert_eq!(
                Path::new("/etc").join("passwd"),
                PathBuf::from("/etc/passwd")
            );
            assert_eq!(Path::new("/etc").join("/bin/sh"), PathBuf::from("/bin/sh"));

            // Test the `with_file_name` method
            let path = Path::new("/tmp/foo.png");
            assert_eq!(path.with_file_name("bar"), PathBuf::from("/tmp/bar"));
            assert_eq!(
                path.with_file_name("bar.txt"),
                PathBuf::from("/tmp/bar.txt")
            );

            let path = Path::new("/tmp");
            assert_eq!(path.with_file_name("var"), PathBuf::from("/var"));

            // Test the `with_extension` method
            let path = Path::new("foo.rs");
            assert_eq!(path.with_extension("txt"), PathBuf::from("foo.txt"));

            let path = Path::new("foo.tar.gz");
            assert_eq!(path.with_extension(""), PathBuf::from("foo.tar"));
            assert_eq!(path.with_extension("xz"), PathBuf::from("foo.tar.xz"));
            assert_eq!(
                path.with_extension("").with_extension("txt"),
                PathBuf::from("foo.txt")
            );

            // Test the `components` method
            let mut components = Path::new("/tmp/foo.txt").components();

            assert_eq!(components.next(), Some(Component::RootDir));
            assert_eq!(
                components.next(),
                Some(Component::Normal(OsStr::new("tmp")))
            );
            assert_eq!(
                components.next(),
                Some(Component::Normal(OsStr::new("foo.txt")))
            );
            assert_eq!(components.next(), None);

            // Test the `iter` method
            let mut it = Path::new("/tmp/foo.txt").iter();
            assert_eq!(
                it.next(),
                Some(OsStr::new(&std::path::MAIN_SEPARATOR.to_string()))
            );
            assert_eq!(it.next(), Some(OsStr::new("tmp")));
            assert_eq!(it.next(), Some(OsStr::new("foo.txt")));
            assert_eq!(it.next(), None);

            // Test the `display` method
            let path = Path::new("/spirited/away.rs");
            let expected_display = std::path::Path::new("/spirited/away.rs")
                .display()
                .to_string();
            let actual_display = path.display().to_string();

            assert_eq!(expected_display, actual_display);

            // Test the `metadata` method
            let mock_file = Path::new("mock_file");
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(mock_file)
                .await;
            let mock_metadata = mock_file.metadata().unwrap();

            // Test the timestamps
            let created = mock_metadata.created().unwrap();
            let modified = mock_metadata.modified().unwrap();
            let accessed = mock_metadata.accessed().unwrap();

            assert!(created <= modified, "created should be <= modified");
            assert!(modified <= accessed, "modified should be <= accessed");

            let now = std::time::SystemTime::now();

            assert!(
                created <= now,
                "created timestamp should not be in the future"
            );
            assert!(
                modified <= now,
                "modified timestamp should not be in the future"
            );
            assert!(
                accessed <= now,
                "accessed timestamp should not be in the future"
            );

            assert_ne!(
                created
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                0
            );
            assert_ne!(
                modified
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                0
            );
            assert_ne!(
                accessed
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                0
            );

            let now = std::time::SystemTime::now();
            let epsilon = std::time::Duration::from_secs(5);
            let metadata = mock_file.metadata().unwrap();
            let accessed = metadata.accessed().unwrap();

            assert!(
                accessed >= now - epsilon && accessed <= now + epsilon,
                "accessed timestamp is not within expected range"
            );

            // Test the `file_type` field
            assert_eq!(
                mock_metadata.file_type(),
                crate::encryptedfs::FileType::RegularFile
            );

            // Test the `len` field
            assert_eq!(mock_metadata.len(), 0);

            // Test the `read_link` method
            // ???

            // Test the `read_dir` method
            // ???

            // Test the `exists` method
            assert!(!Path::new("does_not_exist.txt").exists());

            let name_dir_foo = SecretBox::from_str("foo").unwrap();
            let name_dir_test = SecretBox::from_str("test").unwrap();
            let name_file_bar = SecretBox::from_str("bar.rs").unwrap();

            let dir_foo = fs
                .create(1, &name_dir_foo, dir_attr(), true, true)
                .await
                .unwrap();
            let dir_foo_ino = fs
                .find_by_name(1, &name_dir_foo)
                .await
                .unwrap()
                .unwrap()
                .ino;

            let dir_test = fs
                .create(dir_foo_ino, &name_dir_test, dir_attr(), true, true)
                .await
                .unwrap();
            let dir_test_ino = fs
                .find_by_name(dir_foo_ino, &name_dir_test)
                .await
                .unwrap()
                .unwrap()
                .ino;

            let file_bar = fs
                .create(dir_test_ino, &name_file_bar, file_attr(), true, true)
                .await
                .unwrap();
            let file_bar_ino = fs
                .find_by_name(dir_test_ino, &name_file_bar)
                .await
                .unwrap()
                .unwrap()
                .ino;

            let path = Path::new("foo/");

            let path = Path::new("foo/test/bar.rs");
            assert!(path.exists());

            // Test the `canonicalize` method
            let path = Path::new("../foo/test/../test/bar.rs");
            assert!(path.canonicalize().is_ok());
            let canon_path = path.canonicalize().unwrap();
            assert_eq!(PathBuf::from("foo/test/bar.rs"), canon_path);

            // Test the `try_exists` method
            assert!(!Path::new("does_not_exist.txt")
                .try_exists()
                .expect("Can't check existence of file does_not_exist.txt"));
            assert!(Path::new("/root/secret_file.txt").try_exists().is_err());

            // Test the `is_dir` method
            assert_eq!(Path::new("foo/").is_dir(), true);
            assert_eq!(Path::new("foo/test/").is_dir(), true);
            assert_eq!(Path::new("foo/test/../test/bar.rs").is_dir(), false);

        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_path_traits() {
    run_test(
        TestSetup {
            key: "test_path_traits",
            read_only: false,
        },
        async {},
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_pathbuf_traits() {
    run_test(
        TestSetup {
            key: "test_pathbuf_traits",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            // Test for `push` method
            let mut path = PathBuf::from("foo");
            path.push("bar");
            path.push("bee");
            path.push("baa");
            assert_eq!(path, PathBuf::from("foo/bar/bee/baa"));

            // Test for `pop` method
            path.pop();
            path.pop();
            assert_eq!(path, PathBuf::from("foo/bar"));
            path.pop();
            path.pop();
            path.pop();
            assert_eq!(path, PathBuf::from(""));

            // Test for `AsRef<Path> for Iter<'_>`
            let paths = vec![
                PathBuf::from("foo/bar"),
                PathBuf::from("baz"),
                PathBuf::from("boo"),
            ];
            let iter: PathBuf = paths.iter().collect();
            assert_eq!(iter, PathBuf::from("foo/bar/baz/boo"));
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_pathbuf_methods() {
    run_test(
        TestSetup {
            key: "test_pathbuf_methods",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            // Test the `new` method
            let path = PathBuf::new();
            assert_eq!(path.as_os_str(), std::ffi::OsStr::new(""));

            // Test the `with_capacity` method
            let mut path = PathBuf::with_capacity(10);
            assert_eq!(path.capacity(), 10);

            let capacity = path.capacity();
            path.push("/foo");
            // TODO Fix push method capacity
            assert_eq!(capacity, path.capacity());

            // Test the `as_path` method
            let p = PathBuf::from("/test");
            assert_eq!(Path::new("/test"), p.as_path());

            // Test the `push` method
            let mut path = PathBuf::from("/tmp");
            path.push("file.bk");
            assert_eq!(path, PathBuf::from("/tmp/file.bk"));

            let mut path = PathBuf::from("/tmp");
            path.push("/etc");
            assert_eq!(path, PathBuf::from("/etc"));

            // Test the `pop` method
            let mut p = PathBuf::from("/spirited/away.rs");
            p.pop();
            assert_eq!(Path::new("/spirited"), p);
            p.pop();
            assert_eq!(Path::new("/"), p);

            // Test the `set_file_name` method
            let mut buf = PathBuf::from("/");
            assert!(buf.file_name() == None);

            buf.set_file_name("foo.txt");
            assert!(buf == PathBuf::from("/foo.txt"));
            assert!(buf.file_name().is_some());

            buf.set_file_name("bar.txt");
            assert!(buf == PathBuf::from("/bar.txt"));

            buf.set_file_name("baz");
            assert!(buf == PathBuf::from("/baz"));

            buf.set_file_name("../b/c.txt");
            assert!(buf == PathBuf::from("/../b/c.txt"));

            buf.set_file_name("baz");
            assert!(buf == PathBuf::from("/../b/baz"));

            // Test the `set_extension` method
            let mut p = PathBuf::from("/feel/the");

            p.set_extension("force");
            assert_eq!(Path::new("/feel/the.force"), p.as_path());

            p.set_extension("dark.side");
            assert_eq!(Path::new("/feel/the.dark.side"), p.as_path());

            p.set_extension("cookie");
            assert_eq!(Path::new("/feel/the.dark.cookie"), p.as_path());

            p.set_extension("");
            assert_eq!(Path::new("/feel/the.dark"), p.as_path());

            p.set_extension("");
            assert_eq!(Path::new("/feel/the"), p.as_path());

            p.set_extension("");
            assert_eq!(Path::new("/feel/the"), p.as_path());

            // Test the `as_mut_os_string` method
            let mut path = PathBuf::from("/foo");

            path.push("bar");
            assert_eq!(path, Path::new("/foo/bar"));

            path.as_mut_os_string().push("baz");
            assert_eq!(path, Path::new("/foo/barbaz"));

            // Test the `into_os_string` method
            let path = PathBuf::from("/foo");
            assert_eq!(path.into_os_string(), std::ffi::OsString::from("/foo"));

            // Test the `into_os_string` method
            let path = PathBuf::from("/foo/bar");
            let boxed_path = path.into_boxed_path();

            assert_eq!(boxed_path.to_str(), Some("/foo/bar"));

            let as_path: &Path = &boxed_path;
            assert_eq!(as_path.to_str(), Some("/foo/bar"));

            // Test the `clear` method
            let mut path = PathBuf::from("/foo/bar");
            path.clear();
            assert_eq!(path, PathBuf::new());

            // Test the `reserve` method
            let mut path = PathBuf::new();
            path.reserve(10);
            assert!(path.capacity() >= 10);

            // Test the `try_reserve` method
            let mut container = PathBuf::new();
            assert!(container.try_reserve(10).is_ok());

            let mut container = PathBuf::new();
            let result = container.try_reserve(usize::MAX);
            assert!(matches!(
                result,
                Err(std::collections::TryReserveError { .. })
            ));

            let mut container = PathBuf::new();
            assert!(container.try_reserve(0).is_ok());

            // Test the `reserve_exact` method
            let mut container = PathBuf::new();
            let initial_capacity = container.inner.capacity();

            let additional = 10;
            container.reserve_exact(additional);
            let new_capacity = container.inner.capacity();

            assert!(new_capacity >= initial_capacity + additional);
            assert_eq!(
                new_capacity,
                initial_capacity + additional,
                "reserve_exact should allocate exactly the requested additional capacity"
            );

            let mut container = PathBuf::new();
            let initial_capacity = container.inner.capacity();

            container.reserve_exact(0);
            let new_capacity = container.inner.capacity();

            assert_eq!(
                new_capacity, initial_capacity,
                "reserve_exact(0) should not change capacity"
            );

            // Test the `try_reserve_exact` method
            let mut container = PathBuf::new();
            let initial_capacity = container.inner.capacity();

            let additional = 10;
            let result = container.try_reserve_exact(additional);

            assert!(
                result.is_ok(),
                "try_reserve_exact should succeed for valid allocation"
            );

            let new_capacity = container.inner.capacity();
            assert_eq!(
                new_capacity,
                initial_capacity + additional,
                "Capacity should increase by exactly the requested amount"
            );

            // try_reserve_exact zero
            let mut container = PathBuf::new();
            let initial_capacity = container.inner.capacity();

            let result = container.try_reserve_exact(0);

            assert!(result.is_ok(), "try_reserve_exact(0) should succeed");

            let new_capacity = container.inner.capacity();
            assert_eq!(
                new_capacity, initial_capacity,
                "Capacity should not change for try_reserve_exact(0)"
            );

            // try_reserve_exact failure
            let mut container = PathBuf::new();

            let additional = usize::MAX;

            let result = container.try_reserve_exact(additional);

            assert!(
                result.is_err(),
                "try_reserve_exact should fail for excessively large allocation"
            );

            if let Err(e) = result {
                println!("Error: {:?}", e);

                let error_str = format!("{:?}", e);
                if error_str.contains("AllocError") {
                    println!("Allocation error occurred.");
                } else if error_str.contains("CapacityOverflow") {
                    println!("Capacity overflow occurred.");
                } else {
                    panic!("Unexpected TryReserveError variant: {:?}", e);
                }
            }

            // Test the `shrink_to_fit` method
            let mut container = PathBuf::new();

            for _ in 0..10 {
                container.push("test".to_string());
            }

            let initial_capacity = container.capacity();

            container.pop();
            container.pop();

            let reduced_length = container.to_string_lossy().len();
            assert!(
                container.capacity() > reduced_length,
                "Capacity should be greater than length before shrinking"
            );

            container.shrink_to_fit();

            assert_eq!(
                container.capacity(),
                reduced_length,
                "Capacity should equal length after shrinking to fit"
            );

            // Test the `shrink_to` method
            let mut container = PathBuf::from("/path/to/file");

            let initial_capacity = container.inner.capacity();
            assert!(initial_capacity > 0);

            container.inner.push("foo".to_string());
            container.inner.push("bar".to_string());

            let expanded_capacity = container.inner.capacity();
            assert!(expanded_capacity > initial_capacity);

            let min_capacity = 5;
            container.shrink_to(min_capacity);

            let final_capacity = container.inner.capacity();
            assert!(final_capacity >= min_capacity);
            assert!(final_capacity < expanded_capacity);
            let file = std::fs::OpenOptions::new().write(true).create(true).open("file").unwrap();

        },
    )
    .await;
}

struct PasswordProviderImpl {}

impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("pass42").unwrap())
    }
}

const fn file_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

const fn dir_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::Directory,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}
