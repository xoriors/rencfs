use std::ffi::OsStr;

use crate::crypto::path::*;
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

            // Test the `as_mut_os_str` method (Pathbuf::as_mut_os_str not impl)
            // let mut path = PathBuf::from("Foo.TXT");
            // assert_ne!(path, Path::new("foo.txt"));

            // path.as_mut_os_str().make_ascii_lowercase();
            // assert_eq!(path, Path::new("foo.txt"));

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
            // let path = Path::new("foo.rs");
            // assert_eq!(path.with_extension("txt"), PathBuf::from("foo.txt"));

            // let path = Path::new("foo.tar.gz");
            // assert_eq!(path.with_extension(""), PathBuf::from("foo.tar"));
            // assert_eq!(path.with_extension("xz"), PathBuf::from("foo.tar.xz"));
            // assert_eq!(
            //     path.with_extension("").with_extension("txt"),
            //     PathBuf::from("foo.txt")
            // );
        },
    )
    .await;
}
