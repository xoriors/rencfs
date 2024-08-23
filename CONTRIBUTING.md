## How to contribute

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache License, shall be dual-licensed as above, without any additional terms or conditions.

1. Fork the repo
2. [Setup](https://github.com/radumarias/rencfs?tab=readme-ov-file#locally) dev env localy, replace URL repo with your fork URL
3. Read the [docs](https://github.com/radumarias/rencfs) and [lib docs](https://docs.rs/rencfs/latest/rencfs), then become familiar with the code and run tests, benchmarks and examples. You can write some examples yourself and maybe some tests to help you understand the flow better. If you do, you can add these later on to the repo for the the community
4. **Ask the owner of the repository to add your GitHub username to the project** 
5. Make sure there is an open issue or a task in the corresponding [project](https://github.com/users/radumarias/projects/1) for the repo that you'll be working on. You can see [good for first issues](https://github.com/radumarias/rencfs/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) that you can pick from
6. **Assign the issues you are working on to you and move them to the corresponding status column as you are working on them. If the taks is not an issue yet, convert it to issue first**
7. Make the changes in your fork
8. Add docs as they apply
9. Add tests, benchmarks and examples for your changes, if applicable
10. `cargo fmt --all` to format the code. You can configure your **IDE** to do this on
   save, [RustRover](https://www.jetbrains.com/help/rust/rustfmt.html)
   and [VSCode](https://code.visualstudio.com/docs/languages/rust#_formatting)
11. `cargo clippy --all --release` and fix any erorrs
12. **DON'T INCREASE THE VERSION NUMBER IN `Cargo.toml`, WE WILL DO THAN WHEN RELEASING**
13. **MAKE SURE YOU RUN THIS BEFORE PUSHING TO THE REPO `./check-before-push.sh` or `cmd /c check-before-push.bat` and fix any errors**
14. Create a **PR** back to the **parent** repo targeting the `main` branch and reques review from owners of the repository
15. Monitor the checks (GitHub actions run) and fix the code if they are failing
16. Respond to any comments
17. In the end, ideally, it will be merged to `main`
