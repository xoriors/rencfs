## How to contribute

1. Fork the repo
2. [Setup](https://github.com/radumarias/rencfs?tab=readme-ov-file#locally) dev env localy, replace url repo with your fork url
3. Make sure there is an open issue or a task in the [project](https://github.com/users/radumarias/projects/1)
4. **Ask the owner of the project to add your GitHub username to the project**
5. **Assign the issues you are woeking to you and move them in the corresponding status column as you are working on it. If the taks is not an issue yet, convert it to issue first**
6. Make the changes in your fork
7. If you add new `.rs` files in `examples` member add all these [lines](https://github.com/radumarias/rencfs/blob/main/src/lib.rs#L1-L16) as first ones
8. If you add new packages to the workspace add all these [lines](https://github.com/radumarias/rencfs/blob/main/src/lib.rs#L1-L16) to it's `lib.rs`
   and to any `bin` files (
   like `main.rs` or other files declared as `[[bin]]`)
9. Add tests for your changes, if applicable
10. `cargo fmt --all`, you can configure your **IDE** to do this on
   save, [RustRover](https://www.jetbrains.com/help/rust/rustfmt.html)
   and [VSCode](https://code.visualstudio.com/docs/languages/rust#_formatting)
11. `./check-before-push.sh` or `cmd /c check-before-push.bat` and fix any errors
12. Create a **PR** back to **main** repo to the `main` branch
13. Monitor the checks (GitHub actions run)
14. Respond to any comments
15. In the end, ideally, it will be merged to `main`
