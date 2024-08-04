## How to contribute

1. Fork the repo
2. [Setup](https://github.com/radumarias/rencfs?tab=readme-ov-file#locally) dev env localy, replace url repo with your fork url
3. Become familiar with the [docs](https://github.com/radumarias/rencfs) and [lib docs](https://docs.rs/rencfs/latest/rencfs), then become familiar with the code and running tests and examples
4. **Ask the owner of the project to add your GitHub username to the project** 
5. Make sure there is an open issue or a task in the [project](https://github.com/users/radumarias/projects/1) that you'll be working on. You can see [good for first issues](https://github.com/radumarias/rencfs/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
6. **Assign the issues you are working to you and move them to the corresponding status column as you are working on them. If the taks is not an issue yet, convert it to issue first**
7. Make the changes in your fork
8. If you add new `.rs` files add all these [lines](https://github.com/radumarias/rencfs/blob/main/src/lib.rs#L1-L16) as first ones to all of them
9. Add tests for your changes, if applicable
10. `cargo fmt --all`, you can configure your **IDE** to do this on
   save, [RustRover](https://www.jetbrains.com/help/rust/rustfmt.html)
   and [VSCode](https://code.visualstudio.com/docs/languages/rust#_formatting)
11. `./check-before-push.sh` or `cmd /c check-before-push.bat` and fix any errors
12. Create a **PR** back to the **parent** repo to the `main` branch
13. Monitor the checks (GitHub actions run)
14. Respond to any comments
15. In the end, ideally, it will be merged to `main`
