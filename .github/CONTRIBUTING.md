## How to contribute

> [!IMPORTANT]  
> **These steps are more particular to this repo but mainly apply to all repositories; change the specifics.**

Unless you explicitly state otherwise, any Contribution intentionally submitted for inclusion in this project by you, as
defined in the Apache License shall be dual-licensed as above, without any additional terms or conditions.

1. Join the project's [slack](https://bit.ly/3UU1oXi) (this is for the `rencfs` project, please use the one for your project) and join the `#dev-beginners` channel (or any relevant ones)
2. **Ask the owner of the repository to add your GitHub username to the repository** so that you can work on issues and
   be able to create your own branches and not need to fork the repo

# Devs & QA automation (which steps apply)

3. Become familiar with docs and code by reading the [ramp-up](../docs/readme/Ramp-up.md) guide
4. Pick an open issue or a task in the corresponding [project](https://github.com/users/radumarias/projects/1) for the
   repo you'll work on. You can
   see [good for first issues](https://github.com/xorio/rencfs/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
   that you can pick from
5. **Assign the issues you are working on to you and move them to the corresponding status column as you progress
   . If the task is not an issue yet, convert it to an issue first**
6. Make the changes in your branch
7. Add docs as they apply
8. Add tests, benchmarks, and examples for your changes, if applicable
9. `cargo fmt --all` to format the code. You can configure your `IDE` to do this on
   save, [RustRover](https://www.jetbrains.com/help/rust/rustfmt.html)
   and [VSCode](https://code.visualstudio.com/docs/languages/rust#_formatting)
10. `cargo clippy --all --release` and fix any errors
11. **DON'T INCREASE THE VERSION NUMBER IN `Cargo.toml`, WE WILL DO THAT WHEN RELEASING**
12. Create a `git` `push hook` file in `.git/hooks/pre-push` with [pre-push](scripts/git-hooks/linux-macos/pre-push)
    content
    on `Linux` and `macOS`, and [pre-push](scripts/git-hooks/windows/pre-push) on `Windows`.
    Make it executable in Linux and macOS
    with `chmod +x .git/hooks/pre-push` .This will run when you do `git push` and will make the push quite
    slow, but please give it time to complete as this helps to fix any issues locally and not rely just on
    running `ci` on GitHub when you create the PR
13. Commit the changes with the commit message following the [Commit Message Guidelines](https://gist.github.com/radumarias/5b5374f3ed022c99d617eb849aafd069)
14. Push your changes, and if there are any errors, fix them before you push them
15. Create a `PR` back to the `parent` repo targeting the `main` branch with the title as the GitHub issue title, including `#ID`. Also, include the link to the GitHub issue in the description, saying like `Fix for <link>` for bugs or `Implementation for <link>` for features and others
16. Request review from owners of the repository by adding them to the `Reviewers` field
17. After you create the PR, link it to the GH issue from the mid-right of the page, press the gear icon from the below image, select `xoriors/rencfs`, then write the issue number and select it. This will link the two, and when the PR is merged, it will close the issue too  
  ![image](https://github.com/user-attachments/assets/5ac0313d-4175-44d1-8d1e-d18da773ab32)
18. In the project, move the item to `In Code Review`
19. Monitor the checks (GitHub actions runs) and fix the code if they are failing
20. Respond to any comments
21. **DON'T MERGE THE PR YOURSELF. LEAVE THAT TO REPOSITORY OWNERS**
22. In the end, ideally, it will be merged into `main`

# QA manual

Please follow these [steps](../docs/readme/Testing.md).
