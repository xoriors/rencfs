# Testing

We'd appreciate it if you could help test the app. For now, the filesystem mounting works only on Linux, so the cleanest way is to test on Linux.

Here are some ways you can do it.

## Testing in VSCode in browser or local

You'll need a GitHub account for this.

This will create a Codespace instance on GitHub, a Linux container, so we can test it.  
The instance config is 2 CPUs and 4 GB RAM. You have 120 CPU hours per month free for Codespace, which means 60 hours for that instance. We will connect to it from the browser and the local VSCode.

### First setup

1. Open the [repo](https://github.com/xoriors/rencfs)
2. Press `Code` button  
  ![image](https://github.com/user-attachments/assets/7c0e8872-fe1f-44b9-a833-2586ade4f618)
3. Create codespace on main  
  ![image](https://github.com/user-attachments/assets/5fee55f6-ef54-427c-b790-c135312d3355)
4. This will create the container on GitHub. If it asks you to setup config, select the minimum possible CPU and RAM
5. Start it and leave it to finish. This could take a bit longer. This will open a VSCode in the browser
6. If the terminal panel is not at the bottom, go to the terminal in the browser version of the VSCode editor you're presented with. It should be at the bottom. If not, open it from the `Terminal -> New Terminal` menu. You can find the menu in the top left, with 3 lines icon  
  ![image](https://github.com/user-attachments/assets/48681023-e450-49b3-8526-ec0323be0d40)
7. Install Rust by pasting these in the terminal:
  ```bash
  apt-get update && apt-get install fuse3
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

  ```
  Press 1 and Enter on Rust installation, accepting all defaults.

  If installation aborts, then run these
  ```bash
    apt update
    apt install rustc
    rustc

  ```
8. Create needed folders and a `tmp` folder, which we will use to copy files from our machine, by pasting this in the terminal:
  ```bash
  mkdir tmp_upload && mkdir tmp_download && mkdir final && mkdir data
  ```
  
### Each resume and after the first setup

1. Open the [repo](https://github.com/xoriors/rencfs)
2. Press `Code` button  
  ![image](https://github.com/user-attachments/assets/7c0e8872-fe1f-44b9-a833-2586ade4f618)
3. Press ```...``` right to the instance in the list  
  ![image](https://github.com/user-attachments/assets/c621c258-009d-46bf-adb7-f81a3d7131f6)

#### VSCode in Browser

4. Press `Open in Browser`, or directly click on the container name

#### In local VSCode

Make sure you have VSCode installed locally, based on your OS.

4. Press `Open in Visual Studio Code`

#### Continue

Do step 6 from above.

5. Type this in the VSCode terminal, which will fetch the changes from the repo (if there are conflicts, accept Theirs):
  ```bash
  git reset --hard
  git pull
  rm -rf final && cargo run --release -- mount -m final -d data
  ```
6. Input a password and confirm it the first time

You can now perform two types of tests; see below. In both cases, follow these steps.

7. Copy files and folders from your local machine to the `tmp_upload` folder in VSCode. This is to eliminate network issues during copying. For example, if we copy from local directly to `final,` if there is a network failure, we have an error during copying. The problem, in this case, is not in our app, and it would create a false positive as we don't know the problem is from the network.
8. Copy files and folders from `tmp_upload` to `final` and then do other operations on the data in there
9. Make sure files were copied successfully by copying them from `final` to `tmp_download`, right-clicking a file, and then `Download...`, saving it to the local machine, and making sure it opens correctly. We first copy to `tmp_download` to eliminate network issues during copying. For example, if we copy directly from `final` to loca, we have an error during copying if there is a network failure. The problem, in this case, is not in our app, and it would create a false positive as we don't know the problem is from the network.

**When testing, remember that the `final` folder should behave exactly like a regular local folder on your system. That's the main idea of how you should test. If something behaves differently than a regular folder then please report it as a Bug, see below.**

#### Exploratory testing

That is, testing anything that comes to mind.

Repeat steps 7-9 in various ways.

#### Test specific issues

Test specific issues from the [project](https://github.com/users/xoriors/projects/1). You can take the ones from `Ready for QA` column:
1. Assign the issue to you and move it to `In QA`
2. Test it
3. When you finished, move it to `Tested`

- [ ] Testing on Linux
- [ ] Testing on macOS
- [ ] Testing on Windows

## Tests

I created some [files](https://drive.google.com/drive/folders/1N-2KhGNo7f23tQ9Si4yWa9dlFtxUnsoM?usp=sharing) to keep our tests until we migrate to browserstack or similar. 

- `test cases`: generic test cases
- `smoke tests`: short, small tests used to test a build quickly
- `acceptance`: tests that must be passed to consider a build stable. These we will run for prod builds

## Open a bug

Please use [this](https://github.com/xoriors/rencfs/issues/new?assignees=&labels=&projects=&template=bug_report.md&title=) and follow the steps in there.

## Creating a test case

Please add a new row in the `test cases` file and follow the template of the first row, for example. The same applies to smoke tests and acceptance tests.
