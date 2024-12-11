# Testing

We'd appreciate it if you could help test the app. For now, the filesystem mounting works only on Linux, so the cleanest way is to test on Linux.

Here are some ways you can do it.

## Testing in VSCode in browser and locally

### First setup

1. Open the [repo](https://github.com/radumarias/rencfs)
2. Press `Code` button  
  ![image](https://github.com/user-attachments/assets/7c0e8872-fe1f-44b9-a833-2586ade4f618)
3. Create codespace on main  
  ![image](https://github.com/user-attachments/assets/5fee55f6-ef54-427c-b790-c135312d3355)
4. This will create the container on GitHub. If it asks you to setup config, select the minimum possible CPU and RAM
5. Start it and leave it to finish
6. Go back to the repo root. You can close the current tab
7. Press `Code` button
  ![image](https://github.com/user-attachments/assets/0baec7da-cbbd-4186-a82b-887e18c0c85d)
8. Press ```...``` right to the instance in the list
  ![image](https://github.com/user-attachments/assets/c621c258-009d-46bf-adb7-f81a3d7131f6)
9. Press `Open in Browser`
10. Allow it to finish
11. Open a terminal in VSCode from the menu `Terminal -> New Terminal`
12. Install Rust and create a `tmp` folder, which we will use to copy files from our machine, by typing these in terminal:
  ```bash
  apt-get update && apt-get install fuse3
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  mkdir mnt && mkdir data
  ```
  Press enter on Rust installation, accepting all defaults

### Each resume and after fist setup

Do steps 1, 7, 8 from above.

#### In Browser

Do step 9 from above. This will open VSCode in browwser.  
Instead of taking step 8 and the above, you can directly click on the container name.

#### In local VSCode

Make sure you have VSCode installed locally, based on your OS

After step 8 press `Open in Visual Studio Code`.

#### Continue

Do step 11 from above.

1. Type this in terminal, which will fetch the changes from the repo (if there are conflicts, accept Theirs):
  ```bash
  git pull
  cargo run --release -- mount -m mnt -d data
  ```
2. Input a password and confirm it the first time
3. Copy test files from your machine to `tmp` folder in `VSCode`, by `Ctrl + C / Ctrl + V` or by Drag and Drop
4. Copy files and folders from `tmp` to `mnt` and do all kinds of operations on `nnt` folder
5. Make sure files were copied successfully by right-clicking a file and then `Download...` and save it to local machine
6. Make sure files open correctly
7. Do all kinds of operations in `mnt` folder and make sure they are ok

## Testing on Linux

TODO

## Testing on macOS

TODO

## Testing on Windows

TODO
