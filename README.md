# GoWR-Script-Loader
This is a simple plugin for God of War Ragnarök that dumps the raw scripts files loaded by the game and let the game load modified scripts without repacking the files.

## Installation
Get the zip file from Releases and unpack it in the same folder as GoWR.exe

## Dump Script
Dump script function is off by default. To enable the function, open GOWR-Script-Loader.ini and change the value under dump section from 0 to 1.
A folder `dump` will be created and the script dumps will be placed inside the folder. The Lua scripts can be decompiled using unluac.

## Load Modified Script
Load modified script function is on by default.
If a script file is found under `mod/<path of the script>`, the program will load it instead.
