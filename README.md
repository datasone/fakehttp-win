# fakehttp-win

A TCP traffic obfuscator for Windows inspired by [FakeHTTP](https://github.com/MikeWang000000/FakeHTTP), powered
by [WinDivert](https://github.com/basil00/WinDivert) library.

This tool just send a fake http request after receving SYN+ACK TCP packet, naively obfuscating the TCP connection as a
HTTP connection.

## Usage

Refer to app help:`fakehttp-win.exe --help`

## Build Tips

You need to set corresponding env vars for WinDivert library files. Refer
to [build guide](https://github.com/Rubensei/windivert-rust#build) for windivert rust wrapper library.

`WinDivert.dll` and `WinDivert64.sys` are required to be placed in the same directory of the built executable.