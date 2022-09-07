# nds.py

Nintendo DS ROM tools for IDA Pro 7.6+. Requires [Python 3.10](https://www.python.org/downloads/release/python-3100/) or greater.

## Features

- Supports ~~both ARM7 and~~ ARM9
- Automated segmentation
- All IO registers are named
- Support for address mirroring
- Fix decompilation for certain instructions (~~SVC~~, MRC/MCR, etc.)

**TODO:**

- Automatically name known functions, without using signature files

## Installation

Move the `nds` folder in the root of your IDA Pro installation; everything else relies on this folder.

For the loader: merge the `loaders` folder with `{IDA_ROOT}/loaders`.
For plugins: merge the `plugins` folder with `{IDA_ROOT}/plugins`.

## License

Do whatever you want with the code, I don't care. If it turns out to be useful, please share any derived work.

## Credits

The reason this thingy exists in the first place is the [GBATEK](https://www.problemkaputt.de/gbatek.htm) docs, which were my main resource during development.