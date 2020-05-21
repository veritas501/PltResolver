# PltResolver
A plugin to resolve `.plt.sec` symbols in IDA.

## Usage

**Only tested on IDA 7.2.**

**Can only used for i386 and amd64 arch elf binary.**

1. Move `PltResolver.py` into `%IDA%/plugins/`.
2. Press `Ctrl+Shift+J` or `Edit->Parse .plt.sec symbols`.

## Screenshot

- Before:

![](assets\before.png)

![](assets\before2.png)

- After:

![](assets\after.png)

![](assets\after2.png)