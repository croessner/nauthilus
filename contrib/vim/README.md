# Nauthilus Vim Syntax Highlighting

This directory contains a Vim syntax highlighting plugin for Nauthilus configuration files.

## Installation

To install the plugin, copy the files to your `~/.vim` directory:

```bash
mkdir -p ~/.vim/syntax ~/.vim/ftdetect ~/.vim/ftplugin
cp syntax/nauthilus.vim ~/.vim/syntax/
cp ftdetect/nauthilus.vim ~/.vim/ftdetect/
cp ftplugin/nauthilus.vim ~/.vim/ftplugin/
```

Or, if you use a plugin manager like vim-plug, you can add the following to your `.vimrc`:

```vim
Plug '/path/to/nauthilus/vim'
```

## Features

- Highlight main configuration sections (Root level: Dark Blue)
- Highlight secondary sections (Second level: Green)
- Highlight mapping keys (Yellow)
- Highlight LDAP filters with a distinct color
- Specific highlighting for important fields like `address`, `server_uri`, etc.
- Built on top of the standard YAML syntax, preserving standard colors for strings and numbers
- Automatic indentation settings (shiftwidth=2, tabstop=2, expandtab)
