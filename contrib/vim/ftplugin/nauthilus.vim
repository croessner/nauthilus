" Vim filetype plugin
" Language:     Nauthilus configuration
" Maintainer:   Christian Roessner <christian@roessner.email>

if exists("b:did_ftplugin")
  finish
endif
let b:did_ftplugin = 1

setlocal shiftwidth=2
setlocal tabstop=2
setlocal softtabstop=2
setlocal expandtab

" Undo the plugin settings when changing filetype
let b:undo_ftplugin = "setlocal shiftwidth< tabstop< softtabstop< expandtab<"
