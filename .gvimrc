call pathogen#infect()

nmap <C-V> "+gP
imap <C-V> <ESC><C-V>i
vmap <C-C> "+y

map <C-b> :w<CR>:!python %<CR>

autocmd! bufwritepost .vimrc source %

set tabstop=4
set softtabstop=4
set shiftwidth=4
set shiftround
set expandtab

set hlsearch
set incsearch
set ignorecase
set smartcase

if filereadable(expand("~/.gvimrc.before"))
  source ~/.gvimrc.before
endif

" CtrlP OS-X Menu remapping
if janus#is_plugin_enabled('ctrlp') && has("gui_macvim")
  macmenu &File.New\ Tab key=<D-S-t>
endif

if filereadable(expand("~/.gvimrc.after"))
  source ~/.gvimrc.after
endif

colorscheme molokai
set guifont=Monospace\ 9


