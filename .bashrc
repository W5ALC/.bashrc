# .bashrc
#
if [ -f /etc/bashrc ]; then
source /etc/bashrc
fi
EDITOR=nano
set -o vi
dotfiles=(
  "${HOME}/.bash_aliases"
  "${HOME}/.bash_functions"
  "${HOME}/.bashrc_colors"
  "${HOME}/.text_functions"
  "${HOME}/.fzf.opts"
)
for dotfile in "${dotfiles[@]}"; do
  [[ -r "${dotfile}" ]] && source "${dotfile}"
done
unset dotfiles; unset -v dotfile

# Function to check last login and print result
checkLastLogin() {
    local login="$1"
    local known_ips=("172\.58\." "71\.196\.250\.30" "10\.0\.0\." "10\.66\.66\.")

    for ip in "${known_ips[@]}"; do
        if [[ "$login" =~ $ip ]]; then
            printf "\\[\\e[1;32m\\]✓\n"
            return
        fi
    done

    echo "$login"
}


# Function to check last login for SSH session
psONE_ssh() {
    local last_login=$(last | sed -n '2p' | awk '{ print $3 }')
    checkLastLogin "$last_login"
}

# Function to check last login for local session
psONE_local() {
    local last_login=$(lastlog | grep "$(whoami)" | awk '{ print $3 }')
    checkLastLogin "$last_login"
}

# Function to set the PS1 prompt
_prompt_command() {
    local prompt

    if [[ -n $SSH_CLIENT ]]; then
        prompt="\\[\\e[1;31m\\]🟢 $(psONE_ssh)"
    else
        if ss -tn src :8222 | grep ESTAB &> /dev/null; then
            prompt="\\[\\e[1;32m\\]🟢 $(psONE_local)"
        else
            prompt="\\[\\e[1;31m\\]🔴 $(psONE_local)"
        fi
    fi

    PS1="$prompt\\[\\e[1;33m\\]\n\w/\n\\[\\e[0m\\]\\[\\e[1;31m\\]𝝅\\[\\e[0m\\]\\[\\e[1;32m\\] "
}
# Set the prompt command
PROMPT_COMMAND="_prompt_command ; history -a; history -c ; history -r ; $PROMPT_COMMAND"

AUDIO_OUTPUT_DEVICE="$(pactl list short sinks | grep -i running | awk '{ print $2 }')"

check_and_source() {
    local file="$1"
    local last_mod="$(stat -c %Y "$file")"
    local last_source="${file}_last_source"
    if [ ! -f "$last_source" ] || [ "$last_mod" -gt "$(cat "$last_source")" ]; then
        source "$file"
        echo "$last_mod" > "$last_source"
    fi
}

alias bashr='$EDITOR ~/.bashrc && check_and_source ~/.bashrc'
alias bashf='$EDITOR ~/.bash_functions && check_and_source ~/.bash_functions'
alias basha='$EDITOR ~/.bash_aliases && check_and_source ~/.bash_aliases'
alias bashru="check_and_source ~/.bashrc"
alias bashfu="check_and_source ~/.bash_functions"
alias bashau="check_and_source ~/.bash_aliases"
alias scmd='fc -ln -1 | sed "s/^\s*//" >> ~/.saved_cmds.txt'
alias rcmd='eval $(fzf < ~/.saved_cmds.txt)'

# User specific $PATH
if ! [[ "$PATH" =~ "$HOME/.local/bin:/usr/local/texlive/2022/bin/x86_64-linux:/media/nowhereman/nowhereman/bin:$HOME/bin:" ]]
then
    PATH="$HOME/.local/bin:/usr/local/texlive/2022/bin/x86_64-linux:/media/nowhereman/nowhereman/bin:$HOME/bin:$PATH"
fi

PS2=""
PS4='-[\e[33m${BASH_SOURCE/.sh}\e[0m: \e[32m${LINENO}\e[0m] '
PS4+='${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

# Export variables
export PATH
HISTSIZE=-1 # unlimited history file
HISTFILESIZE=-1 # unlimited history file
HISTCONTROL=ignorespace:ignoredups:erasedups
shopt -s histappend
export MANPAGER="most"
export HISTIGNORE=$'[ \t]*:&:[fb]g:[ewr][xcz][iou][try]:ls:bash[afr]:bash[afr]u:cd:::'
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"
shopt -s lithist
shopt -s checkwinsize
shopt -s globstar
shopt -s dotglob
shopt -s cmdhist
shopt -s autocd
shopt -s cdspell
shopt -s force_fignore
shopt -s nocaseglob
shopt -s nocasematch
set -o notify
set -o ignoreeof

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

export LESS='FiX'

# If not running interactively, don't do anything
case $- in
  *i*) ;;
    *) return;;
esac

get_command() {
  local errcount cmd
  case "${1}" in
    (-v|--verbose)
      shift 1
      errcount=0
      for cmd in "${@}"; do
        command -v "${cmd}" ||
          { printf -- '%s\n' "${cmd} not found" >&2; (( ++errcount )); }
      done
      (( errcount == 0 )) && return 0
    ;;
    ('')
      printf -- '%s\n' "get_command [-v|--verbose] list of commands" \
        "get_command will emit return code 1 if any listed command is not found" >&2
      return 0
    ;;
    (*)
      errcount=0
      for cmd in "${@}"; do
        command -v "${1}" >/dev/null 2>&1 || (( ++errcount ))
      done
      (( errcount == 0 )) && return 0
    ;;
  esac
  # If we get to this point, we've failed
  return 1
}

if get_command pbcopy; then
	clipin() { pbcopy; } # Execute the pbcopy command
	clipout() { pbpaste; } # Execute the pbpaste command
elif get_command xclip; then
	clipin() { xclip -selection c; } # Execute the xclip command with the '-selection c' option
	clipout() { xclip -selection clipboard -o; } # Execute the xclip command with the '-selection clipboard -o' options
elif get_command xsel ; then
	clipin() { xsel --clipboard --input; } # Execute the xsel command with the '--clipboard --input' options
	clipout() { xsel --clipboard --output; } # Execute the xsel command with the '--clipboard --output' options
elif get_command termux-clipboard-set ; then
	clipin() { termux-clipboard-set; } # Execute the termux-clipboard-set command
	clipout() { termux-clipboard-get; } # Execute the termux-clipboard-get command
else
	clipin() { printf -- '%s\n' "No clipboard capability found" >&2; } # Print an error message to stderr
	clipout() { printf -- '%s\n' "No clipboard capability found" >&2; } # Print an error message to stderr
fi

# export OPENAI_API_KEY=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
