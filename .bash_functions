# .bash_functions



alt_h() {
  local _alth_first_word _alth_lookup_cmd
  export ALTH_SC="$(tput sc)"

  _alth_first_word=${READLINE_LINE%% *}
  if (( READLINE_POINT > ${#_alth_first_word} )); then
    # grab the string up to the cursor. e.g. "df {} | less" where {} is the cursor looks up df.
    _alth_lookup_cmd=${READLINE_LINE::$READLINE_POINT}
    # remove previous commands from the left
    _alth_lookup_cmd=${_alth_lookup_cmd##*[;|&]}
    # remove leading space if it exists (only a single one though)
    _alth_lookup_cmd=${_alth_lookup_cmd# }
    #remove arguments to the current command from the right
    _alth_lookup_cmd=${_alth_lookup_cmd%% *}
  else
    # if the cursor is at the beginning of the line, look up the first word
    _alth_lookup_cmd=$_alth_first_word
  fi

  if get_command tldr; then
   pman "${_alth_lookup_cmd}" && tldr "${_alth_lookup_cmd}"
  else
    pman "${_alth_lookup_cmd}"
  fi
}

bind -x '"\eh":alt_h' 2>/dev/null


# Function to save the last command
alt_s() {
    local last_cmd="$(fc -ln -1 | sed 's/^\s*//')"
    echo "$last_cmd" >> ~/.saved_cmds.txt
    echo "Command saved: $last_cmd"
}

# Bind the Alt + s key combination to the save_last_command function
bind -x '"\es":alt_s'
#bind -x '"\C-x\C-j": "cd \$(dirs -v | awk '!index(\$2,\"/\") {print \$2}' | fzf --height 40% --reverse --inline-info)\n"'

# Define the alt_r function
alt_r() {
    eval $(fzf < ~/.saved_cmds.txt)
}

# Bind the Alt + r key combination to the alt_r function
bind -x '"\er":alt_r'


# Define the alt_d function
alt_d() {
    # Check if the file exists
    if [ ! -f ~/.saved_cmds.txt ]; then
        printf "File not found: ~/.saved_cmds.txt\n"
        return
    fi

    # Prompt the user to select line(s) to delete
#   printf "Select line(s) to delete:\n"
    selected_lines=$(nl -w1 -s' ' ~/.saved_cmds.txt | fzf -m)
    if [[ -z $selected_lines ]]; then
        printf "No lines selected\n"
        return
    fi

    # Extract line numbers from the selected lines
    line_numbers=$(echo "$selected_lines" | awk '{print $1}')

    # Create a temporary file
    temp_file=$(mktemp)

    # Delete the selected lines from the file
    awk -v lines_to_delete="$line_numbers" 'BEGIN { split(lines_to_delete, lines_array, "\n") }
          { for (i in lines_array) if (NR == lines_array[i]) next } 1' ~/.saved_cmds.txt > "$temp_file"

    # Replace the original file with the temporary file
    mv "$temp_file" ~/.saved_cmds.txt
    printf "Deleted command\n"
}


# Bind the Alt + d key combination to the alt_d function
bind -x '"\ed":alt_d'

bind -x '"\C-xt": "echo $(date +%H:%M:%S)"'
function dnf_manage {
    # Check if required commands exist
    command -v dnf >/dev/null 2>&1 || { echo >&2 "Error: dnf command not found. Aborting."; return 1; }
    command -v sudo >/dev/null 2>&1 || { echo >&2 "Error: sudo command not found. Aborting."; return 1; }

    case "$1" in
        install)
            read -rp "Enter package name(s) to install: " packages
            printf "Installing %s...\n" "$packages"
            sudo dnf install "$packages"
            ;;
        update)
            printf "Updating packages...\n"
            sudo dnf update -y
            ;;
        remove)
            read -rp "Enter package name(s) to remove: " packages
            printf "Removing %s...\n" "$packages"
            sudo dnf remove "$packages"
            ;;
        search)
            printf "Searching for packages matching '%s'...\n" "$2"
            sudo dnf search "$2"
            ;;
        list)
            printf "Listing installed packages...\n"
            sudo dnf list installed
            ;;
        upgrade)
            printf "Upgrading packages...\n"
            sudo dnf upgrade -y
            ;;
        *)
            printf "Invalid command '%s'. Usage: dnf_manage [install|update|remove|search|list|upgrade] [package]\n" "$1"
            return 1
            ;;
    esac
}

# Key bindings
bind -x '"\C-xi": "dnf_manage install "'
bind -x '"\C-xu": "dnf_manage update"'
bind -x '"\C-xd": "dnf_manage remove "'
bind -x '"\C-xs": "dnf_manage search "'
bind -x '"\C-xl": "dnf_manage list"'
bind -x '"\C-xg": "dnf_manage upgrade"'


fcd() {
  cd "${1:-$HOME}" && echo "Changed directory to $(pwd)"
  dirs -v | awk 'index($2,"/") { print $2 }' | fzf --height 10% --reverse --inline-info --read0 | xargs -0 cd && echo "Changed directory to $(pwd)"
}

bind -x '"\C-g": "fcd"'
#######################################################
############## Begin Network functions ################
#######################################################
function banip()
{
sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$1' reject"
sudo firewall-cmd --reload
}


function allowip-fwd() {
    sudo firewall-cmd --zone=home --add-source="$1" --permanent
	sudo firewall-cmd --reload
}

function blockip-fwd() {
    sudo firewall-cmd --zone=home --remove-source="$1" --permanent
	sudo firewall-cmd --reload
}

function allowport-fwd() {
    sudo firewall-cmd --zone=home --add-port="$1"/tcp --permanent
	sudo firewall-cmd --reload
}

function blockport-fwd() {
	sudo firewall-cmd --zone=home --remove-port="$1"/tcp --permanent
	sudo firewall-cmd --reload
}

function allowip-ufw() {
	sudo ufw allow from "$1"
}

function blockip-ufw() {
	sudo ufw delete allow from "$1"
}

function allowport-ufw() {
    sudo ufw allow "$1"/tcp
}

function blockport-ufw() {
	sudo ufw delete allow "$1"/tcp
}


function allowip-ipfw() {
	sudo iptables -I INPUT -s "$1" -j ACCEPT
	sudo iptables -A OUTPUT -d "$1" -j ACCEPT
}

function blockip-ipfw() {
	sudo iptables -I INPUT -s "$1" -j DROP
	sudo iptables -A OUTPUT -d "$1" -j DROP
}

function allowport-ipfw() {
	sudo iptables -I INPUT -p tcp -m tcp --dport "$1" -j ACCEPT
	sudo iptables -A OUTPUT -p tcp -m tcp --dport "$1" -j ACCEPT
}

function blockport-ipfw() {
	sudo iptables -I INPUT -p tcp -m tcp --dport "$1" -j REJECT
}

function allowip() {
	if command -v firewall-cmd &>/dev/null; then
		sudo firewall-cmd --zone=home --add-source="$1" --permanent
		sudo firewall-cmd --reload
	elif command -v ufw &>/dev/null; then
		sudo ufw allow from "$1"
	elif command -v iptables &>/dev/null; then
		sudo iptables -I INPUT -s "$1" -j ACCEPT
		sudo iptables -A OUTPUT -d "$1" -j ACCEPT
	else
		echo "Something is wrong with your firewall...  exiting" >&2
	fi
}

function blockip() {
	if command -v firewall-cmd &>/dev/null; then
		sudo firewall-cmd --zone=home --remove-source="$1" --permanent
		sudo firewall-cmd --reload
	elif command -v ufw &>/dev/null; then
		sudo ufw delete allow from "$1"
	elif command -v iptables &>/dev/null; then
		sudo iptables -I INPUT -s "$1" -j DROP
		sudo iptables -A OUTPUT -d "$1" -j DROP
	else
		echo "Something is wrong with your firewall...  exiting" >&2
	fi

}

function allowport() {
	if command -v firewall-cmd &>/dev/null; then
		sudo firewall-cmd --zone=home --add-port="$1"/tcp --permanent
		sudo firewall-cmd --reload
	elif command -v ufw &>/dev/null; then
		sudo ufw allow "$1"/tcp
	elif command -v iptables &>/dev/null; then
		sudo iptables -I INPUT -p tcp -m tcp --dport "$1" -j ACCEPT
		sudo iptables -A OUTPUT -p tcp -m tcp --dport "$1" -j ACCEPT
	else
		echo "Something is wrong with your firewall...  exiting" >&2
	fi

}

function blockport() { # Function to cover most used firewalls on bigger distributions
	if command -v firewall-cmd &>/dev/null; then # Check if firewall-cmd is installed
		sudo firewall-cmd --zone=home --remove-port="$1"/tcp --permanent
		sudo firewall-cmd --reload
	elif command -v ufw &>/dev/null; then # If no firewall-cmd check for ufw
		sudo ufw delete allow "$1"/tcp
	elif command -v iptables &>/dev/null; then # If ufw unavailable, resort to iptables
		sudo iptables -I INPUT -p tcp -m tcp --dport "$1" -j REJECT
	else
		echo "Something is wrong with your firewall...  exiting" >&2 # If no Firewalld, ufw or iptables exit
	fi

}


# netstat_used_local_ports: get used tcp-ports
netstat_used_local_ports()
{
  netstat -atn \
    | awk '{printf "%s\n", $4}' \
    | grep -oE '[0-9]*$' \
    | sort -n \
    | uniq
}

# netstat_free_local_port: get one free tcp-port
netstat_free_local_port()
{  for port in $(seq 32768 61000); do
    for i in $(netstat_used_local_ports); do
      if [[ $used_port -eq $port ]]; then
        continue
      else
        echo "$port"
        return 0
      fi
    done
  done

  return 1
}

function get_ssh_pubkey() {
      local SSHPUBKEY="$(mktemp)"
      ssh-keygen -v -y -f "$1" > "${SSHPUBKEY}"
  /bin/cat "${SSHPUBKEY}"
}

# server: Start an HTTP server from a directory, optionally specifying the directory, on port 8000
#
# example  $ serve ~/ # would serve your home directory
# or
# 			$ serve   # would serve the location set for variable $FOLDER


#function serve ()
#{
#	local FOLDER="/run/media/nowhereman/5c272246-9fa8-4671-a436-966b50f58f86/nowhereman"
#	local CD_FOLDER="${1:-${FOLDER}}"
#	#free_port=$(netstat_free_local_port)
#	#port="${1:-${free_port}}"
#	allowport 8000
	#cd /run/media/nowhereman/5c272246-9fa8-4671-a436-966b50f58f86/nowhereman
#	cd $CD_FOLDER
#	python3 -m http.server
#}

serve() {
  if [[ "${1}" = "-h" ]]; then
    printf -- '%s\n' "Usage: serve [port(default: 8000)] [path(default: cwd)]"
    return 0
  fi
  local port="${1:-8000}"
	allowport "$port"
  httpModule=$( python -c 'import sys; print("http.server" if sys.version_info[:2] > (2,7) else "SimpleHTTPServer")' )
  trap 'kill -9 "${httpPid}"' SIGHUP SIGINT SIGTERM
  (
    cd "${2:-.}" || return 1
    case "${httpModule}" in
      (SimpleHTTPServer)
        python -c "import sys,BaseHTTPServer,SimpleHTTPServer; sys.tracebacklimit=0; httpd =BaseHTTPServer.HTTPServer(('', ${port}), SimpleHTTPServer.SimpleHTTPRequestHandler); httpd.serve_forever()"
        httpPid="$!"
      ;;
      (http.server)
        python -c "import sys,http.server,http.server,ssl,signal; signal.signal(signal.SIGINT, lambda x,y: sys.exit(0)); httpd = http.server.HTTPServer(('', ${port}), http.server.SimpleHTTPRequestHandler) ; httpd.serve_forever()"
        httpPid="$!"
      ;;
      (*)
        printf -- '%s\n' "No suitable python module could be found"
        return 1
      ;;
    esac
  )
}

function unserve ()
{
	#free_port=$(netstat_free_local_port)
	port="${1:-8000}"
	#ps auxf | grep http.server | head -n1 | awk '{ print $2 }' | xargs kill -9
	lsof -nti:"$port" | xargs kill -9
	blockport "$port"
}

function netinfo ()
{
echo "--------------- Network Information ---------------"
ifconfig | awk /'inet/ {print $2}' | head -n 1
#echo ""
#ifconfig | awk /'HWaddr/ {print $4,$5}'
echo "---------------------------------------------------"
}

#scpsend ()
#{
#scp -P PORTNUMBERHERE "$@"
#USERNAME@YOURWEBSITE.com:/var/www/html/pathtodirectoryonremoteserver/;
#}

function my_ip() # Get IP adress on ethernet.
{
    MY_IP=$(ip addr show dev enp1s0 | awk '/inet/ { print $2 } ' | head -n 1 | sed -e 's/\/24//' )
	echo "${MY_IP:-"Not connected"}"
}

function whatsmyip() {
    local myipv4="$(dig +short -4 @resolver1.opendns.com myip.opendns.com A)"
    local myipv6="$(dig +short -6 @resolver1.ipv6-sandbox.opendns.com myip.opendns.com AAAA)"
    local reverse="$(dig +short -4 -x "${myipv4}")"
    printf %b "${myipv4}\n${myipv6}\n${reverse}\n"
}

function proxy_on() {
    if [ -z ${HTTP_PROXY+http://127.0.0.1:8123/} ]; then
        failure "Proxy was not turned on."
        export HTTP_PROXY="http://127.0.0.1:8123"
    else
        success "Proxy will be set to '$HTTP_PROXY'.";
    fi
    export HTTPS_PROXY="$HTTP_PROXY"
    export SOCKS_PROXY="$HTTP_PROXY"
    export FTP_PROXY="$HTTP_PROXY"
    export ALL_PROXY="$HTTP_PROXY"
    export NO_PROXY="localhost,127.0.0.1,::1"
    env | grep --color=always -e _PROXY | sort
}

function proxy_off() {
    variables=("HTTP_PROXY" "HTTPS_PROXY" "ALL_PROXY" "FTP_PROXY" "SOCKS_PROXY")
    for i in "${variables[@]}"; do
	unset "$i"
    done
    env | grep --color=always -e _PROXY | sort
    success "Proxy turned off."
}

function proxy_switch() {
    success "Switching proxy to http://127.0.0.1:8118."
    export HTTP_PROXY="http://127.0.0.1:8118"
    proxy_on
}

function getoffline() {
    NET_DEVICES=$(sudo lshw -short -C net -quiet -sanitize | tail +3 | awk {'print $2'})
    for device in $NET_DEVICES; do
        timelimit -q -t 3 -T 5 sudo ifdown "${device}"
    done
}

function getonline() {
    sudo systemctl restart systemd-networkd
    sudo systemctl restart networking
    sudo systemctl restart NetworkManager
    NET_DEVICES=$(sudo lshw -short -C net -quiet -sanitize | tail +3 | awk {'print $2'})
    for device in $NET_DEVICES; do
        timelimit -q -t 3 -T 5 sudo dhclient "${device}"
        timelimit -q -t 3 -T 5 sudo ifup "${device}"
    done
    sudo systemctl restart dnsmasq
    sudo systemctl restart coredns
    sudo systemctl restart systemd-resolved
}

function sound() {
#	read -p "Volume level 0-200: " CHOICE
	pactl -- set-sink-volume 0 "$1"\%
}



function clone {
    if [ $# -eq 0 ]; then
        printf "Please enter a repo name or full URL:\n"
        read -r repo
        clone "$repo"
    elif [[ $1 == --help ]] || [[ $1 == --h ]] || [[ $1 == --? ]]; then
        printf "This will clone a git repo.\n\n"
        printf "Option 1: Provide just the name, e.g.:\n"
        printf "$ clone membership\n"
        printf "This will do: git clone https://github.com/phillip-kruger/membership.git\n\n"
        printf "Option 2: Provide the full URL\n"
        printf "$ clone https://github.com/smallrye/smallrye-rest-client.git\n"
        printf "This will do: git clone https://github.com/smallrye/smallrye-rest-client.git\n"
    else
        if [[ $1 == https://* ]] || [[ $1 == git://* ]] || [[ $1 == ssh://* ]]; then
            URL=$1
        else
            URL="https://github.com/w5alc/$1.git"
        fi

        printf "git clone %s\n" "$URL"
        git clone "$URL"
    fi
}
    export -f clone

gistpub()
{
	printf "Creating Public Gist from ""$1""\n"
	gh gist create "$@" -p
}

gistpriv()
{
	printf "Creating Private Gist from ""$1""\n"
	gh gist create "$@"
}

gistedit() {
  paste <(seq "$(gh gist list --limit 15 | wc -l)"; gh gist list --limit 15 | awk '{ print ") gh gist edit "$1 " ;;  # " $2 }') | pr -2 -t -s" "
  read -rp "Enter your choice: "
  case "${File}" in
    (*.tar.bz2) tar cjf "${File}" "$@"  ;;
    (*.tar.gz)  tar czf "${File}" "$@"  ;;
    (*.tgz)     tar czf "${File}" "$@"  ;;
    (*.zip)     zip "${File}" "$@"      ;;
    (*.rar)     rar "${File}" "$@"      ;;
    (*)         echo "Filetype not recognized" ;;
  esac
}

#######################################################
################ Begin gpg functions ##################
#######################################################

################################################################################
# genpasswd password generator
################################################################################
# Password generator function for when pwgen or apg arent available
# Koremutake mode inspired by:
# https:#raw.githubusercontent.com/lpar/kpwgen/master/kpwgen.go
# http://shorl.com/koremutake.php
genpasswd() {
  get-randint() {
  local nCount nMin nMax nMod randThres i xInt
  nCount="${1:-1}"
  nMin="${2:-1}"
  nMax="${3:-32767}"
  nMod=$(( nMax - nMin + 1 ))
  if (( nMod == 0 )); then return 3; fi
  # De-bias the modulo as best as possible
  randThres=$(( -(32768 - nMod) % nMod ))
  if (( randThres < 0 )); then
    (( randThres = randThres * -1 ))
  fi
  i=0
  while (( i < nCount )); do
    xInt="${RANDOM}"
    if (( xInt > ${randThres:-0} )); then
      printf -- '%d\n' "$(( xInt % nMod + nMin ))"
      (( i++ ))
    fi
  done
}
  export LC_CTYPE=C
  # localise variables for safety
  local OPTIND pwdChars pwdDigit pwdNum pwdSet pwdKoremutake pwdUpper \
    pwdSpecial pwdSpecialChars pwdSyllables n t u v tmpArray
  # Default the vars
  pwdChars=10
  pwdDigit="false"
  pwdNum=1
  pwdSet="[:alnum:]"
  pwdKoremutake="true"
  pwdUpper="false"
  pwdSpecial="false"
  # shellcheck disable=SC1001
  pwdSpecialChars=(\! \@ \# \$ \% \^ \( \) \_ \+ \? \> \< \~)
  # Filtered koremutake syllables
  # http:#shorl.com/koremutake.php
  pwdSyllables=( ba be bi bo bu by da de di 'do' du dy fe 'fi' fo fu fy ga ge \
    gi go gu gy ha he hi ho hu hy ja je ji jo ju jy ka ke ko ku ky la le li \
    lo lu ly ma me mi mo mu my na ne ni no nu ny pa pe pi po pu py ra re ri \
    ro ru ry sa se si so su sy ta te ti to tu ty va ve vi vo vu vy bra bre \
    bri bro bru bry dra dre dri dro dru dry fra fre fri fro fru fry gra gre \
    gri gro gru gry pra pre pri pro pru pry sta ste sti sto stu sty tra tre \
    er ed 'in' ex al en an ad or at ca ap el ci an et it ob of af au cy im op \
    co up ing con ter com per ble der cal man est 'for' mer col ful get low \
    son tle day pen pre ten tor ver ber can ple fer gen den mag sub sur men \
    min out tal but cit cle cov dif ern eve hap ket nal sup ted tem tin tro
  )
  while getopts ":c:DhKn:SsUY" Flags; do
    case "${Flags}" in
      (c)  pwdChars="${OPTARG}";;
      (D)  pwdDigit="true";;
      (h)  printf -- '%s\n' "" "genpasswd - a poor sysadmin's pwgen" \
             "" "Usage: genpasswd [options]" "" \
             "Optional arguments:" \
             "-c [Number of characters. Minimum is 4. (Default:${pwdChars})]" \
             "-D [Require at least one digit (Default:off)]" \
             "-h [Help]" \
             "-K [Koremutake mode.  Uses syllables rather than characters, meaning more phonetical pwds." \
             "    Note: In this mode, character counts = syllable count and different defaults are used]" \
             "-n [Number of passwords (Default:${pwdNum})]" \
             "-s [Strong mode, seeds a limited amount of special characters into the mix (Default:off)]" \
             "-S [Stronger mode, complete mix of characters (Default:off)]" \
             "-U [Require at least one uppercase character (Default:off)]" \
             "-Y [Require at least one special character (Default:off)]" \
             "" "Note1: Broken Pipe errors, (older bash versions) can be ignored" \
             "Note2: If you get umlauts, cyrillic etc, export LC_ALL= to something like en_US.UTF-8"
           return 0;;
      (K)  pwdKoremutake="true";;
      (n)  pwdNum="${OPTARG}";;
      # Attempted to randomise special chars using 7 random chars from [:punct:] but reliably
      # got "reverse collating sequence order" errors.  Seeded 9 special chars manually instead.
      (s)  pwdSet="[:alnum:]#$&+/<}^%@";;
      (S)  pwdSet="[:graph:]";;
      (U)  pwdUpper="true";;
      (Y)  pwdSpecial="true";;
      (\?)  printf -- '%s\n' "[ERROR] genpasswd: Invalid option: $OPTARG.  Try 'genpasswd -h' for usage." >&2
            return 1;;
      (:)  echo "[ERROR] genpasswd: Option '-$OPTARG' requires an argument, e.g. '-$OPTARG 5'." >&2
           return 1;;
    esac
  done
  # We need to check that the character length is more than 4 to protect against
  # infinite loops caused by the character checks.  i.e. 4 character checks on a 3 character password
  if (( pwdChars < 4 )); then
    printf -- '%s\n' "[ERROR] genpasswd: Password length must be greater than four characters." >&2
    return 1
  fi
  if [[ "${pwdKoremutake}" = "true" ]]; then
    for (( i=0; i<pwdNum; i++ )); do
      n=0
      for int in $(get-randint "${pwdChars:-7}" 1 $(( ${#pwdSyllables[@]} - 1 )) ); do
        tmpArray[n]=$(printf -- '%s\n' "${pwdSyllables[int]}")
        (( n++ ))
      done
      read -r t u v < <(get-randint 3 0 $(( ${#tmpArray[@]} - 1 )) | paste -s -)
      #pwdLower is effectively guaranteed, so we skip it and focus on the others
      if [[ "${pwdUpper}" = "true" ]]; then
        tmpArray[t]=$(capitalise "${tmpArray[t]}")
      fi
      if [[ "${pwdDigit}" = "true" ]]; then
        while (( u == t )); do
          u="$(get-randint 1 0 $(( ${#tmpArray[@]} - 1 )) )"
        done
        tmpArray[u]="$(get-randint 1 0 9)"
      fi
      if [[ "${pwdSpecial}" = "true" ]]; then
        while (( v == t )); do
          v="$(get-randint 1 0 $(( ${#tmpArray[@]} - 1 )) )"
        done
        randSpecial=$(get-randint 1 0 $(( ${#pwdSpecialChars[@]} - 1 )) )
        tmpArray[v]="${pwdSpecialChars[randSpecial]}"
      fi
      printf -- '%s\n' "${tmpArray[@]}" | paste -sd '\0' -
    done
  else
    for (( i=0; i<pwdNum; i++ )); do
      n=0
      while read -r; do
        tmpArray[n]="${REPLY}"
        (( n++ ))
      done < <(tr -dc "${pwdSet}" < /dev/urandom | tr -d ' ' | fold -w 1 | head -n "${pwdChars}")
      read -r t u v < <(get-randint 3 0 $(( ${#tmpArray[@]} - 1 )) | paste -s -)
      #pwdLower is effectively guaranteed, so we skip it and focus on the others
      if [[ "${pwdUpper}" = "true" ]]; then
        if ! printf -- '%s\n' "tmpArray[@]}" | grep "[A-Z]" >/dev/null 2>&1; then
          tmpArray[t]=$(capitalise "${tmpArray[t]}")
        fi
      fi
      if [[ "${pwdDigit}" = "true" ]]; then
        while (( u == t )); do
          u="$(get-randint 1 0 $(( ${#tmpArray[@]} - 1 )) )"
        done
        if ! printf -- '%s\n' "tmpArray[@]}" | grep "[0-9]" >/dev/null 2>&1; then
          tmpArray[u]="$(get-randint 1 0 9)"
        fi
      fi
      # Because special characters arent sucked up from /dev/urandom,
      # we have no reason to test for them, just swap one in
      if [[ "${pwdSpecial}" = "true" ]]; then
        while (( v == t )); do
          v="$(get-randint 1 0 $(( ${#tmpArray[@]} - 1 )) )"
        done
        randSpecial=$(get-randint 1 0 $(( ${#pwdSpecialChars[@]} - 1 )) )
        tmpArray[v]="${pwdSpecialChars[randSpecial]}"
      fi
      printf -- '%s\n' "${tmpArray[@]}" | paste -sd '\0' -
    done
  fi
}

################################################################################
# A separate password encryption tool, so that you can encrypt passwords of your own choice

cryptpasswd() {
  local inputPwd pwdSalt pwdKryptMode
  # If $1 is blank, print usage
  if [[ -z "${1}" ]]; then
    printf -- '%s\n' "" "cryptpasswd - a tool for hashing passwords" "" \
    "Usage: cryptpasswd [password to hash] [1|5|6|n]" \
    "    Crypt method can be set using one of the following options:" \
    "    '1' (MD5, default)" \
    "    '5' (SHA256)" \
    "    '6' (SHA512)" \
    "    'n' (NTLM)"
    return 0
  # Otherwise, assign our base variables
  else
    inputPwd="${1}"
    pwdSalt=$(tr -dc '[:alnum:]' < /dev/urandom | tr -d ' ' | fold -w 8 | head -n 1 | tolower) 2> /dev/null
  fi
  # We dont want to mess around with other options like bcrypt as it
  # requires more error handling than I can be bothered with
  # If the crypt mode isnt defined as 1, 5, 6 or n: default to 1
  case "${2}" in
    (n)
      printf -- '%s' "${inputPwd}" \
        | iconv -t utf16le \
        | openssl md4 \
        | awk '{print $2}' \
        | toupper
      return "$?"
    ;;
    (*)
      case "${2}" in
        (1|5|6) pwdKryptMode="${2}";;
        (*)     pwdKryptMode=1;;        # Default to MD5
      esac
      if get_command python; then
        #python -c 'import crypt; print(crypt.crypt('${inputPwd}', crypt.mksalt(crypt.METHOD_SHA512)))'
        python -c "import crypt; print crypt.crypt('${inputPwd}', '\$${pwdKryptMode}\$${pwdSalt}')"
      elif get_command perl; then
        perl -e "print crypt('${inputPwd}','\$${pwdKryptMode}\$${pwdSalt}\$')"
      elif get_command openssl; then
        printf -- '%s\n' "This was handled by OpenSSL which is only MD5 capable." >&2
        openssl passwd -1 -salt "${pwdSalt}" "${inputPwd}"
      else
        printf -- '%s\n' "No available method for this task" >&2
        return 1
      fi
    ;;
  esac
}

genphrase() {
  # Requires bash4 or newer and shuf
  # There is an older, more portable version of this available in my git history (pre 01/23)
  (( BASH_VERSINFO < 4 )) && {
    printf -- '%s\n' "genphrase(): bash 4 or newer required"
    return 1
  }
  command -v shuf >/dev/null 2>&1 || {
    printf -- '%s\n' "genphrase(): 'shuf' required but not found in PATH"
    return 1
  }
  # First, double check that the dictionary file exists.
  if [[ ! -f ~/.pwords.dict ]] ; then
    # Test if we can download our wordlist, otherwise use the standard 'words' file to generate something usable
    if ! wget -T 2 https://raw.githubusercontent.com/rawiriblundell/dotfiles/master/.pwords.dict -O ~/.pwords.dict &>/dev/null; then
      # Alternatively, we could just use grep -v "[[:punct:]]", but we err on the side of portability
      LC_COLLATE=C grep -Eh '^[A-Za-z].{3,9}$' /usr/{,share/}dict/words 2>/dev/null | grep -v "'" > ~/.pwords.dict
    fi
  fi
  # localise our vars for safety
  local OPTIND delimiter phrase_words phrase_num phrase_seed seed_word total_words
  # Default the vars
  delimiter='\0'
  phrase_words=4
  phrase_num=1
  phrase_seed="False"
  seed_word=
  while getopts ":d:hn:s:w:" Flags; do
    case "${Flags}" in
      (d) delimiter="${OPTARG}" ;;
      (h)
        printf -- '%s\n' "" "genphrase - a basic passphrase generator" \
          "" "Optional Arguments:" \
          "    -d Delimiter.  Note: Quote special chars. (Default: none)" \
          "    -h Help" \
          "    -n Number of passphrases to generate (Default: ${phrase_num})" \
          "    -s Seed your own word" \
          "    -w Number of random words to use (Default: ${phrase_words})" ""
        return 0
      ;;
      (n)  phrase_num="${OPTARG}" ;;
      (s)  phrase_seed="True"; seed_word="${OPTARG}" ;;
      (w)  phrase_words="${OPTARG}";;
      (:)
        printf -- "Option '%s' requires an argument. e.g. '%s 10'\n" "-${OPTARG}" "-${OPTARG}" >&2
        return 1
      ;;
      (*)
        printf -- "Unrecognised argument: '%s'\n" "-${OPTARG}.  Try 'genphrase -h' for usage." >&2
        return 1
      ;;
    esac
  done

  # Next test if a word is being seeded in, if so, make space for the seed word
  [[ "${phrase_seed}" = "True" ]] && (( phrase_words = phrase_words - 1 ))
  # Calculate the total number of words we might process
  total_words=$(( phrase_words * phrase_num ))

  # Now generate the passphrase(s)
  # Use 'shuf' to pull our complete number of random words from the dict
  # Use 'awk' to word wrap to '$phrase_words' per line
  # Then parse each line through this while loop
  while read -r; do
    # Convert the line to an array and add any seed word
    # This allows us to capitalise each word and randomise the seed location
    # shellcheck disable=SC2206 # We want REPLY to word-split
    lineArray=( ${seed_word} ${REPLY} )
    shuf -e "${lineArray[@]^}" | paste -sd "${delimiter}" -
  done < <(
    shuf -n "${total_words}" ~/.pwords.dict |
      awk -v w="${phrase_words}" 'ORS=NR%w?FS:RS'
    )
  return 0
}

function encrypt ()
{
# Use ascii armor
gpg -ac --no-options "$1"
}

function bencrypt ()
{
# No ascii armor
# Encrypt binary data. jpegs/gifs/vobs/etc.
gpg -c --no-options "$1"
}

function decrypt ()
{
gpg --no-options "$1"
}

pe() {
    # Passphrase encryption program
    # Created by Dave Crouse 01-13-2006
    # Reads input from a text editor and encrypts to screen.
    clear
    printf "Passphrase Encryption Program\n"
    printf "%s\n" "------------------------------"
    if [ -z "$EDITOR" ]; then
        read -rp "It appears that you do not have a text editor set in your .bashrc file. Enter the editor you would like to use: " EDITOR
        printf "\n"
    fi
    read -rp "Enter the name/comment for this message: " comment
   $EDITOR passphraseencryption
   gpg --armor --comment "$comment" --no-options --output passphraseencryption.gpg --symmetric passphraseencryption
    shred -u passphraseencryption
    clear
    printf "Outputting passphrase-encrypted message\n\n\n"
    cat passphraseencryption.gpg
    printf "\n\n"
    shred -u passphraseencryption.gpg
    read -rp "Hit enter to exit" temp
    clear
}

function encryptfile ()
{
zenity --title="zcrypt: Select a file to encrypt" --file-selection > zcrypt
encryptthisfile=$(cat zcrypt);rm zcrypt
# Use ascii armor
#  --no-options (for NO gui usage)
gpg -acq --yes "${encryptthisfile}"
zenity --info --title "File Encrypted" --text "$encryptthisfile has been
encrypted"
}

function decryptfile ()
{
zenity --title="zcrypt: Select a file to decrypt" --file-selection > zcrypt
decryptthisfile=$(cat zcrypt);rm zcrypt
# NOTE: This will OVERWRITE existing files with the same name !!!
gpg --yes -q "${decryptthisfile}"
zenity --info --title "File Decrypted" --text "$encryptthisfile has been
decrypted"
}

#######################################################
################## End gpg functions ##################
#######################################################

#######################################################
################ Start misc functions #################
#######################################################

remove_duplicates() {
    if [ -n "$1" ]; then
        find "$1" -type f -exec md5sum {} + | sort | uniq -w32 -dD
    else
        echo "Usage: remove_duplicates 'directory_path'"
    fi
}

function allcolors() {
    # credit to http://askubuntu.com/a/279014
    for x in 0 1 4 5 7 8; do
        for i in $(seq 30 37); do
            for a in $(seq 40 47); do
                echo -ne "\e[$x;$i;$a""m\\\e[$x;$i;$a""m\e[0;37;40m "
            done
            echo
        done
    done
    echo ""
}

function spin() {
	RED="\e[91m"
	WHITE="\e[97m"
	BLUE="\e[94m"
	NC="\e[0m"

    echo -ne "${RED}-"
    sleep 0.02
    echo -ne "${WHITE}|"
    sleep 0.02
    echo -ne "${BLUE}x"
    sleep 0.02
    echo -ne "${RED}+${NC}"
}

#######################################################
################## End misc functions #################
#######################################################

function overview() {
	du -h --max-depth=1 | sed -r '
		$d; s/^([.0-9]+[KMGTPEZY]\t)\.\//\1/
	' | sort -hr | column
}

#-------------------------------------------------------------
# Make the following commands run in background automatically:
#-------------------------------------------------------------

function te()  # wrapper around xemacs/gnuserv
{
    if [ "$(gnuclient -batch -eval t 2>&-)" == "t" ]; then
       gnuclient -q "$@";
    else
       ( xemacs "$@" &);
    fi
}

function soffice() { command soffice "$@" & }
function firefox() { command firefox "$@" & }
function xpdf() { command xpdf "$@" & }

#######################################################
################ Start file functions #################
#######################################################

compress() {
  File=$1
  shift
  case "${File}" in
    (*.tar.bz2) tar cjf "${File}" "$@"  ;;
    (*.tar.gz)  tar czf "${File}" "$@"  ;;
    (*.tgz)     tar czf "${File}" "$@"  ;;
    (*.zip)     zip "${File}" "$@"      ;;
    (*.rar)     rar "${File}" "$@"      ;;
    (*)         echo "Filetype not recognized" ;;
  esac
}

function maketarbz() {
    # export TAR_OPTS="--auto-compress --one-file-system --quoting-style='literal' --utc --verbose --deference --compress --totals=SIGQUIT --ignore-failed-read --seek --wildcards --no-acls --no-selinux --no-xattrs --verify"
    if [ -d "$1" ]; then
        local ARCHIVENAME=$(basename "$1.tar.bz2")
        export BZIP2="-9"; tar -pcvjf "${TAR_OPTS}" "$1" "${ARCHIVENAME}"
    fi
}

function maketargz() {
    # export TAR_OPTS="--auto-compress --one-file-system --quoting-style='literal' --utc --verbose --deference --compress --totals=SIGQUIT --ignore-failed-read --seek --wildcards --no-acls --no-selinux --no-xattrs --verify"
    if [ -d "$1" ]; then
        local ARCHIVENAME=$(basename "$1.tar.xz")
        export XZ_OPT="-9"; tar -zpcvf "${TAR_OPTS}" "$1" "${ARCHIVENAME}"
    fi
}

function maketarxz() {
    # export TAR_OPTS="--auto-compress --one-file-system --quoting-style='literal' --utc --verbose --deference --compress --totals=SIGQUIT --ignore-failed-read --seek --wildcards --no-acls --no-selinux --no-xattrs --verify"
    if [ -d "$1" ]; then
        local ARCHIVEDIR=$(basename "$1.tar.gz")
        export GZIP="-9"; tar -pcvJf  "${TAR_OPTS}" "$1" "${ARCHIVENAME}"
    fi
}

function newlines() {
    sed -i 's/\\n/\n/g' "$1"
}

function noblanklines() {
    sed -i '/^$/d' "$1"
}

function nocomments() {
    cat "$1" | egrep -v "(^#.*|^$)"
}

function noleading() {
    sed -i "s/^[ \t]*//" "$1"
}


# Find a file with a pattern in name:
function ff() { find . -type f -iname '*'"$*"'*' -ls ; }

# Find a file with pattern $1 in name and Execute $2 on it:
function fe() { find . -type f -iname '*'"${1:-}"'*' -exec "${2:-file}" {} \;  ; }

function f() {
    find . -not -iwholename '*.svn*' -not -iwholename '*.git*' -iname "*$1*"
}

function largefolders() {
    if [ -z "$1" ]; then
        local searchpath="$(pwd)"
    else
        local searchpath="$1"
    fi
    sudo find "${searchpath}" -xdev -maxdepth 5 -type d -print0 | xargs -0 du -bx --max-depth=5 2>/dev/null | perl -M'Number::Bytes::Human format_bytes' -lane 'my $SIZE = format_bytes ($F[0], bs=>1000, round_style => 'round', quiet => 1, precision => 2); shift @F; print $SIZE . "\t@F";' | sort -rh | head -20
}


#  Find a pattern in a set of files and highlight them:
#+ (needs a recent version of egrep).
function fstr()
{
    OPTIND=1
    local mycase=""
    local usage="fstr: find string in files.
Usage: fstr [-i] \"pattern\" [\"filename pattern\"] "
    while getopts :it opt
    do
        case "$opt" in
           i) mycase="-i " ;;
           *) echo "$usage"; return ;;
        esac
    done
    shift $(( $OPTIND - 1 ))
    if [ "$#" -lt 1 ]; then
        echo "$usage"
        return;
    fi
    find . -type f -name "${2:-*}" -print0 | xargs -0 egrep --color=always -sn "${case}" "$1" 2>&- | more

}


function swap() {
    # Swap 2 filenames around, if they exist (from Uzis bashrc).
    local TMPFILE=tmp.$$

    [ $# -ne 2 ] && printf "swap: 2 arguments needed\n" && return 1
    [ ! -e "$1" ] && printf "swap: %s does not exist\n" "$1" && return 1
    [ ! -e "$2" ] && printf "swap: %s does not exist\n" "$2" && return 1

    mv "$1" "$TMPFILE"
    mv "$2" "$1"
    mv "$TMPFILE" "$2"
}


function extract {
    if [ -z "$1" ]; then
        # display usage if no parameters given
        printf "Usage: extract <path/file_name>.<zip|rar|bz2|gz|tar|tbz2|tgz|Z|7z|xz|ex|tar.bz2|tar.gz|tar.xz|.zlib|.cso>\n"
        printf "       extract <path/file_name_1.ext> [path/file_name_2.ext] [path/file_name_3.ext]\n"
    else
        for n in "$@"; do
            if [ -f "$n" ]; then
                case "${n%,}" in
                    *.cbt | *.tar.bz2 | *.tar.gz | *.tar.xz | *.tbz2 | *.tgz | *.txz | *.tar)
                        tar xvf "$n" ;;
                    *.lzma) unlzma ./"$n" ;;
                    *.bz2) bunzip2 ./"$n" ;;
                    *.cbr | *.rar) unrar x -ad ./"$n" ;;
                    *.gz) gunzip ./"$n" ;;
                    *.cbz | *.epub | *.zip) unzip ./"$n" ;;
                    *.z) uncompress ./"$n" ;;
                    *.7z | *.apk | *.arj | *.cab | *.cb7 | *.chm | *.deb | *.dmg | *.iso | *.lzh | *.msi | *.pkg | *.rpm | *.udf | *.wim | *.xar)
                        7z x ./"$n" ;;
                    *.xz) unxz ./"$n" ;;
                    *.exe) cabextract ./"$n" ;;
                    *.cpio) cpio -id < ./"$n" ;;
                    *.cba | *.ace) unace x ./"$n" ;;
                    *.zpaq) zpaq x ./"$n" ;;
                    *.arc) arc e ./"$n" ;;
                    *.cso) ciso 0 ./"$n" ./"$n.iso" && extract "$n.iso" && \rm -f "$n" ;;
                    *.zlib)
                        zlib-flate -uncompress < ./"$n" > ./"$n.tmp" && \
                        mv ./"$n.tmp" ./"${n%.*zlib}" && rm -f "$n" ;;
                    *)
                        printf "extract: '$n' - unknown archive method\n"
                        return 1 ;;
                esac
            else
                printf "'$n' - file doesn't exist\n"
                return 1
            fi
        done
    fi
}



# Creates an archive (*.tar.gz) from given directory.
function maketar() { tar cvzf "${1%%/}.tar.gz"  "${1%%/}/"; }

# Create a PW-Protected ZIP archive of a file or folder.
function makezip() { zip -e "${1%%/}.zip" "$1" ; }

# Make your directories and files access rights sane.
function sanitize() { chmod -R u=rwX,g=rX,o= "$@" ;}

function compare_dirs() {
    diff --brief --recursive "$1" "$2"
}

function bytestohuman() {
    b=${1:-0}; d=''; s=0; S=(Bytes {K,M,G,T,P,E,Z,Y}iB)
    while ((b > 1024)); do
        d="$(printf ".%02d" $((b % 1024 * 100 / 1024)))"
        b=$((b / 1024))
        (( s++ ))
    done
    echo "$b$d ${S[$s]}"
}

#######################################################
################# End file functions ##################
#######################################################


#-------------------------------------------------------------
# Process/system related functions:
#-------------------------------------------------------------


function my_ps() { ps "$@" -u "$USER" -o pid,%cpu,%mem,bsdtime,command ; }
function pp() { my_ps f | awk '!/awk/ && $0~var' var="${1:-".*"}" ; }


function killps()   # kill by process name
{
    local pid pname sig="-TERM"   # default signal
    if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
        echo "Usage: killps [-SIGNAL] pattern"
        return;
    fi
    if [ $# = 2 ]; then sig=$1 ; fi
    for pid in $(my_ps| awk '!/awk/ && $0~pat { print $1 }' pat=${!#} )
    do
        pname=$(my_ps | awk '$1~var { print $5 }' var="$pid" )
        if ask "Kill process $pid <$pname> with signal $sig?"
            then kill "$sig" "$pid"
        fi
    done
}

function mydf()         # Pretty-print of 'df' output.
{                       # Inspired by 'dfc' utility.
    for fs ; do

        if [ ! -d "$fs" ]
        then
          echo -e "$fs"" :No such file or directory" ; continue
        fi

        local info=( $(command df -P "$fs" | awk 'END{ print $2,$3,$5 }') )
        local free=( $(command df -Pkh "$fs" | awk 'END{ print $4 }') )
        local nbstars=$(( 20 * ${info[1]} / ${info[0]} ))
        local out="["
        for ((j=0;j<20;j++)); do
            if [ ${j} -lt ${nbstars} ]; then
               out=$out"*"
            else
               out=$out"-"
            fi
        done
        out=${info[2]}" "$out"] ("$free" free on "$fs")"
        echo -e "$out"
    done
}



function ii() {
    printf "\nYou are logged on: %s\n" "$(hostname)"
    printf "\nAdditional information: %s\n" "$(uname -a | awk '{ print $1,$3,$15,$16 }')"
    printf "\nUsers logged on: %s\n" "$(w -hs | cut -d ' ' -f1 | sort | uniq)"
    printf "\nCurrent date : %s\n" "$(date)"
    printf "\nMachine stats : %s\n" "$(uptime -p)"
    printf "\nMemory stats : %s\n" "$(free -h)"
    printf "\nDiskspace : %s\n" "$(mydf /run/media/nowhereman/5c* "$HOME")"
    printf "\nLocal IP Address : %s\n" "$(my_ip)"
    printf "\nOpen connections : %s\n" "$(sudo netstat -pan --inet)"

}

#######################################################
############## Start systemd functions ################
#######################################################

function reload() {
    sudo systemctl reload "$1"
}

function restart() {
    local PROGRAM="$1"
    if confirm "restart ${PROGRAM}" -eq 0; then
        sudo systemctl restart "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Restarted ${PROGRAM}." || failure "Failed to restart ${PROGRAM}."
    else
        failure "No action taken."
    fi
}

function start() {
    local PROGRAM="$1"
    if confirm "start ${PROGRAM}" -eq 0; then
        sudo systemctl start "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Started ${PROGRAM}." || failure "Failed to start ${PROGRAM}."
    else
        failure "No action taken."
    fi
}
function disable() {
    local PROGRAM="$1"
    if confirm "disable ${PROGRAM}" -eq 0; then
	sudo systemctl disable "${PROGRAM}"
	local EXITSTATUS="$?"
	sleep 1s
	[[ ${EXITSTATUS} == 0 ]] && success "Disabled ${PROGRAM}." || failure "Failed to disable ${PROGRAM}."
    else
	failure "No action taken."
    fi
}

function enable() {
    local PROGRAM="$1"
    if confirm "enable ${PROGRAM}" -eq 0; then
        sudo systemctl enable "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Enabled ${PROGRAM}." || failure "Failed to enable ${PROGRAM}."
    else
        failure "No action taken."
    fi
}

function status() {
    sudo systemctl status "$1"
}

function stop() {
    local PROGRAM="$1"
    if confirm "stop ${PROGRAM}" -eq 0; then
        sudo systemctl stop "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Stopped ${PROGRAM}." || failure "Failed to stop ${PROGRAM}."
    else
        failure "No action taken."
    fi
}

function confirm() {
    read -p "Are you sure you want to $1? (y/n): " -n 1 -r REPLY
	echo -e "\n"
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		return 0
	else
		return 1
	fi
}

function failure() {
    ERR="$1"
    echo -e "\e[01;31m* $ERR\e[0m" 1>&2
}

function success() {
    MSG="$1"
    echo -e "\e[01;32m* $MSG\e[0m"
}


#######################################################
############### End systemd functions #################
#######################################################

function topfile
{
	BASEDIR=$1
	TOP=$2
	find "$BASEDIR" -xdev -type f -ls |sort -k 7 -r -n | head -"$TOP" |awk '{size=$7/1024/1024; printf("%dMb %s\n", size,$11);}'
}

function topdir
{
    BASEDIR=$1
    TOP=$2
	du -alx "$BASEDIR" | sort -n -r | head -n "$TOP" | awk '{size=$1/1024/1024; printf("%dMb %s\n", size,$2);}'
}

function ansibleSetup()
{
    ansible "$1" -m setup > ~/"$1".txt
}
alias accio=ansibleSetup

function gsay() {
    if command -v mplayer &>/dev/null; then
        local player="mplayer"
    elif command -v vlc &>/dev/null; then
        local player="vlc"
    else
        echo "Error: No suitable media player found (mplayer or vlc required)." >&2
        return 1
    fi

    if [[ "${1}" =~ -[a-z][a-z] ]]; then
        local lang=${1#-}
        local text="${*#"$1"}"
    else
        local lang=${LANG%_*}
        local text="$*"
    fi

    local encoded_text=$(printf "%s" "$text" | jq -s -R -r @uri)

    case $player in
        "mplayer")
            $player "http://translate.google.com/translate_tts?ie=UTF-8&tl=${lang}&q=${encoded_text}"
            ;;
        "vlc")
            $player "http://translate.google.com/translate_tts?ie=UTF-8&tl=${lang}&q=${encoded_text}" vlc://quit
            ;;
    esac
}

function encodemp3() {
    local FULLPATH=$(readlink -e "$1")
    local INPUTMEDIA=$(basename "$1")
    local FNAME=$(echo "${INPUTMEDIA}" | cut -d'.' -f1)
    local DESTDIR=$(dirname "${FULLPATH}")
    ffmpeg -i "$1" -vn -ab 128k -acodec libmp3lame -ar 44100 -y "${DESTDIR}/${FNAME}.mp3"
}

function freespace() {
    local CWD=$(pwd)
    mapfile -t BIGFILES< <(find "${CWD}" -xdev -type f -size +50M -printf  '%s\t%k\t%p\n' | numfmt --field=1 --from=iec --to=si --padding=8 | sort -rh | tail -100)
    for f in "${BIGFILES[@]}"; do
        local FNAME="$(echo "$f" | cut -d' ' -f3)"
        local FSIZEKB="$(echo "$f" | cut -d' ' -f2)"
        read -p "\nPress 'y' to delete ${FNAME}, 'm' to move it to another directory, and 'k' to keep: " -n 1 -r REPLY
        if [[ $REPLY =~ ^[Mm]$ ]]; then
            read -e -p "\nEnter new destination for ${FNAME}: " -n 64 -r DESTDIR
            if [[ -d "${DESTDIR}" ]]; then
                local FREESPACE="$(df -k --sync "${DESTDIR}" | awk '{ print $4 }' | tail -n 1| cut -d'%' -f1)"
                declare -i REMAINING=$(($FREESPACE - $FSIZEKB))
                if [[ "${REMAINING}" -gt 1024 ]]; then
                    local REMAINING_HUMAN_READABLE=$(printf '%dK\t' "${REMAINING}" | numfmt --field=1 --format="%-10f" --zero-terminated --from=auto --to=iec --padding=8)
                    success "\nThere will be ${REMAINING_HUMAN_READABLE} kilobytes left available on that filesystem after migrating the file..."
                    sudo mv -ivun -t "${DESTDIR}/" "${FNAME}" &
                fi
            fi
        elif [[ $REPLY =~ ^[Kk]$ ]]; then
            success "\nKeeping ${FSIZEKB} ${FNAME} where it's located."
        elif [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm --preserve-root=all --one-file-system -rfvi "${FNAME}"
        fi
    done
    for job in $(jobs -p); do
        wait -n "$job"
    done
}

function pdfshrink() {
    local input=$1
    local output=$2
    if [ -e "$1" ]; then
        gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.6 -dPDFSETTINGS=/ebook -dNOPAUSE -dQUIET -dBATCH -sOutputFile="$2" "$1"
    fi
}

trendsetter()  # Create files for Trendsetter plate making process
{
	gs -sDEVICE=tiffsep1 -dNOPAUSE -dBATCH -dSAFER -r1200x1200 -dCOLORSCREEN -dDITHERPPI=85 -sOutputFile="$2"_%02d.tif "$1"
}

graypdf() {
    find . -name "*.pdf" \
        | grep -v "$(find . -name "*.pdf" | grep "$(find . -name "*gray.pdf" | sed 's|-gray.pdf|.pdf|g')")" \
        | grep -v gray.pdf \
        | while read -r file; do
            graypdf_run "$file"
        done
}

graypdf_run() {
    local input="$1"
    local output="${input%.*}-gray.pdf"
    
    if [ -e "$input" ]; then
        gs -sDEVICE=pdfwrite -sColorConversionStrategy=Gray -dProcessColorModel=/DeviceGray -dCompatibiltyLevel=1.4 -dNOPAUSE -dBATCH -sOutputFile="$output" "$input"
    fi
}

function qt_switch() {
    read -p "Do you want to use 5.11.3, 5.12.6, 5.13.2, 5.14.0 (1, 2, 3 or 4)?: " -n 1 -r REPLY
    echo "REPLY IS: ${REPLY}\n"
    if [[ $REPLY =~ ^[1] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.11.3/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.11.3/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.11.3/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.11.3/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.11.3/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.11.3/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.11.3/gcc_64/plugins
        success "QT has been set to 5.11.3."
    elif [[ $REPLY =~ ^[2] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.12.6/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.12.6/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.12.6/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.12.6/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.12.6/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.12.6/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.12.6/gcc_64/plugins
        success "QT has been set to 5.12.6."
    elif [[ $REPLY =~ ^[3] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.13.2/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.13.2/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.13.2/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.13.2/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.13.2/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.13.2/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.13.2/gcc_64/plugins
        success "QT has been set to 5.13.2."
    elif [[ $REPLY =~ ^[4] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.14.0/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.14.0/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.14.0/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.14.0/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.14.0/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.14.0/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.14.0/gcc_64/plugins
        success "QT has been set to 5.14.0."
    fi
   env | grep --color=always -e '^QT' | sort
}

function repackdeb() {
    if [ -e "$1" ]; then
        dpkg-deb -I "$1"
    fi
    export DPKGTMPDIR="$(mktemp -d)"
    export DEBARCHIVE="$(basename "$1")"
    export FULLPATH="$(readlink -e "$1")"
    export DPKGDEST="$(dirname "$FULLPATH")"
    export NEWDEBARCHIVE=$(printf '%s\n' "${DEBARCHIVE%.deb}_repacked.deb")
    # trap "rm -rf ${DPKGTMPDIR}" EXIT
    mkdir -pv "${DPKGTMPDIR}"
    fakeroot sh -c 'dpkg-deb -RvD "${FULLPATH}" "${DPKGTMPDIR}"; exit'
    # guake -n guake -e 'cd ${DPKGTMPDIR}; ls -lrt ${DPKGTMPDIR}' guake -r 'dpkg editing session'
    read -n 1 -s -r -p "${DEBARCHIVE} extracted to ${DPKGTMPDIR}. Press Enter when finished making modifications."
    fakeroot sh -c 'dpkg-deb -bvD "${DPKGTMPDIR}" "${DPKGDEST}/${NEWDEBARCHIVE}"'
    debdiff "${FULLPATH}" "${DPKGDEST}/${NEWDEBARCHIVE}"
    rm -rf "${DPKGTMPDIR}"
}

rpmextract() {
    if [ -z "$1" ]; then
        echo "Usage: rpmextract <RPM_FILE>"
        return 1
    fi

    local RPMFILE="$1"

    if [ ! -e "$RPMFILE" ]; then
        echo "Error: RPM file not found: $RPMFILE"
        return 1
    fi

    rpm2cpio "$RPMFILE" | cpio -idmv || {
        echo "Error: Extraction failed for $RPMFILE"
        return 1
    }
}

function viewlog() {
    if [ -z "$1" ]; then
        sudo journalctl -e --output json-pretty
    else
        sudo journalctl --output json-pretty -e -u "$1"
    fi
}

function wine_switch() {
    read -p "Do you want to set Wine to 32-bit or 64-bit? (32/64): " -n 3 -r REPLY
    echo "REPLY IS: ${REPLY}\n"
    if [[ $REPLY =~ ^[32.*] ]]; then
        export WINEARCH="win32"
        export WINEPREFIX="/media/data/wine32"
        export WINE="/opt/wine32/bin/wine"
        export WINESERVER="/opt/wine32/bin/wineserver"
        export WINELOADER="/opt/wine32/bin/wine-preloader"
        export WINEDEBUG="-all"
        # export WINEDLLPATH="/opt/wine32/lib:/usr/lib/x86_64-linux-gnu/wine"
        success "Wine has been set to 32-bit."
        echo -e "winetricks commands: dlls fonts settings winecfg regedit taskmgr explorer uninstaller shell folder annihilate\n"
        # sudo setcap cap_net_raw+epi /opt/wine32/bin/wine-preloader
        nohup winetricks --country=US --torify arch=32 prefix=win32 taskmgr >/dev/null 2>&1
    elif [[ $REPLY =~ ^[64.*] ]]; then
        export WINEARCH="win64"
        export WINEPREFIX="/media/data/wine"
        export WINE="/opt/wine64/bin/wine64"
        export WINESERVER="/opt/wine64/bin/wineserver64"
        export WINELOADER="/opt/wine64/bin/wine64-preloader"
        export WINEDEBUG="-all"
        # export WINEDLLPATH="/opt/wine64/lib64:/opt/wine64/lib:/usr/lib/x86_64-linux-gnu/wine"
        success "Wine has been set to 64-bit."
        echo -e "winetricks commands: dlls fonts settings winecfg regedit taskmgr explorer uninstaller shell folder annihilate\n"
        # sudo setcap cap_net_raw+epi /opt/wine64/bin/wine-preloader /opt/wine64/bin/wine64-preloader
        nohup winetricks --country=US --torify arch=64 prefix=wine taskmgr >/dev/null 2>&1
   fi
   env | grep --color=always -e '^WINE' | sort
}



function repeat()       # Repeat n times command.
{
    local i max
    max=$1; shift;
    for ((i=1; i <= max ; i++)); do  # --> C-like syntax
        eval "$@";
    done
}


function ask()          # See 'killps' for example of use.
{
    echo -n "$@" '[y/n] ' ; read ans
    case "$ans" in
        y*|Y*) return 0 ;;
        *) return 1 ;;
    esac
}

#######################################################
############### SPECIAL FUNCTIONS #####################
#######################################################

function activedisplay() {
    # mapfile -t SESSIONS< <(loginctl list-sessions --nolegend | awk {'print $1'})
    local DISP="$(\ps -u $(id -u) -o pid= | xargs -I{} cat /proc/{}/environ 2>/dev/null | tr '\0' '\n' | grep -m1 '^DISPLAY=')"
    printf "%s\n" "${DISP}"
}

function functions() {
    if [ "$#" -gt 0 ]; then
        for f in "$@"; do
             declare -F "$f" && typeset -f "$f"
        done
    else
        typeset -F | grep -v '^declare -f _'
    fi
}

function mach() {
    printf "\nMachine information:\n%s\n" "$(uname -a)"
    printf "\nUsers logged on:\n%s\n" "$(w -h)"
    printf "\nCurrent date:\n%s\n" "$(date)"
    printf "\nMachine status:\n%s\n" "$(uptime)"
    printf "\nMemory status:\n%s\n" "$(free -h)"
    printf "\nFilesystem status:\n%s\n" "$(df -h)"
}



#######################################################
############### SPECIAL FUNCTIONS #####################
#######################################################



function dirsize ()
{
du -shx * .[a-zA-Z0-9_]* 2> /dev/null | \
egrep '^ *[0-9.]*[MG]' | sort -n > /tmp/list
egrep '^ *[0-9.]*M' /tmp/list
egrep '^ *[0-9.]*G' /tmp/list
rm /tmp/list
}

#shot - takes a screenshot of your current window
function shot ()
{
import -frame -strip -quality 100 "$HOME/$(date +%T).png"
}

# cd and ls in one
function cl()
{
    dir=$1
    if [[ -z "$dir" ]]; then
        dir=$HOME
    fi
    if [[ -d "$dir" ]]; then
        cd "$dir"
        ls
    else
        echo "bash: cl: '$dir': Directory not found"
    fi
}


#######################################################
############### SPECIAL FUNCTIONS #####################
#######################################################
generateqr ()
{
printf "$@" | curl -F-=\<- qrenco.de
}

ryt() {
    cleanup() {
        printf "\nInterrupted. Exiting...\n"
        exit 1
    }

    trap cleanup INT

    if [ -f "$1" ]; then
        pv -qL $[11+(-1 + RANDOM%5)] < "$1"
    else
        printf '%s\n' "$@" | pv -qL $[11+(-1 + RANDOM%5)];
    fi

    trap - INT  # Remove the trap after execution
    printf "\n"
}




# Function to indent text by n spaces (default: 2 spaces)
indent() {
  local identWidth
  identWidth="${1:-2}"
  identWidth=$(eval "printf -- '%.0s ' {1..${identWidth}}")
  sed "s/^/${identWidth}/" "${2:-/dev/stdin}"
}

# Indent code by four spaces, useful for posting in markdown
codecat() { indent 4 "${1}"; }

# A function to print a specific line from a file
# TO-DO: Update it to handle globs e.g. 'printline 4 *'
printline() {
  # Fail early: We require sed
  if ! command -v sed >/dev/null 2>&1; then
    printf -- '%s\n' "[ERROR] printline: This function depends on 'sed' which was not found." >&2
    return 1
  fi

  # If $1 is empty, print a usage message
  # Otherwise, check that $1 is a number, if it isnt print an error message
  # If it is, blindly convert it to base10 to remove any leading zeroes
  case "${1}" in
    (''|-h|--help|--usage|help|usage)
      printf -- '%s\n' "Usage:  printline n [file]" ""
      printf -- '\t%s\n' "Print the Nth line of FILE." "" \
        "With no FILE or when FILE is -, read standard input instead."
      return 0
    ;;
    (*[!0-9]*)
      printf -- '%s\n' "[ERROR] printline: '${1}' does not appear to be a number." "" \
        "Run 'printline' with no arguments for usage." >&2
      return 1
    ;;
    (*) local lineNo="$((10#${1})){p;q;}" ;;
  esac

  # Next, we handle $2.  First, we check if its a number, indicating a line range
  if (( "${2}" )) 2>/dev/null; then
    # Stack the numbers in lowest,highest order
    if (( "${2}" > "${1}" )); then
      lineNo="${1},$((10#${2}))p;$((10#${2}+1))q;"
    else
      lineNo="$((10#${2})),${1}p;$((${1}+1))q;"
    fi
    shift 1
  fi

  # Otherwise, we check if its a readable file
  if [[ -n "${2}" ]]; then
    if [[ ! -r "${2}" ]]; then
      printf -- '%s\n' "[ERROR] printline: '$2' does not appear to exist or I can't read it." "" \
        "Run 'printline' with no arguments for usage." >&2
      return 1
    else
      local file="${2}"
    fi
  fi

  # Finally after all that testing and setup is done
  sed -ne "${lineNo}" -e "\$s/.*/[ERROR] printline: End of stream reached./" -e '$ w /dev/stderr' "${file:-/dev/stdin}"
}

# GUI-paginated man pages
# Inspired by the discussion here https://news.ycombinator.com/item?id=25304257
pman() {
  local mantext
  case "$(uname -s)" in
    (Darwin) man -t "${@}" | ps2pdf - - | open -g -f -a Preview ;;
    (Linux)
      mantext=$(mktemp)
      man -t "${@}" | ps2pdf - > "${mantext}"
      (
        atril "${mantext}"
        rm -f "${mantext}" 2>/dev/null
      )
    ;;
  esac
}

# 'redo' the last command, optionally with search and replace
# Usage:
# redo <-- Invokes the last command
# redo foo bar <-- last command, replaces first instance of 'foo' with 'bar'
# redo -g foo bar <-- last command, replaces all instances of 'foo' with 'bar'
redo() {
  local last_cmd match_str replace_str
  # Ensure that 'redo' calls aren't put into our command history
  # This prevents 'redo' from 'redo'ing itself.  Which is a sin.  Repent etc.
  case "${HISTIGNORE}" in
    (*redo\**) : ;;
    (*)
      printf -- '%s\n' "Adding 'redo*' to HISTIGNORE.  Please make this permanent" >&2
      export HISTIGNORE="${HISTIGNORE}:redo*"
    ;;
  esac
  case "${1}" in
    ('')
      fc -s
    ;;
    (-h|--help)
      printf -- '%s\n' \
        "'redo' the last command, optionally with search and replace" \
        "Usage:" \
        "redo <-- Invokes the last command" \
        "redo foo bar <-- last command, replaces first instance of 'foo' with 'bar'" \
        "redo -g foo bar <-- last command, replaces all instances of 'foo' with 'bar'"
    ;;
    (-g|--global)
      shift 1
      match_str="${1:?Search parameter missing}"
      replace_str="${2:?Replacement parameter missing}"
      fc -s "${match_str}"="${replace_str}"
    ;;
    (*)
      last_cmd=$(fc -l -- -1  | cut -d ' ' -f2-)
      match_str="${1:?Search parameter missing}"
      replace_str="${2:?Replacement parameter missing}"
      ${last_cmd/$match_str/$replace_str}
    ;;
  esac
}

# A function to repeat an action any number of times
repeat() {
  # check that $1 is a digit, if not error out, if so, set the repeatNum variable
  case "${1}" in
    (*[!0-9]*|'') printf -- '%s\n' "[ERROR]: '${1}' is not a number.  Usage: 'repeat n command'"; return 1;;
    (*)           local repeatNum=$1;;
  esac
  # shift so that the rest of the line is the command to execute
  shift

  # Run the command in a while loop repeatNum times
  for (( i=0; i<repeatNum; i++ )); do
    "$@"
  done
}

# Create the file structure for an Ansible role
rolesetup() {
  if [[ -z "${1}" ]]; then
    printf -- '%s\n' "rolesetup - setup the file structure for an Ansible role." \
      "By default this creates into the current directory" \
      "and you can recursively copy the structure from there." "" \
      "Usage: rolesetup rolename" ""
    return 1
  fi

  if [[ ! -w . ]]; then
    printf -- '%s\n' "Unable to write to the current directory"
    return 1
  elif [[ -d "${1}" ]]; then
    printf -- '%s\n' "The directory '${1}' seems to already exist!"
    return 1
  else
    mkdir -p "${1}"/{defaults,files,handlers,meta,templates,tasks,vars}
    (
      cd "${1}" || return 1
      for dir in defaults files handlers meta templates tasks vars; do
        printf -- '%s\n' "---" > "${dir}/main.yml"
      done
    )
  fi
}


graysize()
{
printf "Starting size: $(bytestohuman "$(stat -c "%s" $(find . -name '*gray.pdf' | sed 's|-gray.pdf|.pdf|') | awk '{ sum += $1 } END { print sum }')")\nEnding size:  $(bytestohuman "$(stat -c "%s" $(find . -name '*gray.pdf') | awk '{ sum += $1 } END { print sum }')")\n"; printf "Space saved: "; bytestohuman $(printf $(($(stat -c "%s" $(find . -name '*gray.pdf' | sed 's|-gray.pdf|.pdf|') | awk '{ sum += $1 } END { print sum }')-$(stat -c "%s" $(find . -name '*gray.pdf') | awk '{ sum += $1 } END { print sum }'))))
}

fire()
{
echo "Find and replace in current directory!"
echo "File pattern to look for? (eg '*.txt')"
read filepattern
echo "Existing string?"
read existing
echo "Replacement string?"
read replacement
echo "Replacing all occurences of $existing with $replacement in files matching $filepattern"

find . -type f -name "$filepattern" -print0 | xargs -0 sed -i -e "s/$existing/$replacement/g"
}

## Search list of your aliases and functions
function faf() {
    CMD=$(
        (
            (alias)
            (functions | grep "()" | cut -d ' ' -f1 | grep -v "^_" )
        ) | fzf | cut -d '=' -f1
    );

    eval "$CMD"
}

function fff(){
  local file=$(fzf --multi --reverse) #get file from fzf
  if [[ $file ]]; then
    for prog in $(echo "$file"); #open all the selected files
    do $EDITOR "$prog"; done;
  else
    echo "cancelled fzf"
  fi
}

function ftf() {
   local file
   local dir
   file=$(fzf +m -q "$1") && dir=$(dirname "$file") && cd "$dir"
   ls
}

function fkp() {
  local pid
  pid=$(ps -ef | sed 1d | fzf -m | awk '{print $2}')

  if [ "x$pid" != "x" ]
  then
    echo "$pid" | xargs kill -"${1:-9}"
  fi
}

#Enhanced rm
function frm() {
  if [[ "$#" -eq 0 ]]; then
    local files
    files=$(find . -maxdepth 1 -type f | fzf --multi)
    echo "$files" | xargs -I '{}' rm {} #we use xargs so that filenames to capture filenames with spaces in them properly
  else
    command rm "$@"
  fi
}

function fd() {
    if [[ "$#" != 0 ]]; then
        builtin cd "$@";
        return
    fi
    while true; do
        local lsd=$(echo ".." && ls -p | grep '/$' | sed 's;/$;;')
        local dir="$(printf '%s\n' "${lsd[@]}" |
            fzf --reverse --preview '
                __cd_nxt="$(echo {})";
                __cd_path="$(echo $(pwd)/${__cd_nxt} | sed "s;//;/;")";
                echo $__cd_path;
                echo;
                ls -p --color=always "${__cd_path}";
        ')"
        [[ ${#dir} != 0 ]] || return 0
        builtin cd "$dir" &> /dev/null
    done
}

nmapfast() {
  # Prompt the user for the target IP address or hostname
  read -p "Enter the target IP address or hostname: " target

  # Validate the target IP address or hostname
  if [[ -z "$target" ]]; then
    printf "Error: Target IP address or hostname is required\n"
    return 1
  fi

  # Create a temporary file to store the Nmap output
  nmap_output=$(mktemp)

  # Perform a fast Nmap scan with the specified options
  nmap_command="sudo nmap -n -sS -Pn -T4 --min-rate 1000 -p- -v $target -oN $nmap_output"
  $nmap_command | sed -u 's|[0-9]\+/tcp|\033[1;32m&\033[0m|'

  # Extract the open port numbers from the Nmap output
  ports=$(awk '/^[1-9]/ {print $1}' "$nmap_output" | paste -sd "," -)

  # Print headers and separators for readability
  printf "\n=======================================\n\n"
  printf "    PORTS\n    -----  \033[1;31m\n    %s\033[0;00m\n\n" "$ports"

  # Perform a detailed Nmap scan on the open ports using the grc command if available
  if [[ -n "$ports" ]]; then
    if command -v grc &>/dev/null; then
      grc_command="grc nmap -n -Pn -sT -p$ports -sC -sV $target"
      $grc_command || printf "Warning: Error executing Nmap with grc. Running without grc.\n"
    else
      printf "Warning: grc is not installed. Installing it might enhance the output.\n"
      $nmap_command
    fi
  else
    printf "No open ports found\n"
  fi

  # Print a separator
  printf "\n=======================================\n\n"

  # Perform a UDP scan on the top 100 ports
  nmap_udp_command="sudo nmap -n -Pn -sU --top-ports 100 -v $target"
  $nmap_udp_command | sed -u 's|[0-9]\+/udp|\033[1;34m&\033[0m|'

  # Delete the temporary file
  rm -f "$nmap_output"
}

# Bind the Ctrl + n key combination to run the nmapfast function
bind -x '"\C-n": nmapfast'

# Creates executable bash script, or just changes modifiers to
# executable, if file already exists.
mkexecute() {
  echo "make File Executable Or Create New Bash Or Python Script"
  echo ""
  if [[ ! -f "$1" ]]; then
    filename=$(basename "$1")
    extension="${filename##*.}"
    if [[ "$extension" == "py" ]]; then
      echo '#!/usr/bin/env python3' >> "$1"
      echo '#' >> "$1"
      echo "# Usage: $1 " >> "$1"
      echo '# ' >> "$1"
      echo >> "$1"
      echo 'import sys' >> "$1"
      echo 'import re' >> "$1"
      echo >> "$1"
      echo 'def main():' >> "$1"
      echo '    ' >> "$1"
      echo >> "$1"
      echo "if __name__ == '__main__':" >> "$1"
      echo '    main()' >> "$1"
    elif [[ "$extension" == "sh" ]]; then
      echo '#!/bin/bash' >> "$1"
      echo '# Shell Script Template' >> "$1"
      echo "#/ Usage: $1 " >> "$1"
      echo "#/ Description: " >> "$1"
      echo "#/ Options: " >> "$1"
      echo '# ' >> "$1"
      echo "#Colors" >> "$1"
      echo
      +3"
normal='\e[0m'
cyan='\e[0;36m'
green='\e[0;32m'
light_green='\e[1;32m'
white='\e[0;37m'
yellow='\e[1;49;93m'
blue='\e[0;34m'
light_blue='\e[1;34m'
orange='\e[38;5;166m'
light_cyan='\e[1;36m'
red='\e[1;31m'
      " >> "$1"
      echo "function usage() { grep '^#/' ""$1"" | cut -c4- ; exit 0 ; }" >> "$1"
      echo >> "$1"
      echo "# Logging Functions to log what happend in the script [It's recommended]" >> "$1"
      echo "" >> "$1"
      echo "readonly LOG_FILE=\"/tmp/\$(basename \"\$0\").log\"" >> "$1"
      echo "
    info()    { echo -e \"\$light_cyan[INFO]\$white \$*\$normal\" | tee -a \"\$LOG_FILE\" >&2 ; }
    warning() { echo -e \"\$yellow[WARNING]\$white \$*\$normal\" | tee -a \"\$LOG_FILE\" >&2 ; }
    error()   { echo -e \"\$red[ERROR]\$white \$*\$normal\" | tee -a \"\$LOG_FILE\" >&2 ; }
    fatal()   { echo -e \"\$orange[FATAL]\$white \$*\$normal\" | tee -a \"\$LOG_FILE\" >&2 ; exit 1 ; }

      " >> "$1"
      echo '# Stops execution if any command fails.' >> "$1"
      echo 'set -eo pipefail' >> "$1"

      echo >> "$1"
      echo "function cleanup() {" >> "$1"
      echo "  # Remove temporary files
    # Restart services
    # ..." >> "$1"
      echo "  echo \"\"" >> "$1"
      echo "}" >> "$1"
      echo >> "$1"
      echo 'function main() {'>> "$1"
      echo "  if [[ \$1 = \"--help\" ]]" >> "$1"
      echo "	then" >> "$1"
      echo '    expr "$*" : ".*--help" > /dev/null && usage'>> "$1"
      echo '	else' >> "$1"
      echo '    # Some Code Here'   >> "$1"
      echo "    echo \"some code here\"" >> "$1"
      echo "  fi" >> "$1"
      echo "" >> "$1"
      echo "#trap command make sure the cleanup function run to clean any miss created by the script" >> "$1"
      echo >> "$1"
      echo "trap cleanup EXIT" >> "$1"
      echo >> "$1"
      echo '}'>> "$1"
      echo >> "$1"
      echo "#This test is used to execute the main code only when the script is executed directly, not sourced" >> "$1"
      echo "
if [[ \"\${BASH_SOURCE[0]}\" = \"\$0\" ]]; then
    # Main code of the script
      " >> "$1"
      echo 'main "$@"'>> "$1"
       echo "
      info  this is information
      warning  this is warning
      error  this is Error
      fatal  this is Fatal
      " >> "$1"
      echo "fi" >> "$1"
      echo "" >> "$1"
      echo "" >> "$1"
    else
      echo "To give executable permissions To exist file: mkexecute <path/file_name>.<py|sh>"
      echo "To Create new executable: mkexecute <file_name>.<py|sh>"
    fi
  fi
  if [[ -n "$1" ]]; then
  chmod u+x "$@"
  else
  true
  fi
}

wirelessNetworksInRange() {
 sudo iwlist wlp2s0 scan \
    | grep Quality -A2 \
    | tr -d "\n" \
    | sed 's/--/\n/g' \
    | sed -e 's/ \+/ /g' \
    | sort -r \
    | sed 's/ Quality=//g' \
    | sed 's/\/70 Signal level=-[0-9]* dBm Encryption key:/ /g' \
    | sed 's/ ESSID:/ /g'
}

function start-program {
    local program_name="$1"
    local unit_name="$(whoami)-$program_name-$(date +%H:%M).service"
    systemd-run --user --unit="$unit_name" "$program_name" "${@:2}"
}

playa() {
  local num_files=${1:-10}  # Use 10 if no argument is provided
  for i in $(shuf -e *.m4a -n "$num_files"); do
    mpv --no-audio-display "$i"
  done
}
