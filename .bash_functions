# .bash_functions
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
{
  # didn't work with zsh / bash is ok
  #read lowerPort upperPort < /proc/sys/net/ipv4/ip_local_port_range

  for port in $(seq 32768 61000); do
    for i in $(netstat_used_local_ports); do
      if [[ $used_port -eq $port ]]; then
        continue
      else
        echo $port
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
	allowport $port
  httpModule=$( \
    python -c 'import sys; \
    print("http.server" if sys.version_info[:2] > (2,7) else "SimpleHTTPServer")'
  )
  trap 'kill -9 "${httpPid}"' SIGHUP SIGINT SIGTERM
  (
    cd "${2:-.}" || return 1
    case "${httpModule}" in
      (SimpleHTTPServer)
        python -c "import sys,BaseHTTPServer,SimpleHTTPServer; \
          sys.tracebacklimit=0; \
          httpd = BaseHTTPServer.HTTPServer(('', ${port}), SimpleHTTPServer.SimpleHTTPRequestHandler); \
          httpd.serve_forever()"
        httpPid="$!"
      ;;
      (http.server)
        python -c "import sys,http.server,http.server,ssl,signal; \
          signal.signal(signal.SIGINT, lambda x,y: sys.exit(0)); \
          httpd = http.server.HTTPServer(('', ${port}), http.server.SimpleHTTPRequestHandler) ; \
          httpd.serve_forever()"
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
	lsof -nti:$port | xargs kill -9
	blockport $port
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
	echo ${MY_IP:-"Not connected"}
}

function whatsmyip() {
    local myipv4="$(dig +short -4 @resolver1.opendns.com myip.opendns.com A)"
    local myipv6="$(dig +short -6 @resolver1.ipv6-sandbox.opendns.com myip.opendns.com AAAA)"
    local reverse="$(dig +short -4 -x ${myipv4})"
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
	unset $i
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

bind -x '"\eh":alt_h'

#######################################################
################ Begin gpg functions ##################
#######################################################

################################################################################
# genpasswd password generator
################################################################################
# Password generator function for when 'pwgen' or 'apg' aren't available
# Koremutake mode inspired by:
# https:#raw.githubusercontent.com/lpar/kpwgen/master/kpwgen.go
# http://shorl.com/koremutake.php
genpasswd() {
  export LC_CTYPE=C
  # localise variables for safety
  local OPTIND pwdChars pwdDigit pwdNum pwdSet pwdKoremutake pwdUpper \
    pwdSpecial pwdSpecialChars pwdSyllables n t u v tmpArray
  # Default the vars
  pwdChars=10
  pwdDigit="false"
  pwdNum=1
  pwdSet="[:alnum:]"
  pwdKoremutake="false"
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
      # Because special characters aren't sucked up from /dev/urandom,
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
  # We don't want to mess around with other options like bcrypt as it
  # requires more error handling than I can be bothered with
  # If the crypt mode isn't defined as 1, 5, 6 or n: default to 1
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

function pe ()
{
# Passphrase encryption program
# Created by Dave Crouse 01-13-2006
# Reads input from text editor and encrypts to screen.
clear
echo "         Passphrase Encryption Program";
echo "--------------------------------------------------"; echo "";
which $EDITOR &>/dev/null
 if [ $? != "0" ];
     then
     echo "It appears that you do not have a text editor set in your
.bashrc file.";
     echo "What editor would you like to use ? " ;
     read EDITOR ; echo "";
 fi
echo "Enter the name/comment for this message :"
read comment
$EDITOR passphraseencryption
gpg --armor --comment "$comment" --no-options --output passphraseencryption.gpg --symmetric passphraseencryption
shred -u passphraseencryption ; clear
echo "Outputting passphrase encrypted message"; echo "" ; echo "" ;
cat passphraseencryption.gpg ; echo "" ; echo "" ;
shred -u passphraseencryption.gpg ;
read -p "Hit enter to exit" temp; clear
}


function encryptfile ()
{
zenity --title="zcrypt: Select a file to encrypt" --file-selection > zcrypt
encryptthisfile=$(cat zcrypt);rm zcrypt
# Use ascii armor
#  --no-options (for NO gui usage)
gpg -acq --yes ${encryptthisfile}
zenity --info --title "File Encrypted" --text "$encryptthisfile has been
encrypted"
}

function decryptfile ()
{
zenity --title="zcrypt: Select a file to decrypt" --file-selection > zcrypt
decryptthisfile=$(cat zcrypt);rm zcrypt
# NOTE: This will OVERWRITE existing files with the same name !!!
gpg --yes -q ${decryptthisfile}
zenity --info --title "File Decrypted" --text "$encryptthisfile has been
decrypted"
}

#######################################################
################## End gpg functions ##################
#######################################################

#######################################################
################ Start misc functions #################
#######################################################

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


function spin ()
{
echo -ne "${RED}-"
echo -ne "${WHITE}\b|"
echo -ne "${BLUE}\bx"
sleep .02
echo -ne "${RED}\b+${NC}"
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
function fe() { find . -type f -iname '*'"${1:-}"'*' -exec ${2:-file} {} \;  ; }

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
    find . -type f -name "${2:-*}" -print0 | xargs -0 egrep --color=always -sn ${case} "$1" 2>&- | more

}


function swap()
{ # Swap 2 filenames around, if they exist (from Uzi's bashrc).
    local TMPFILE=tmp.$$

    [ $# -ne 2 ] && echo "swap: 2 arguments needed" && return 1
    [ ! -e $1 ] && echo "swap: $1 does not exist" && return 1
    [ ! -e $2 ] && echo "swap: $2 does not exist" && return 1

    mv "$1" $TMPFILE
    mv "$2" "$1"
    mv $TMPFILE "$2"
}


function extract {
 if [ -z "$1" ]; then
    # display usage if no parameters given
    echo "Usage: extract <path/file_name>.<zip|rar|bz2|gz|tar|tbz2|tgz|Z|7z|xz|ex|tar.bz2|tar.gz|tar.xz|.zlib|.cso>"
    echo "       extract <path/file_name_1.ext> [path/file_name_2.ext] [path/file_name_3.ext]"
 else
    for n in "$@"
    do
      if [ -f "$n" ] ; then
          case "${n%,}" in
            *.cbt|*.tar.bz2|*.tar.gz|*.tar.xz|*.tbz2|*.tgz|*.txz|*.tar)
                         tar xvf "$n"       ;;
            *.lzma)      unlzma ./"$n"      ;;
            *.bz2)       bunzip2 ./"$n"     ;;
            *.cbr|*.rar) unrar x -ad ./"$n" ;;
            *.gz)        gunzip ./"$n"      ;;
            *.cbz|*.epub|*.zip) unzip ./"$n"   ;;
            *.z)         uncompress ./"$n"  ;;
            *.7z|*.apk|*.arj|*.cab|*.cb7|*.chm|*.deb|*.dmg|*.iso|*.lzh|*.msi|*.pkg|*.rpm|*.udf|*.wim|*.xar)
                         7z x ./"$n"        ;;
            *.xz)        unxz ./"$n"        ;;
            *.exe)       cabextract ./"$n"  ;;
            *.cpio)      cpio -id < ./"$n"  ;;
            *.cba|*.ace) unace x ./"$n"     ;;
            *.zpaq)      zpaq x ./"$n"      ;;
            *.arc)       arc e ./"$n"       ;;
            *.cso)       ciso 0 ./"$n" ./"$n.iso" && \
                              extract "$n.iso" && \rm -f "$n" ;;
            *.zlib)      zlib-flate -uncompress < ./"$n" > ./"$n.tmp" && \
                              mv ./"$n.tmp" ./"${n%.*zlib}" && rm -f "$n"   ;;
            *)
                         echo "extract: '$n' - unknown archive method"
                         return 1
                         ;;
          esac
      else
          echo "'$n' - file doesn't exist"
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


#######################################################
################# End file functions ##################
#######################################################


#-------------------------------------------------------------
# Process/system related functions:
#-------------------------------------------------------------


function my_ps() { ps $@ -u $USER -o pid,%cpu,%mem,bsdtime,command ; }
function pp() { my_ps f | awk '!/awk/ && $0~var' var=${1:-".*"} ; }


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
        pname=$(my_ps | awk '$1~var { print $5 }' var=$pid )
        if ask "Kill process $pid <$pname> with signal $sig?"
            then kill $sig $pid
        fi
    done
}

function mydf()         # Pretty-print of 'df' output.
{                       # Inspired by 'dfc' utility.
    for fs ; do

        if [ ! -d $fs ]
        then
          echo -e $fs" :No such file or directory" ; continue
        fi

        local info=( $(command df -P $fs | awk 'END{ print $2,$3,$5 }') )
        local free=( $(command df -Pkh $fs | awk 'END{ print $4 }') )
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
        echo -e $out
    done
}



function ii()   # Get current host related info.
{
    echo -e "\nYou are logged on: " ; hostname
    echo -e "\nAdditional information: " ; uname -a | awk '{ print $1,$3,$15,$16 }'
    echo -e "\nUsers logged on: " ; w -hs | cut -d " " -f1 | sort | uniq
    echo -e "\nCurrent date : " ; date
    echo -e "\nMachine stats : " ; uptime -p
    echo -e "\nMemory stats : " ; free -h
    echo -e "\nDiskspace : " ; mydf /run/media/nowhereman/5c* $HOME
    echo -e "\nLocal IP Address :" ; my_ip
    echo -e "\nOpen connections : "; sudo netstat -pan --inet;
    echo
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
	find $BASEDIR -xdev -type f -ls |sort -k 7 -r -n | head -$TOP |awk '{size=$7/1024/1024; printf("%dMb %s\n", size,$11);}'
}

function topdir
{
    BASEDIR=$1
    TOP=$2
	du -alx $BASEDIR | sort -n -r | head -n $TOP | awk '{size=$1/1024/1024; printf("%dMb %s\n", size,$2);}'
}

function ansibleSetup()
{
    ansible $1 -m setup > ~/$1.txt
}
alias accio=ansibleSetup

function gsay()
{
	if [[ "${1}" =~ -[a-z]{2} ]]; then
		local lang=${1#-};
		local text="${*#$1}";
	else
		local lang=${LANG%_*};
		local text="$*";
	fi;
		mplayer "http://translate.google.com/translate_tts?ie=UTF-8&tl=${lang}&q=${text}" &> /dev/null ;
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
    mapfile -t BIGFILES< <(find ${CWD} -xdev -type f -size +50M -printf  '%s\t%k\t%p\n' | numfmt --field=1 --from=iec --to=si --padding=8 | sort -rh | tail -100)
    for f in "${BIGFILES[@]}"; do
        local FNAME="$(echo $f | cut -d' ' -f3)"
        local FSIZEKB="$(echo $f | cut -d' ' -f2)"
        read -p "\nPress 'y' to delete ${FNAME}, 'm' to move it to another directory, and 'k' to keep: " -n 1 -r REPLY
        if [[ $REPLY =~ ^[Mm]$ ]]; then
            read -e -p "\nEnter new destination for ${FNAME}: " -n 64 -r DESTDIR
            if [[ -d "${DESTDIR}" ]]; then
                local FREESPACE="$(df -k --sync ${DESTDIR} | awk '{ print $4 }' | tail -n 1| cut -d'%' -f1)"
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
    if [ -e $1 ]; then
        gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.6 -dPDFSETTINGS=/ebook -dNOPAUSE -dQUIET -dBATCH -sOutputFile="$2" "$1"
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
    export DEBARCHIVE="$(basename $1)"
    export FULLPATH="$(readlink -e $1)"
    export DPKGDEST="$(dirname $FULLPATH)"
    export NEWDEBARCHIVE=$(printf '%s\n' "${DEBARCHIVE%.deb}_repacked.deb")
    # trap "rm -rf ${DPKGTMPDIR}" EXIT
    mkdir -pv ${DPKGTMPDIR}
    fakeroot sh -c 'dpkg-deb -RvD "${FULLPATH}" "${DPKGTMPDIR}"; exit'
    # guake -n guake -e 'cd ${DPKGTMPDIR}; ls -lrt ${DPKGTMPDIR}' guake -r 'dpkg editing session'
    read -n 1 -s -r -p "${DEBARCHIVE} extracted to ${DPKGTMPDIR}. Press Enter when finished making modifications."
    fakeroot sh -c 'dpkg-deb -bvD "${DPKGTMPDIR}" "${DPKGDEST}/${NEWDEBARCHIVE}"'
    debdiff "${FULLPATH}" "${DPKGDEST}/${NEWDEBARCHIVE}"
    rm -rf "${DPKGTMPDIR}"
}

function rpmextract () {
    local RPMFILE=$1
    rpm2cpio "${RPMFILE}" | cpio -idmv
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
    local DISP="$(ps -u $(id -u) -o pid= | xargs -I{} cat /proc/{}/environ 2>/dev/null | tr '\0' '\n' | grep -m1 '^DISPLAY=')"
    # local ACTIVETTY="$(cat /sys/class/tty/tty0/active)"
    # mapfile -t PROCS< <(pgrep -t "${ACTIVETTY}")
    # for PROC in "${PROCS[@]}}"; do
        # if [[ "$(loginctl show-session -p State --value ${SESS})" =~ "active" ]]; then local ACTIVESESS="${SESS}"; fi
        # local DISP="$(awk -v RS='\0' -F= '$1=="DISPLAY" {print $2}' /proc/${PROC}/environ 2>/dev/null)"; [[ -n "${DISP}" ]] && break;
    # done;
    echo -e "${DISP}"
}


function functions ()
{
if [ “$#” -gt 0 ]; then
for f in “$@”;
do
typeset -f “$f”;
done;
else
typeset -F | grep –color=auto -v ‘^declare -f _’;
fi
}

function mach()
{
    echo -e "\nMachine information:" ; uname -a
    echo -e "\nUsers logged on:" ; w -h
    echo -e "\nCurrent date :" ; date
    echo -e "\nMachine status :" ; uptime
    echo -e "\nMemory status :" ; free
    echo -e "\nFilesystem status :"; df -h
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

function fun {

  case $1 in

  fun|f)

    #list all custom bash functions defined

    declare -f $(declare -F | grep -v "_" | awk '{ print $3 }')

    ;;

  def|d)

    #show definition of function $1

    declare -f $2

    ;;

  help|h|*)

    printf "[dur]dn shell automation tools\n"

    printf "commands available:\n"

    printf " [f]fun lists all bash functions defined in .bashrc\n"

    printf " [def] <fun> lists definition of function defined in .bashrc\n"

    printf " [h]elp"

    ;;

  esac

}

function ryt ()
{
printf '%s\n' "$@" | pv -qL $[11+(-1 + RANDOM%5)] ; printf "\n"
}

if get_command pbcopy; then
  clipin() { pbcopy; }
  clipout() { pbpaste; }
elif get_command xclip; then
  clipin() { xclip -selection c; }
  clipout() { xclip -selection clipboard -o; }
elif get_command xsel ; then
  clipin() { xsel --clipboard --input; }
  clipout() { xsel --clipboard --output; }
else
  clipin() { printf -- '%s\n' "No clipboard capability found" >&2; }
  clipout() { printf -- '%s\n' "No clipboard capability found" >&2; }
fi

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
  # Otherwise, check that $1 is a number, if it isn't print an error message
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

  # Next, we handle $2.  First, we check if it's a number, indicating a line range
  if (( "${2}" )) 2>/dev/null; then
    # Stack the numbers in lowest,highest order
    if (( "${2}" > "${1}" )); then
      lineNo="${1},$((10#${2}))p;$((10#${2}+1))q;"
    else
      lineNo="$((10#${2})),${1}p;$((${1}+1))q;"
    fi
    shift 1
  fi

  # Otherwise, we check if it's a readable file
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
