# Navigation Aliases
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias .....='cd ../../../..'

# File Permissions Aliases
alias 000='chmod 000'
alias 644='chmod 644'
alias 755='chmod 755'

# Audible Aliases
alias authcode='jq -r ".activation_bytes" ~/.audible/home.json'
alias audilist='audible library list'
alias audiload='audible download --aax-fallback --chapter --annotation --pdf --output-dir ~/Audiobook -a $1'

# System Management Aliases
alias c='clear'
alias da='date "+%A %m-%d-%Y %T %Z"'
#alias install='sudo dnf install -y'
#alias search='dnf search'
#alias list='dnf list installed'
#alias update='sudo dnf update -y'
alias halt='sudo /sbin/halt'
alias reboot='sudo /sbin/reboot'
alias shutdown='sudo /sbin/shutdown'

# File and Directory Operations Aliases
alias du1='du -h --max-depth=1'
alias funderscores="find . -name '* *' -type f | /usr/local/bin/rename 's/ /_/g'"
alias dunderscores="find . -name '* *' -type d | /usr/local/bin/rename 's/ /_/g'"
alias l.='ls -d .* --color=auto'
alias la='ls -Al'
alias lc='ls -lcr'
alias lk='ls -lSr'
alias ll='cd /media/nowhereman/nowhereman/Linux/Linux-Learn'
alias lr='ls -lR'
alias ls='ls -X --format=single-column'
alias lt='ls -ltr'
alias lu='ls -lur'
alias lx='ls -lXB'
alias hdd='cd /media/nowhereman/nowhereman/'

# Kubernetes Aliases
alias k='kubectl'
alias ka='kubectl apply -f'
alias kdesc='kubectl describe'
alias ked='kubectl edit'
alias kex='kubectl exec -i -t'
alias kg='kubectl get'
alias kga='kubectl get all'
alias kgall='kubectl get all --all-namespaces'
alias kinfo='kubectl cluster-info'
alias klo='kubectl logs -f'
alias kn='kubectl get nodes'
alias kpa='kubectl patch -f'
alias kpv='kubectl get pv'
alias kpvc='kubectl get pvc'
alias ksc='kubectl scale'
alias ktp='kubectl top'

# Process and Resource Monitoring Aliases
alias pg='ps aux | grep'
alias pscpu='ps auxf | sort -nr -k 3'
alias psmem='ps auxf | sort -nr -k 4'

# Miscellaneous Aliases
alias meminfo='free -m -l -t'
alias ns='netstat -alnp --protocol=inet | grep -v CLOSE_WAIT | cut -c-6,21-94 | tail +2'
alias openports='netstat -nape --inet'
alias myip='curl ipinfo.io/ip ; echo "" ;'
alias sl='fc -ln -1 | sed "s/^\s*//" >> ~/.saved_cmds.txt'
alias slg='< ~/.saved_cmds.txt grep'
alias unt='tar -zxvf'
alias wgetc='wget -c'
alias x='chmod u+x'
alias youtube='yt-dlp --extract-audio --audio-format mp3 --audio-quality 0 --prefer-ffmpeg'

# Audio File Playback Aliases
alias playm='for i in *.mp3; do mpv --no-audio-display $i; done'
alias playo='for i in *.ogg; do mpv --no-audio-display $i; done'
alias playw='for i in *.wav; do mpv --no-audio-display $i; done'



# GitHub Gist Aliases
# alias gist-list='gh gist list --limit 15 | awk '{ print $1 "   # " $2 }''

# System Information Aliases
alias homestart='systemd-run --user "$1"'
alias mountedinfo='df -hT | grep "Filesystem\|Type\|Size\|Used\|Avail\|Use%\|Mounted on\|ext4"'

# Miscellaneous File Operations Aliases
alias ebrc='pico ~/.bashrc'
alias {e,w,r}{c,x,z}{i,o,u}{t,r,y}='exit'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Process and Resource Monitoring Aliases
alias pscpu10='ps auxf | sort -nr -k 3 | head -10'
alias psmem10='ps auxf | sort -nr -k 4 | head -10'
