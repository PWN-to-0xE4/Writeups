# Linux 1: SuckMORE shell
[This challenge](https://ctf.wpictf.xyz/challenges#suckmore-shell) starts by giving you access to an SSH server running a custom shell:
```
SuckMORE shell v1.0.1. Note: for POSIX support update to v1.1.0
suckmore>
```
The MOTD suggests that the current shell does not support POSIX commands, and sure enough:
```
suckmore>ls /
sleep: invalid time interval '/'
Try 'sleep --help' for more information.
```

```
suckmore>cd 
     April 2019     
Su Mo Tu We Th Fr Sa
    1  2  3  4  5  6
 7  8  9 10 11 12 13
14 15 16 17 18 19 20
21 22 23 24 25 26 27
28 29 30
```
However, upon closer inspection it looks like the shell is just `/bin/sh` with some custom aliases:
```sh
suckmore>echo $SHELL
/bin/sh
```
```sh
suckmore>alias
alias bash='sh'
alias cat='sleep 1 && vim'
alias cd='cal'
alias cp='grep'
alias dnf=''
alias find='w'
alias less='echo "We are suckMORE, not suckless"'
alias ls='sleep 1'
alias more='echo "SuckMORE shell, v1.0.1, (c) SuckMore Software, a division of WPI Digital Holdings Ltd."'
alias nano='touch'
alias pwd='uname'
alias rm='mv /u/'
alias sh='echo "Why would you ever want to leave suckmore shell?"'
alias sl='ls'
alias vi='touch'
alias vim='touch'
alias which='echo "Not Found"'
```
The `unalias` command is left intact, so we can simply `unalias -a` to get rid of the aliases. <br>
We still don't have access to some POSIX commands, though:
```
suckmore>ls /
bash: /usr/bin/ls: Permission denied
suckmore>ls ~
bash: /usr/bin/ls: Permission denied
suckmore>cat ~/.bashrc
bash: /usr/bin/cat: Permission denied
```
We can get around this by using the `sed` command with an empty string as a substitute for `cat`:
```
suckmore>alias cat='sed "" '
suckmore>cat /etc/locale.conf 
LANG="en_US.UTF-8"
```
`/bin/sh`'s tab completion tells us that `/home/ctf` contains the following files:
```
suckmore>cat ~/
.bash_logout   .bash_profile  .bashrc        flag
```
So finally, to get the flag we run:
```
suckmore>cat ~/flag
WPI{bash_sucks0194342}
```
