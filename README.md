# Python Script Collection

This is a small collection of Python scripts I've written that can perform some basic
(mostly network-related) tasks. As I inevitably use Python more, I'll be updating this repository with
more scripts. As of right now though, there are just a few things here. Including:

1. **sniffpackets.py**: Requires administrative privileges. Intercepts packets on the
   local machine, displays information about them, or dumps them to a specified folder. Running this on Windows may prove
   challenging, as the OS seems to be quite finicky and whiny when it comes to raw packet interception.
3. **tcpproxy.py**: A script that provides a basic TCP-proxy to a target.
4. **reverse_tcp_client.py and reverse_tcp_server.py**: Essentially a simple reverse
   shell backdoor that provides a remote shell session to a
   listener.
6. **uriencat.py**: a small script that provides functionality similar to netcat.

**These were mostly tested on Kali Linux. You may run into issues on Windows.**
