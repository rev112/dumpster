dumpster
========

**dumpster** simplifies traffic capturing from several ports. 

*Requirements:* ruby, tcpdump, net-ssh gem (for remote captures)

Tested on: Fedora 18/19 x64.

## Usage

1. Show usage

    `./dumpster.rb -h`


2. Modify port list in the beginning of the script, for example:

    ```ruby
    PORTS = ['t1234', 'u2345'] # captures traffic from ports 1234 (TCP) and 2345 (UDP)
    ```

#### Local capture

Launch **dumpster** (default output directory is 'OUTDUMPS'):

    `./dumpster.rb -o OUTDIR`

You can specify interface and address to filter for:

    `./dumpster.rb -i eth0 -a 10.23.23.2`

Tired of coming up with output directory names? Use '-g' flag:

    `./dumpster.rb -g  # Will create the directory with the name like 17_Dec_19_13_46/`


#### Remote capture

Launch **dumpster** with remote hostname, user (default: root) and port (default: 22):

    `./dumpster.rb -r host.com -u root -p 2200`


## TODO

* Test dat

