dumpster
========

**dumpster** helps to capture network dumps.

*Requirements:* tcpdump.

Tested on: Fedora 18 x64.

## Usage

1. Show usage

    `./dumpster.rb -h`


2. Modify ports, for example:

    ```ruby
    PORTS = ['t1234', 'u2345'] # captures traffic from ports 1234 (TCP) and 2345 (UDP)
    ```

3. Launch **dumpster** (default output directory is 'outdumps')

    `./dumpster.rb -o outdir`


## TODO

* Capture from the remote host
* Special dumps permissions?

