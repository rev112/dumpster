#!/usr/bin/env ruby

require 'optparse'

###
# t1234 - TCP port 1234
# u2345 - UDP port 2345
PORTS = %w/
            t1234
            u2345
            t80 t443
          /

MAXSIZE = 20  # in MB
INTERFACE = 'lo'
OUTFILE = 'dump_out'
DEFAULT_OUTDIR = 'OUTDUMPS'
TIMEOUT = 0.2 # in seconds

SCRIPT_DIR = File.expand_path(File.dirname(__FILE__))

def check_ports(ports = PORTS)
  abort ">>> NO PORTS GIVEN\n" if ports.empty?
  ports.each do |p|
    proto = p[0]
    abort ">>> PORT TYPE ERROR: #{p}\n" unless  ['t', 'u'].include?(proto)
    portnum = p[1..-1].to_i
    abort ">>> PORT NUMBER ERROR: #{p}\n" unless portnum.between?(1, 2**16)
  end
end

def launch_tcpdump(outdir)
  check_ports()
  pids = []
  main_pid = Process.pid
  Dir.chdir(SCRIPT_DIR)
  Dir.mkdir(outdir) unless File.exists?(outdir)
  PORTS.each do |p|
    newpid = fork do
      # child    
      proto = case p[0]
              when 't' then 'tcp'
              when 'u' then 'udp'
              else abort ">>> PORT ERROR: #{p}. Use 't1234' format."
              end
      portnum = p[1..-1].to_i
      puts "\n>>> Capturing #{proto.upcase} port #{portnum}...\n"
      newdir = SCRIPT_DIR + '/' + outdir + '/' + "port_#{p}"
      Dir.mkdir(newdir) unless File.exists?(newdir)
      Dir.chdir(newdir)
      File.chmod(0700, '.')
      exec_str = "tcpdump -Z root -i #{INTERFACE} -w #{OUTFILE}_#{p}.pcap -C #{MAXSIZE} #{proto} port #{portnum} || kill -s INT #{main_pid}"
      puts exec_str
      exec exec_str
    end

    # parent
    pids << newpid
    sleep(TIMEOUT)
  end
  sleep
rescue Interrupt
  pids.each do |pid|
    Process.kill "KILL", pid
  end
  sleep(TIMEOUT)
  puts "\nInterrupted. Alpacas won't forget."
end

def show_usage
  res = <<-USAGE
Usage: dumpster.rb [-o DIR]
  -o, --outdir      Output directory (default is #{DEFAULT_OUTDIR})
  -h, --help        Show this help
  USAGE
  print res
end

### MAIN

outdir ||= DEFAULT_OUTDIR

mode = :local
remote_host = nil
optparse = OptionParser.new do |opts|
  opts.on('-o OUTDIR', '--outdir', 'Output directory') do |out|
    outdir = out 
  end

  opts.on('-h', '--help', 'Show usage') do |out|
    show_usage()
    exit(0)
  end

  opts.on('-r HOST', '--remote', 'Show usage') do |remote|
    mode = :remote
    remote_host = remote
    abort 'Not implemented!'
  end
end
optparse.parse!

abort 'Must run as root!' unless Process.uid == 0
launch_tcpdump(outdir)
puts 'Finished.'

#TODO split file from the remote host

proto = 'tcp'
portnum = 123
host = 'localhost'
main_pid = 1234
remote_str = "tcpdump -Z root -i #{INTERFACE} -w - #{proto} port #{portnum}"
split_str = "split - -b #{MAXSIZE}M -d -a 3"
exec_str = "ssh root@#{host} '#{remote_str}' | #{split_str} || kill -s INT #{main_pid}"
puts exec_str

