#!/usr/bin/env ruby

require 'optparse'

###
# t1234 - TCP port 1234
# u2345 - UDP port 2345
PORTS = ['t1234', 'u2345', 't1235', 't1236']

MAXSIZE = 20  # in MB
INTERFACE = 'lo'
OUTFILE = 'dump_out'
DEFAULT_OUTDIR = 'outdumps'

SCRIPT_DIR = File.expand_path(File.dirname(__FILE__))

def check_ports
  abort ">>> NO PORTS GIVEN\n" if PORTS.empty?
  PORTS.each do |p|
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
      proto = ''
      if p[0] == 't' 
        proto = 'tcp'
      elsif p[0] == 'u'
        proto = 'udp'
      else
        puts ">>> PORT ERROR: #{p}. Use 't1234' format."
        raise "PortError Exception"
      end
      portnum = p[1..-1].to_i
      puts ">>> Capturing #{proto.upcase} port #{portnum}...\n"
      newdir = SCRIPT_DIR + '/' + outdir + '/' + "port_#{p}"
      Dir.mkdir(newdir) unless File.exists?(newdir)
      Dir.chdir(newdir)
      exec_str = "tcpdump -Z root -i #{INTERFACE} -w #{OUTFILE}_#{p}.pcap -C #{MAXSIZE} #{proto} port #{portnum} || kill -s INT #{main_pid}"
      puts exec_str
      exec exec_str
    end

    # parent
    pids << newpid
    sleep(0.2)
  end
  sleep
rescue Interrupt  => e
  pids.each do |pid|
    Process.kill "KILL", pid
  end
  puts "\nInterrupted. Alpacas won't forget."
end

def show_usage
  res = <<-USAGE
Usage: dumpster.rb [-o DIR]
  -o, --outdir      Output directory (default is 'outdumps')
  -h, --help        Show this help
  USAGE
  print res
end

### MAIN

outdir ||= DEFAULT_OUTDIR

optparse = OptionParser.new do |opts|
  opts.on('-o OUTDIR', '--outdir', 'Output directory') do |out|
    outdir = out 
  end

  opts.on('-h', '--help', 'Show usage') do |out|
    show_usage()
    exit(0)
  end
end
optparse.parse!


launch_tcpdump(outdir)
