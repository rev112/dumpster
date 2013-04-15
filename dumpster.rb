#!/usr/bin/env ruby

###
# t1234 - TCP port 1234
# u2345 - UDP port 2345
PORTS = ['t1234', 'u2345', 't1235', 't1236']

MAXSIZE = 10  # in MB
INTERFACE = 'lo'
OUTFILE = 'dump_out'
OUTDIR = 'outdumps'

SCRIPT_DIR = File.expand_path(File.dirname(__FILE__))
Dir.chdir(SCRIPT_DIR)
Dir.mkdir(OUTDIR) unless File.exists?(OUTDIR)

def check_ports
  abort ">>> NO PORTS GIVEN\n" if PORTS.empty?
  PORTS.each do |p|
    proto = p[0]
    abort ">>> PORT TYPE ERROR: #{p}\n" unless  ['t', 'u'].include?(proto)
    portnum = p[1..-1].to_i
    abort ">>> PORT NUMBER ERROR: #{p}\n" unless  1 <= portnum and portnum <= 2**16
  end
end

def launch_tcpdump
  check_ports()
  pids = []
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
      newdir = SCRIPT_DIR + '/' + OUTDIR + '/' + "port_#{p}"
      Dir.mkdir(newdir) unless File.exists?(newdir)
      Dir.chdir(newdir)
      exec_str = "tcpdump -i #{INTERFACE} -w #{OUTFILE}_#{p}.pcap -C #{MAXSIZE} #{proto} port #{portnum}"
      puts exec_str
      exec exec_str
    end

    # parent
    pids.push(newpid)  
    sleep(0.1)
  end
  sleep
rescue Interrupt  => e
  pids.each do |pid|
    Process.kill "KILL", pid
  end
  puts "\nInterrupted. Alpacas won't forget."
end


### MAIN
launch_tcpdump()

