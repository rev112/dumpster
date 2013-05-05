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

def launch_local(options = {})
  pids = []
  main_pid = Process.pid
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
      newdir = SCRIPT_DIR + '/' + options[:outdir] + '/' + "port_#{p}"
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

def launch_remote(options = {})
  abort 'Install net-ssh gem!' unless require 'net/ssh'

  Net::SSH.start(options[:remote_host], 'root', :port => 22) do |ssh|
    pids = []
    out_pipes = []
    PORTS.each do |port|
      tcpdump_str = "tcpdump -U -i lo -w - tcp port #{port}"
      # perl_wrapper_str = %q(perl -e 'print STDERR "$$\n";exec "@ARGV";print STDERR $!')
      shell_wrapper_str = %q(echo $$>&2; exec)
      exec_str = "#{shell_wrapper_str} #{tcpdump_str}"
      is_pid_str = true
      #split_out = IO.popen("split - -b 100 -d -a 3 out_#{port}", 'wb')
      split_out = IO.popen("tcpdump -r - -w out_#{port}.pcap -C 1 2>/dev/null", 'wb')
      out_pipes << split_out
      ssh.exec(exec_str) do |ch, stream, data|
        case stream
          when :stdout
            split_out.write(data)
          when :stderr
            if is_pid_str
              pid = data.chomp.to_i
              puts "PID: ##{pid}#"
              pids << pid
              is_pid_str = false
            else
              puts data
            end
        end
      end
    end

    # loop until ctrl-C is pressed
    int_pressed = false
    trap("INT") do
      p out_pipes
      puts ssh.exec!("kill #{pids.join(' ')}")
      int_pressed = true
      puts "Interrupted!"
    end
    ssh.loop(0.1) { not int_pressed and ssh.busy? }
    # close pipes
    out_pipes.each {|p| p.close}
    puts 'Finished.'
  end

end


def launch_tcpdump(mode, options = {})
  check_ports()
  Dir.chdir(SCRIPT_DIR)
  outdir = options[:outdir]
  if File.exists?(outdir)
    abort "ABORT: Invalid output directory. '#{outdir}' is not a directory." unless File.directory?(outdir)
    res = ''
    puts "Output directory '#{outdir}' already exists."
    until ['y', 'n'].include? res.downcase
      print "Overwrite? [y/n] "
      res = gets().chomp
    end
    exit(1) if res == 'n'
  else
    Dir.mkdir(options[:outdir])
  end

  case mode
  when :local
    launch_local(options)
  when :remote
    launch_remote(options)
  else
    abort 'Invalid mode.'
  end
end

def show_usage
  res = <<-USAGE
Usage: dumpster.rb [options]
  -o, --outdir DIR    Output directory (default is #{DEFAULT_OUTDIR})
  -h, --help          Show this help
  -r, --remote HOST   Remote capture
  USAGE
  print res
end

### MAIN

options = {}
options[:outdir] = DEFAULT_OUTDIR
mode = :local
remote_host = nil

optparse = OptionParser.new do |opts|
  opts.on('-o OUTDIR', '--outdir', 'Output directory') do |out|
    options[:outdir] = out
  end

  opts.on('-h', '--help', 'Show usage') do |out|
    show_usage()
    exit(0)
  end

  opts.on('-r HOST', '--remote', 'Show usage') do |remote|
    mode = :remote
    options[:remote_host] = remote
  end
end
optparse.parse!

abort 'Must run as root!' unless Process.uid == 0
launch_tcpdump(mode, options)
puts 'Finished.'

