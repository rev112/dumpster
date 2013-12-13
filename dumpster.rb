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
LOCAL_OUTFILE = 'local_out'
REMOTE_OUTFILE = 'remote_out'
DEFAULT_OUTDIR = 'OUTDUMPS'
TIMEOUT = 0.2 # in seconds

#========================================================

SCRIPT_DIR = File.expand_path(File.dirname(__FILE__))

def get_proto(str)
    proto = case str[0]
              when 't' then 'tcp'
              when 'u' then 'udp'
              else abort ">>> PORT ERROR: #{str}. Use 't1234' format."
            end
    return proto
end

def get_portnum(str)
    portnum = str[1..-1].to_i
    abort ">>> PORT NUMBER ERROR: #{str}\n" unless portnum.between?(1, 2**16)
    return portnum
end

def check_ports(ports = PORTS)
  abort ">>> NO PORTS GIVEN\n" if ports.empty?
  ports.each do |p|
    get_proto(p)
    get_portnum(p)
  end
end

# Launch local capture
def launch_local(options = {})
  puts ">>> Starting local capture..."
  pids = []
  main_pid = Process.pid
  puts ">>> Parent PID: #{main_pid}\n"
  PORTS.each do |p|
    newpid = fork do
      # child
      proto = get_proto(p)
      portnum = get_portnum(p)
      puts "\n>>> Capturing #{proto.upcase} port #{portnum}...\n"
      newdir = SCRIPT_DIR + '/' + options[:outdir] + '/' + "port_#{p}"
      Dir.mkdir(newdir) unless File.exists?(newdir)
      Dir.chdir(newdir)
      File.chmod(0700, '.')
      filter_address = options[:address] ? "and host #{options[:address]}" : ''
      exec_str = <<-EXEC
tcpdump -Z root -i #{options[:interface]} -w #{LOCAL_OUTFILE}_#{p}.pcap \
-C #{MAXSIZE} #{proto} port #{portnum} #{filter_address}\
  || kill -s INT #{main_pid}
      EXEC
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

# Launch remote capture
def launch_remote(options = {})
  abort 'Install net-ssh gem! (for ex: gem install net-ssh)' unless require 'net/ssh'

  puts ">>> Starting remote capture..."
  Net::SSH.start(options[:remote_host], options[:user], :port => options[:port]) do |ssh|
    pids = []
    out_pipes = []
    PORTS.each do |port|
      abort ">>> HEHE, SSH PORT, NICE TRY!\n" if port == 't' + options[:port].to_s
      proto = get_proto(port)
      portnum = get_portnum(port)
      tcpdump_str = "tcpdump -U -i #{options[:interface]} -w - #{proto} port #{portnum}"
      shell_wrapper_str = %q(echo $$>&2; exec)
      exec_str = "#{shell_wrapper_str} #{tcpdump_str}"
      is_pid_str = true
      newdir = SCRIPT_DIR + '/' + options[:outdir] + '/' + "port_#{port}"
      Dir.mkdir(newdir) unless File.exists?(newdir)
      File.chmod(0700, newdir)
      popen_str = "tcpdump -r - -w #{newdir}/#{REMOTE_OUTFILE}_#{port}.pcap -C #{MAXSIZE} 2>/dev/null"
      split_out = IO.popen(popen_str, 'wb')
      puts popen_str
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
    ssh.loop(TIMEOUT) { not int_pressed and ssh.busy? }
    # close pipes
    out_pipes.each {|p| p.close}
    puts 'Finished remote capture.'
  end

end

# Common function
def launch_tcpdump(mode, options = {})
  abort "Must run as root!" if mode == :local and Process.uid != 0
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


### MAIN

options = {}
mode = :local

optparse = OptionParser.new do |opts|

  options[:outdir] = DEFAULT_OUTDIR
  opts.on('-o OUTDIR', '--outdir', 'Output directory (default: OUTDUMPS)') do |out|
    options[:outdir] = out
  end

  opts.on('-g', '--generate', 'Generate new output directory name (using date)') do 
    options[:outdir] = Time.now.strftime("%d_%b_%H_%M_%S")
  end

  opts.on('-h', '--help', 'Show usage') do |out|
    puts optparse.help
    exit(0)
  end

  opts.on('-r HOST', '--remote', 'Remote host') do |remote|
    mode = :remote
    options[:remote_host] = remote
  end

  options[:port] = 22
  opts.on('-p PORT', '--port', 'Remote SSH port (default: 22)') do |port|
    options[:port] = port.to_i 
  end

  options[:user] = 'root'
  opts.on('-u USER', '--user', 'Remote user (default: root)') do |user|
    options[:user] = user
  end

  options[:interface] = 'lo'
  opts.on('-i INTERFACE', '--interface', 'Capture interface (default: lo)') do |i|
    options[:interface] = i
  end

  opts.on('-a ADDRESS', '--address', 'Filter packets for a specific address') do |a|
    options[:address] = a
  end
end
optparse.parse!

launch_tcpdump(mode, options)
puts 'Finished.'

