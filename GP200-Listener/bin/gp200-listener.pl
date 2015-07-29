#!/usr/bin/perl

use strict;
use warnings;

use TrackerProtocol '0.02';
use TrackerProtocol::Log;
use TrackerProtocol::GP200;
use Data::Dumper;  ## for debugging only
use DBI;
use POE::API::Peek;
use POE qw(Component::Server::TCP Filter::Line);
use Socket;
use Getopt::Long;

local $| = 1;

our $VERSION = '1.0';


our $POEDEBUG = 0;        	# be very very noisy
our $POETRACE = 0;			# enable POE tracing
our $VERBOSE = 1;			# enable/disable verbose logging
our $LOGLEVEL = 3;			# loglevel 0-9
our $SERVERPORT = 9999;		# listener port
our $RUNASDAEMON = 0;		# run as daemon
our $MAX_SESSIONS = -1;		# max. concurrent sessions

our $MYSERVER = "monitor.homeoffice.com";	# mysql server
our $MYDB = "gp200";						# mysql db
our $MYUSER = "gp200";						# mysql user
our $MYPASS = "gp200";						# mysql pass
our $MYPORT = "3306";						# mysql port
our $USEDB = 1;								# enable / disable logging to database

# list of ip addresses to allow - empty array allows everyone
our @ALLOWED_GPRS_IP = (	
						);	
# list of ip addresses allowing mgmt tasks - empty array allows everyone
our @ALLOWED_MGMT_IP = ( 	
							'127.0.0.1',
						);	
# list of ip addresses that are blocked
our @BLOCKED_IP = (	
					);


## do not change the parameters below

our $MYDBH;			## global handle to the database
our $api;			# global handle to POE::API::Peek
our $SESSION_ALIAS = "gp200_socketlistener";	# DO NOT CHANGE






####################################################################

## initialize the socket server
&init();

# And start it ...
PRINT("GPE200 socket server started at " . (scalar localtime()));
$poe_kernel->run();

exit 0;

####################################################################






## -----------  SERVER TASKS ----------- 

##
## - initialize the script, start up the server session
## - initialize logging
## - initialize some counters
##
sub init()  {

	my $options = GetOptions (
									'debug!'		=>	\$POEDEBUG,
									'trace!'		=>	\$POETRACE,
									'verbose!'		=>	\$VERBOSE,
									'loglevel=i'	=>	\$LOGLEVEL,
									'daemon!'		=>	\$RUNASDAEMON,
									'port=i'		=>	\$SERVERPORT,
									'sessions=i'	=>	\$MAX_SESSIONS,
									'myserver=s'	=>	\$MYSERVER,
									'mydb=s'		=>	\$MYDB,
									'myuser=s'		=> 	\$MYUSER,
									'mypass=s'		=>	\$MYPASS,
									'mpyport=i'		=>	\$MYPORT,
									'usedb|db!'	 	=>	\$USEDB,
									'help'			=> 	\&print_help_and_exit,
									'version'		=>	\&print_version_and_exit,
							);
							
	$LOGLEVEL = 4 if ($POEDEBUG && $LOGLEVEL < 4);

	## set the logging + verbose level
	VERBOSE($VERBOSE);
	LOGLEVEL($LOGLEVEL);
	
	## run in daemon mode if needed
	fork and exit if ($RUNASDAEMON);
	
	DEBUG("initializing tcp socket server");
	DEBUG("parameters:\n" .
			"\tloglevel = $LOGLEVEL\n" .
			"\tPOEdebug = $POEDEBUG\n" .
			"\tPOEtrace = $POETRACE\n" .
			"\tverbose = $VERBOSE\n" .
            "\tport = $SERVERPORT\n" .
            "\tmax_sessions = $MAX_SESSIONS\n" . 
            "\tusedb = $USEDB\n" .
            "\tdbserver = $MYSERVER\n" .
            "\tdb = $MYDB");

	## create a new POE::Component::Server::TCP object
	my $acceptor_session_id = POE::Component::Server::TCP->new(
		Port     => $SERVERPORT,
		Alias    => $SESSION_ALIAS,
		Error    => \&error_handler,
		Concurrency => $MAX_SESSIONS,
		ClientInput        => \&handle_client_input,
		ClientConnected    => \&handle_client_connect,
		ClientDisconnected => \&handle_client_disconnect,
		ClientError        => \&handle_client_error,
		ClientFlushed      => \&handle_client_flush,
		ClientFilter       => POE::Filter::Line->new( InputRegexp   => '[>\r\n]+'),
		ClientShutdownOnError => 1,
	);
	
	## die if there's a problem with the server
	if (!$acceptor_session_id)  {
		ERROR("unable to start a new socket server on port $SERVERPORT - QUIT");
		die();
	}
	
	## initialize some counters on the server heap
	&init_server_heap();
	
	## initialize POE::API::Peek object
	$api = POE::API::Peek->new();
}



##
## print some help and exit
##
sub print_help_and_exit  {
	print "Usage: $0 --debug --trace --verbose --daemon --loglevel=i --port=i --sessions=i --myserver=s --mydb=s --myuser=s --mypass=s --myport=i --usedb --help --version\n\n" .
		"This is a TCP listener that expects connections from GP200 tracker devices. GP200 packets are being decoded and stored in a mysql database as soon as they are received.\n" .
		"It is possible to telnet directly to the listener and execute some management tasks.\n" .
		"Connection restrictions can be enforced by allowing or denying certain ip addresses, these need to be configured in the script\n\n" .
		"Commandline options :\n" .
		"---------------------\n" .
		"--[no]debug : enable or disable debug logging, when enabled all received GP200 data is also being stored in a debug table called Events_debug\n" .
		"--[no]trace : enable or disable POE trace logging\n" .
		"--[no]verbose : enable or disable verbose logging\n" .
		"--[no]daemon : run as daemon\n" .
		"--loglevel=i : integer between 0-9 sets the level of debug output where 0 means no output at all\n" .
		"--port=i : port that the server listens to for incoming data\n" .
		"--sessions=i : max number of simultaneous sessions allowed, -1 means system limited\n" .
		"--myserver=s : mysql server name\n" .
		"--mydb=s : mysql database\n" .
		"--myuser=s : mysql username\n" .
		"--mypass=s : mysql password\n" .
		"--myport=i : mysql port\n" .
		"--[no]usedb : enable or disable storage of packets in the database\n" .
		"--help : print this help and exit\n" .
		"--version : print the current version and exit\n\n" .
		"Management commands :\n" .
		"---------------------\n" .
		"info : print some statistics and connection sessions information\n" .
		"quit : quit the management session\n" .
		"shutdown : quit all sessions and shutdown the server\n" .
		"help : print some help about the management commands\n\n";
		
		exit;
}


##
## print the current version and exit
##
sub print_version_and_exit  {
	print "current version = $VERSION\n";
	exit;
}


##
## Initialize some parameters on the server heap
##
sub init_server_heap()  {
	## get the heap
	my $heap = $poe_kernel->alias_resolve($SESSION_ALIAS)->get_heap();
	
	DEBUG("initializing the server heap");
	$heap->{stats}->{total_connections} = 0;		## keep track of total connections made
	$heap->{stats}->{server_starttime} = time();	## timestamp when the server was started
	$heap->{stats}->{server_stoptime} = "";		## timestamp when the server was stopped
	$heap->{stats}->{total_packets_decoded} = 0; ## total packets decoded for all connections
	$heap->{stats}->{total_decode_errors} = 0; ## total packets decoded for all connections
	$heap->{stats}->{total_invalid_packets} = 0; ## total invalid/not allowed packets
	$heap->{stats}->{total_mgmt_commands} = 0; ## total mgmt commands received
}



##
## here we'll handle any problems with the server
##
sub error_handler {
	my ($syscall_name, $error_number, $error_string) = @_[ARG0, ARG1, ARG2];
	
	ERROR("problem occurred with the server : $error_string");
	DEBUG("error_handler was called by $syscall_name");
}







## -----------  CLIENT/SOCKET TASKS -----------



##
## handle new client connections
##
sub handle_client_connect {
	# no special parameters

	my $client_ip = $_[HEAP]->{remote_ip};
	my $client_port = $_[HEAP]->{remote_port};

	LOG(scalar localtime() . " : new client connection received : $client_ip on port $client_port");
	
	## check if ip addresses are allowed
	$_[HEAP]->{allowed_gprs} = 1;
	$_[HEAP]->{allowed_mgmt} = 1;
	
	$_[HEAP]->{blocked} = 0;		## this ip is not blocked
	if (scalar @ALLOWED_GPRS_IP > 0)  {
		if (!grep { $_ =~ /^$client_ip$/ } @ALLOWED_GPRS_IP)  {
			$_[HEAP]->{allowed_gprs} = 0;
			DEBUG("client ip is not allowed to send GPRS packets");
		}
	}
	if (scalar @ALLOWED_MGMT_IP > 0)  {
		if (!grep { $_ =~ /^$client_ip$/ } @ALLOWED_MGMT_IP)  {
			$_[HEAP]->{allowed_mgmt} = 0;
			DEBUG("client ip is not allowed to send management instructions");
		}
	}
	if (scalar @BLOCKED_IP > 0)  {
		if (grep { $_ =~ /^$client_ip$/ } @BLOCKED_IP)  {
			DEBUG("client ip is blacklisted, session closed");
		}
	}
	
	## this client cannot connect
	unless ( ($_[HEAP]->{allowed_gprs} || $_[HEAP]->{allowed_mgmt}) && !$_[HEAP]->{blocked})  {
		ERROR("this ip ($client_ip) is being blocked - shut down session");
		$_[KERNEL]->yield("shutdown");
		return;
	}
	
	## update some statistics on the server's heap
	my $server_heap = $_[SENDER]->get_heap();
	$server_heap->{stats}->{total_connections}++;
	if (!defined($server_heap->{stats}->{client_ip}->{$client_ip}))  {
		$server_heap->{stats}->{client_ip}->{$client_ip}->{connections} = 0;
		$server_heap->{stats}->{client_ip}->{$client_ip}->{packets} = 0;
		$server_heap->{stats}->{client_ip}->{$client_ip}->{invalid_packets} = 0;
		$server_heap->{stats}->{client_ip}->{$client_ip}->{decode_errors} = 0;
		$server_heap->{stats}->{client_ip}->{$client_ip}->{total_mgmt_commands} = 0;
	}
	$server_heap->{stats}->{client_ip}->{$client_ip}->{connections}++;

	## store the imei number on the heap, as soon as we know what it is
	$_[HEAP]->{imei} = "[UNDEF]";
	
	## create a new TrackerProtocol object - only needed if GPRS is allowed for this ip
	if ($_[HEAP]->{allowed_gprs})  {
		DEBUG("this client is allowed to send GPRS packets so let's initialize TrackerProtocol::GP200");
		$_[HEAP]->{protocol} = new TrackerProtocol::GP200('debug' => $LOGLEVEL);
	}
	
	DEBUG("client is now connected");
}
	

##
## Client got disconnected, this should be a "normal" disconnect
## Currently we're only logging this
##
sub handle_client_disconnect {
	# no special parameters
	
	my $client_ip = $_[HEAP]->{remote_ip};
	my $client_port = $_[HEAP]->{remote_port};

	LOG(scalar localtime() . " : client got disconnected : ip = $client_ip,  port = $client_port");
}



##
## Client got "flush" event
## Currently we're only logging this
##
sub handle_client_flush {
	# no special parameters
	
	my $client_ip = $_[HEAP]->{remote_ip};
	my $client_port = $_[HEAP]->{remote_port};

	DEBUG("client flush event received : ip = $client_ip,  port = $client_port");
}




##
## handle client errors
##
sub handle_client_error {
	my ($syscall_name, $error_number, $error_string) = @_[ARG0, ARG1, ARG2];

	my $client_ip = $_[HEAP]->{remote_ip};
	my $client_port = $_[HEAP]->{remote_port};
	
	ERROR("problem occurred with the client ($client_ip - $client_port) : $error_string");
	DEBUG("error_handler was called by $syscall_name");
}




##
## This is where everything happens : client input is being handled
## 2 types of connections : GP200 (GPRS) and management
## GPRS => assume data starts with "<" and HEX characters
##         this data will be decoded and stored in the database if needed
## MGMT => several specific commands can be used, for now :
##         - quit = quit the current session
##         - shutdown = completely shut down the listener and quit all sessions
##         - info = get some info about number of connections etc.
##         - help = print this help about the available commands
##
sub handle_client_input {
    my $input_record = $_[ARG0];
    my $heap = $_[HEAP];
    my $kernel = $_[KERNEL];
    my $client_ip = $heap->{remote_ip};

	# we need the server heap to store some statistics
	my $server_heap = $kernel->alias_resolve($SESSION_ALIAS)->get_heap();

    ## these are the management commands which are allowed
    my @mgmt_commands = qw/ quit shutdown info help /;
    

    ## only continue if we have some payload
    return unless ($input_record);

    my $input_dispatcher = {
    							'gp200'		=> \&_input_gp200,
    							'quit'		=> \&_input_mgmt_quit,
    							'shutdown' 	=> \&_input_mgmt_shutdown,
    							'info'		=> \&_input_mgmt_info,
    							'help'		=> \&_input_mgmt_help,
    						};

	DEBUG("client input received : $input_record");
	$server_heap->{stats}->{client_ip}->{$client_ip}->{packets} ++;
	$server_heap->{stats}->{last_packet_received} = time;
	$server_heap->{stats}->{client_ip}->{$client_ip}->{last_packet_received} = time;

    ## this looks like a valid GPE200 packet (looks like <A122...>)
    ## decode the packet, save the result in the database and return
    if ($input_record =~ /^<[0-9A-F]+>{0,1}$/)  {  
    		$input_dispatcher->{'gp200'}->($heap, $kernel, $input_record);
    		return;
    }
    
    ## if we got this far then we probably received a mgmt packet, check if this ip is allowed to do this
    ## check if this connection can run management commands, if not then shut it down
	if (grep { $input_record =~ /^$_$/ } @mgmt_commands) {
    	if (! $heap->{allowed_mgmt})  {
    		ERROR("this ip (" . $heap->{remote_ip} . ") is not allowed to run management tasks - shutting down connection");
    		$kernel->yield( "shutdown" );
    		return;
    	}
    }
    ## invalid command received
    else {
    	ERROR("invalid packet received from $client_ip : $input_record");
		$server_heap->{stats}->{client_ip}->{$client_ip}->{invalid_packets} ++;
		$server_heap->{stats}->{total_invalid_packets} ++;
		return;
    }

	## OK, now continue processing management commands
	foreach my $cmd (@mgmt_commands)  {
		if ($input_record =~ /^$cmd$/i)  {
			$server_heap->{stats}->{total_mgmt_commands}++;
			$server_heap->{stats}->{client_ip}->{$client_ip}->{total_mgmt_commands}++;
			$input_dispatcher->{$cmd}->($heap, $kernel);
		}
	}

}




## -----------  INPUT RELATED TASKS -----------


##
## decode + store the GP200 packet in the database
##
sub _input_gp200  {
		my ($heap, $kernel, $input_record) = @_;
		my $client_ip = $heap->{remote_ip};

		$input_record =~ s/[<>]//g;

		# we need the server heap to store some statistics
		my $server_heap = $kernel->alias_resolve($SESSION_ALIAS)->get_heap();

    	DEBUG("looks like a GP200 packet, let's try to decode");
    	
    	## check if this connection is allowed to send GPRS commands, if not then shut it down
    	if (! $heap->{allowed_gprs})  {
    		ERROR("this ip (" . $client_ip . ") is not allowed to send GPRS packets - shutting down connection");
    		$kernel->yield( "shutdown" );
    		return;
    	}
    	
    	## if debugging is enabled then store the input field in a debugging database
    	if ($POEDEBUG)  {
    		&store_debug_packet_in_db($input_record);
    	}

		## initialize the packet on the heap, decode and store result on the heap		
    	$heap->{packet} = "";
    	eval {
    		DEBUG("decode GP200 packet and store on heap");
    		$heap->{packet} = $heap->{protocol}->decode($input_record);
    		DEBUG(&Dumper($heap->{packet}), 8);
    	};
    	if ($@)  {
    		ERROR("unable to decode GP200 packet" . $@);
    		## store some statistics
    		if ($heap->{imei})  {
    			$server_heap->{stats}->{imei}->{$heap->{imei}}->{decode_errors}++;
    			$server_heap->{stats}->{client_ip}->{$client_ip}->{decode_errors}++;
    			$server_heap->{stats}->{total_decode_errors}++;
    		}
    		else  {
    			$server_heap->{stats}->{client_ip}->{$client_ip}->{decode_errors}++;
    			$server_heap->{stats}->{total_decode_errors}++;
    		}
    	}
    	else {
			## get the imei number, store on heap
			DEBUG("GP200 packet was decoded, now store the imei number on the heap");
			$heap->{imei} = $heap->{packet}->{imei}->{number} unless ($heap->{imei} =~ /^[0-9]+$/);
			
			## calculate number of bytes, assuming 2 HEX equals 1 byte
			my $bytes = 0;
			eval { $bytes = (length($input_record) / 2); };

    		## store some statistics
			$server_heap->{stats}->{total_packets_decoded} ++;
			if (!defined($server_heap->{stats}->{imei}->{$heap->{imei}}))  {
				$server_heap->{stats}->{imei}->{$heap->{imei}}->{total_packets_decoded} = 0;
				$server_heap->{stats}->{imei}->{$heap->{imei}}->{decode_errors} = 0;
				$server_heap->{stats}->{imei}->{$heap->{imei}}->{total_bytes_received} = 0;
			}
			$server_heap->{stats}->{imei}->{$heap->{imei}}->{total_packets_decoded} ++;
			$server_heap->{stats}->{imei}->{$heap->{imei}}->{last_packet_decoded} = time;
			$server_heap->{stats}->{imei}->{$heap->{imei}}->{total_bytes_received} += $bytes;
			
			## store the decoded packet in the database
   			eval { &store_packet_in_database($heap->{packet}); };
    	}
    	
    	## nothing to do after decoding the GP200 packet, just return
    	return;
}



##
## process the command 'quit'
## = the current session will be closed
##
sub _input_mgmt_quit  {
	my ($heap, $kernel) = @_;
	
    DEBUG("quit received, shutting down the connection");
    $heap->{client}->put("shutting down this connection");
    $kernel->yield( "shutdown" );
}



##
## process the command 'shutdown'
## = the listener server will be shutdown after all open connections have been closed
##
sub _input_mgmt_shutdown  {
	my ($heap, $kernel) = @_;

	LOG(scalar localtime() . " shutdown received, shutting down the server and any open connections");
	## first shut down each open client session
	my @sessions = $api->get_session_children($api->resolve_alias($SESSION_ALIAS));
	foreach (@sessions)  {
		my $h = $_->get_heap();
		LOG("shutting down session = " . $h->{imei} . " / " . $h->{remote_ip} . "-" . $h->{remote_port});
		$heap->{client}->put("closing connection");
		$kernel->post($_, "shutdown");
	}
	
	$heap->{client}->put("shutting down the server ...");

	## now shutdown the server
	$kernel->post( $SESSION_ALIAS => "shutdown" );
}



##
## process the command 'info'
## = print out some (useful) statistics
##
sub _input_mgmt_info  {
	my ($heap, $kernel) = @_;

	LOG("info requested");
	my $server_heap = $kernel->alias_resolve($SESSION_ALIAS)->get_heap();
	my @sessions = $api->get_session_children($api->resolve_alias($SESSION_ALIAS));
	DEBUG("Server information:");
	DEBUG("-------------------");
	DEBUG("Server startup = " . scalar localtime($server_heap->{stats}->{server_starttime}) );
	DEBUG("Total connections since server startup = " . $server_heap->{stats}->{total_connections} );
	DEBUG("Active connections = " . (scalar @sessions) ); # don't count kernel and server
	DEBUG("Total GP200 sessions seen = " . (scalar keys %{$server_heap->{stats}->{imei}}) );
	DEBUG("Total remote IP's seen = " . (scalar keys %{$server_heap->{stats}->{client_ip}}) );
	DEBUG("Total GP200 packets decoded = " . $server_heap->{stats}->{total_packets_decoded} );
	DEBUG("Total invalid/not allowed packets seen = " . $server_heap->{stats}->{total_invalid_packets} );
	DEBUG("Last packet received = " . scalar localtime($server_heap->{stats}->{last_packet_received}));
	DEBUG("Total management commands received = " . $server_heap->{stats}->{total_mgmt_commands});
	
	$heap->{client}->put("\nServer information:");
	$heap->{client}->put("-------------------");
	$heap->{client}->put("Server startup = " . scalar localtime($server_heap->{stats}->{server_starttime}) );
	$heap->{client}->put("Total connections since server startup = " . $server_heap->{stats}->{total_connections} );
	$heap->{client}->put("Active connections = " . (scalar @sessions) ); # don't count kernel and server
	$heap->{client}->put("Total GP200 sessions seen = " . (scalar keys %{$server_heap->{stats}->{imei}}) );
	$heap->{client}->put("Total remote IP's seen = " . (scalar keys %{$server_heap->{stats}->{client_ip}}) );
	$heap->{client}->put("Total GP200 packets decoded = " . $server_heap->{stats}->{total_packets_decoded} );
	$heap->{client}->put("Total invalid/not allowed packets seen = " . $server_heap->{stats}->{total_invalid_packets} );
	$heap->{client}->put("Last packet received = " . scalar localtime($server_heap->{stats}->{last_packet_received}));
	$heap->{client}->put("Total management commands received = " . $server_heap->{stats}->{total_mgmt_commands});
	
	## print out some statistics for each ip address that has connected
	DEBUG("\nConnection information:");
	DEBUG("-----------------------");
	DEBUG(sprintf("% 15s|% 8s|% 8s|% 8s|% 8s|%30s", "ip", "conn", "pkts", "err", "mgmt", "last pkt received"));
	DEBUG(sprintf("% 15s|% 8s|% 8s|% 8s|% 8s|%30s", "-" x 15, "-" x 8, "-" x 8, "-" x 8, "-" x 8, "-" x 30));

	$heap->{client}->put("\nConnection information:");
	$heap->{client}->put("-----------------------");
	$heap->{client}->put(sprintf("% 15s|% 8s|% 8s|% 8s|% 8s|%30s", "ip", "conn", "pkts", "err", "mgmt", "last pkt received"));
	$heap->{client}->put(sprintf("% 15s|% 8s|% 8s|% 8s|% 8s|%30s", "-" x 15, "-" x 8, "-" x 8, "-" x 8, "-" x 8, "-" x 30));
	
	foreach my $ip (sort keys %{$server_heap->{stats}->{client_ip}})  {
		DEBUG(sprintf("% 15s|% 8s|% 8s|% 8s|% 8s|%30s", $ip, $server_heap->{stats}->{client_ip}->{$ip}->{connections}, $server_heap->{stats}->{client_ip}->{$ip}->{packets}, $server_heap->{stats}->{client_ip}->{$ip}->{invalid_packets}, $server_heap->{stats}->{client_ip}->{$ip}->{total_mgmt_commands}, scalar(localtime $server_heap->{stats}->{client_ip}->{$ip}->{last_packet_received})));

		$heap->{client}->put(sprintf("% 15s|% 8s|% 8s|% 8s|% 8s|%30s", $ip, $server_heap->{stats}->{client_ip}->{$ip}->{connections}, $server_heap->{stats}->{client_ip}->{$ip}->{packets}, $server_heap->{stats}->{client_ip}->{$ip}->{invalid_packets}, $server_heap->{stats}->{client_ip}->{$ip}->{total_mgmt_commands}, scalar(localtime $server_heap->{stats}->{client_ip}->{$ip}->{last_packet_received})));
	}
	
	## print out some statistics for each EMEI that has connected
	DEBUG("\nIMEI information:");
	DEBUG("-----------------");
	DEBUG(sprintf("% 15s|% 8s|% 8s|% 8s|%30s", "imei", "errors", "decoded", "bytes", "last pkt received"));
	DEBUG(sprintf("% 15s|% 8s|% 8s|% 8s|%30s", "-" x 15, "-" x 8, "-" x 8, "-" x 8, "-" x 30));

	$heap->{client}->put("\nIMEI information:");
	$heap->{client}->put("-----------------");
	$heap->{client}->put(sprintf("% 15s|% 8s|% 8s|% 8s|%30s", "imei", "errors", "decoded", "bytes", "last pkt received"));
	$heap->{client}->put(sprintf("% 15s|% 8s|% 8s|% 8s|%30s", "-" x 15, "-" x 8, "-" x 8, "-" x 8, "-" x 30));

	foreach my $imei (sort keys %{$server_heap->{stats}->{imei}})  {
		DEBUG(sprintf("% 15s|% 8s|% 8s|% 8s|%30s", $imei, $server_heap->{stats}->{imei}->{$imei}->{decode_errors}, $server_heap->{stats}->{imei}->{$imei}->{total_packets_decoded}, $server_heap->{stats}->{imei}->{$imei}->{total_bytes_received}, scalar(localtime $server_heap->{stats}->{imei}->{$imei}->{last_packet_decoded})));

		$heap->{client}->put(sprintf("% 15s|% 8s|% 8s|% 8s|%30s", $imei, $server_heap->{stats}->{imei}->{$imei}->{decode_errors}, $server_heap->{stats}->{imei}->{$imei}->{total_packets_decoded}, $server_heap->{stats}->{imei}->{$imei}->{total_bytes_received}, scalar(localtime $server_heap->{stats}->{imei}->{$imei}->{last_packet_decoded})));
	}

}



##
## process the command 'help'
## = print some help about possible commands
##
sub _input_mgmt_help  {
	my ($heap) = @_;

	LOG("info requested");
	$heap->{client}->put("Following commands are allowed:");
	$heap->{client}->put("-------------------------------");
	$heap->{client}->put("quit     = quit the current session");
	$heap->{client}->put("shutdown = completely shut down the listener and quit all sessions");
	$heap->{client}->put("info     = get some info about number of connections etc.");
	$heap->{client}->put("help     = print this help about the available commands");
}








## -----------  CUSTOM CLIENT RELATED TASKS -----------




##
## Store the received GP200 in the database
##
sub store_packet_in_database()  {
	my ($packet) = @_;
	
	DEBUG("store packet in the database\n");
	
	## temp 'event_id' values => 44 = driving, 41 = start datetime found, 40 = stop coordinates found, 44 = avg coordinates found
	
	## initialize variables
	my ($gps_date, $raw_data, $extra);
	my ($imei, $switch, $event_id, $latitude, $longitude, $io, $speed, $direction, $altitude, $power, $battery, $distance, $satellites, $gpssignal, $gsmsignal, $trusted);
	map { $_ = ""; } ($gps_date, $raw_data, $extra);
	map { $_ = 0;  } ($imei, $switch, $event_id, $latitude, $longitude, $io, $speed, $direction, $altitude, $power, $battery, $distance, $satellites, $gpssignal, $gsmsignal, $trusted);
	
	## datetime : could be a 'normal' datetime or a 'start' datetime
	## this is a 'normal' or driving datetime
	if (defined($packet->{datetime}))  {
		$gps_date = sprintf("%04s-%02s-%02s %02s:%02s:%02s", $packet->{datetime}->{year}, $packet->{datetime}->{month}, $packet->{datetime}->{day},
														 $packet->{datetime}->{hour}, $packet->{datetime}->{minute}, $packet->{datetime}->{second});
	}
	## this is a start record
	elsif (defined($packet->{datetime_start})) {
		$gps_date = sprintf("%04s-%02s-%02s %02s:%02s:%02s", $packet->{datetime_start}->{year}, $packet->{datetime_start}->{month}, $packet->{datetime_start}->{day},
														 $packet->{datetime_start}->{hour}, $packet->{datetime_start}->{minute}, $packet->{datetime_start}->{second});
		$event_id = 41;
	}
	
	## coordinates : could be 'stop', 'normal', or 'average'
	## thist is a 'normal' or driving coordinate
	if (defined($packet->{gps_coord}))  {
		$latitude = $packet->{gps_coord}->{latitude};
		$longitude = $packet->{gps_coord}->{longitude};
		$gpssignal = $packet->{gps_coord}->{gps};
		
		$event_id = 44,
	}
	## a stop record
	elsif (defined($packet->{gps_coord_stop}))  {
		$latitude = $packet->{gps_coord_stop}->{latitude};
		$longitude = $packet->{gps_coord_stop}->{longitude};
		$gpssignal = $packet->{gps_coord_stop}->{gps};
		
		$event_id = 40;
	}
	## this is an average coordinate, consider this as a driving coordinate
	elsif (defined($packet->{avg_coord}))  {
		$latitude = $packet->{avg_coord}->{latitude};
		$longitude = $packet->{avg_coord}->{longitude};
		$gpssignal = $packet->{avg_coord}->{gps};
		
		$event_id = 44;
	}
	
	$imei = $packet->{imei}->{number} if (defined($packet->{imei}->{number}));
	$speed = $packet->{speed}->{speed} if (defined($packet->{speed}->{speed}));
	$direction = $packet->{direction}->{direction} if (defined($packet->{direction}->{direction}));
	$altitude = $packet->{altitude}->{height} if (defined($packet->{altitude}->{height}));
	$power = $packet->{powersupply_voltage}->{voltage} if (defined($packet->{powersupply_voltage}->{voltage}));
	$battery = $packet->{battery_voltage}->{voltage} if (defined($packet->{battery_voltage}->{voltage}));
	$distance = $packet->{distance}->{distance} if (defined($packet->{distance}->{distance}));
	$satellites = $packet->{satellites}->{satellites} if (defined($packet->{satellites}->{satellites}));
	$gsmsignal = $packet->{quality_gsm_signal}->{signal} if (defined($packet->{quality_gsm_signal}->{signal}));
	$trusted = $packet->{_info}->{trusted} if (defined($packet->{_info}->{trusted}));
	$raw_data = $packet->{_info}->{packet} if (defined($packet->{_info}->{packet}));
	
	return unless ($USEDB);
	
	if (&_connect_db() > 0)  {
		eval {
			my $sql = "INSERT INTO Events VALUES ('', '$gps_date', $imei, $switch, $event_id, $latitude, $longitude, $io, $speed, $direction, $altitude, $power, $battery, $distance, $satellites, $gpssignal, $gsmsignal, $trusted, '$raw_data', '$extra')";
			DEBUG("insert into database : $sql");
			$MYDBH->do($sql);
		};
		if ($@)  {
			ERROR("unable to insert the record to the database : $@");
		}
	}
	else  {
		# raise error
		ERROR("unable to connect to the databse, incoming event was not saved");
	}
}



sub store_debug_packet_in_db()  {
	my ($payload) = @_;

	if (&_connect_db() > 0)  {
		eval {
			my $sql = "INSERT INTO Events_debug VALUES (NOW(), '$payload')";
			DEBUG("insert into debug database table : $sql");
			$MYDBH->do($sql);
		};
		if ($@)  {
			ERROR("unable to insert the record into the debug database table : $@");
		}
	}
	else  {
		# raise error
		ERROR("unable to connect to the databse, incoming event was not saved in the debug table");
	}
}





## 
## check if we still have a connection to the database, if not then make the connection
##
sub _connect_db  {

	if ($MYDBH)  {
		## check if the connection's still ok
		DEBUG("verify database connection");
		## we keep the database connection open to optimize for many incoming requests
		## but it could have timed out so let's do a short test
		eval {
			my $sql = "select now()";
			DEBUG("execute test : $sql", 8);
			$MYDBH->do($sql);
		};
		if ($@)  {
			DEBUG("databse connection was lost, we'll need to re-connect");
			undef $MYDBH;
		}
		else {
			DEBUG("database connection seems to work", 5);
			return 1;
		}
	}

	eval {
		DEBUG("make a new connection to the database");
		$MYDBH = DBI->connect("DBI:mysql:database=$MYDB;host=$MYSERVER;port=$MYPORT", "$MYUSER", "$MYPASS", {'RaiseError' => 1});
	};
	if ($@)  {
		# raise error
		ERROR("database connection failed : $@");
		return -1;
	}
	
	return 1;
}

    