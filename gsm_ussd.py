import argparse
import atexit
import binascii
import codecs
import logging
import os
import re
import signal
import stat
import sys
import termios
import time

import pexpect
import pexpect.fdpexpect
import serial
import smspdu

VERSION            	= '1.0'          	# Our version
modemport          	= '/dev/ttyUSB1'   	# AT port of a Huawei E160 modem
modem_lockfile     	= None            	# The modem lockfile (e.g. /var/run/LCK..ttyUSB1)
modem_fh           	= None
timeout_for_answer 	= 20               	# Timeout for modem answers in seconds
ussd_queries   		= [ '*124#' ]       # Prepaid account query as default
use_cleartext      	= None            	# Need to encode USSD query?
cancel_ussd_session	= False             # User wants to cancel an ongoing USSD session
show_online_help   	= 0                	# Option flag online help
debug              	= False             # Option flag debug mode
expect             	= None            	# The Expect object
expect_logfilename 	= None            	# Filename to log the modem dialog into
pin                	= None            	# Value for option PIN
all_args       		= sys.argv[1:]     	# Backup of args to print them for debug

num_net_reg_retries = 10               	# Number of retries if modem is not already
										# registered in a net
saved_stty_value	= None
gsm_codec 			= None

# Consts
success         =  1
fail            =  0
exit_success    =  0
exit_nopin      =  1
exit_wrongpin   =  2
exit_nonet      =  3
exit_error      =  4
exit_bug        = 10

gsm_error = {
	# CMS ERRORs are network related errors
	'+CMS ERROR' : {
		  '1' : 'Unassigned number',
		  '8' : 'Operator determined barring',
		 '10' : 'Call bared',
		 '21' : 'Short message transfer rejected',
		 '27' : 'Destination out of service',
		 '28' : 'Unindentified subscriber',
		 '29' : 'Facility rejected',
		 '30' : 'Unknown subscriber',
		 '38' : 'Network out of order',
		 '41' : 'Temporary failure',
		 '42' : 'Congestion',
		 '47' : 'Recources unavailable',
		 '50' : 'Requested facility not subscribed',
		 '69' : 'Requested facility not implemented',
		 '81' : 'Invalid short message transfer reference value',
		 '95' : 'Invalid message unspecified',
		 '96' : 'Invalid mandatory information',
		 '97' : 'Message type non existent or not implemented',
		 '98' : 'Message not compatible with short message protocol',
		 '99' : 'Information element non-existent or not implemente',
		'111' : 'Protocol error, unspecified',
		'127' : 'Internetworking , unspecified',
		'128' : 'Telematic internetworking not supported',
		'129' : 'Short message type 0 not supported',
		'130' : 'Cannot replace short message',
		'143' : 'Unspecified TP-PID error',
		'144' : 'Data code scheme not supported',
		'145' : 'Message class not supported',
		'159' : 'Unspecified TP-DCS error',
		'160' : 'Command cannot be actioned',
		'161' : 'Command unsupported',
		'175' : 'Unspecified TP-Command error',
		'176' : 'TPDU not supported',
		'192' : 'SC busy',
		'193' : 'No SC subscription',
		'194' : 'SC System failure',
		'195' : 'Invalid SME address',
		'196' : 'Destination SME barred',
		'197' : 'SM Rejected-Duplicate SM',
		'198' : 'TP-VPF not supported',
		'199' : 'TP-VP not supported',
		'208' : 'D0 SIM SMS Storage full',
		'209' : 'No SMS Storage capability in SIM',
		'210' : 'Error in MS',
		'211' : 'Memory capacity exceeded',
		'212' : 'Sim application toolkit busy',
		'213' : 'SIM data download error',
		'255' : 'Unspecified error cause',
		'300' : 'ME Failure',
		'301' : 'SMS service of ME reserved',
		'302' : 'Operation not allowed',
		'303' : 'Operation not supported',
		'304' : 'Invalid PDU mode parameter',
		'305' : 'Invalid Text mode parameter',
		'310' : 'SIM not inserted',
		'311' : 'SIM PIN required',
		'312' : 'PH-SIM PIN required',
		'313' : 'SIM failure',
		'314' : 'SIM busy',
		'315' : 'SIM wrong',
		'316' : 'SIM PUK required',
		'317' : 'SIM PIN2 required',
		'318' : 'SIM PUK2 required',
		'320' : 'Memory failure',
		'321' : 'Invalid memory index',
		'322' : 'Memory full',
		'330' : 'SMSC address unknown',
		'331' : 'No network service',
		'332' : 'Network timeout',
		'340' : 'No +CNMA expected',
		'500' : 'Unknown error',
		'512' : 'User abort',
		'513' : 'Unable to store',
		'514' : 'Invalid Status',
		'515' : 'Device busy or Invalid Character in string',
		'516' : 'Invalid length',
		'517' : 'Invalid character in PDU',
		'518' : 'Invalid parameter',
		'519' : 'Invalid length or character',
		'520' : 'Invalid character in text',
		'521' : 'Timer expired',
		'522' : 'Operation temporary not allowed',
		'532' : 'SIM not ready',
		'534' : 'Cell Broadcast error unknown',
		'535' : 'Protocol stack busy',
		'538' : 'Invalid parameter',
	},
	# CME ERRORs are equipment related errors (missing SIM etc.)
	'+CME ERROR' : {
		  '0' : 'Phone failure',
		  '1' : 'No connection to phone',
		  '2' : 'Phone adapter link reserved',
		  '3' : 'Operation not allowed',
		  '4' : 'Operation not supported',
		  '5' : 'PH_SIM PIN required',
		  '6' : 'PH_FSIM PIN required',
		  '7' : 'PH_FSIM PUK required',
		 '10' : 'SIM not inserted',
		 '11' : 'SIM PIN required',
		 '12' : 'SIM PUK required',
		 '13' : 'SIM failure',
		 '14' : 'SIM busy',
		 '15' : 'SIM wrong',
		 '16' : 'Incorrect password',
		 '17' : 'SIM PIN2 required',
		 '18' : 'SIM PUK2 required',
		 '20' : 'Memory full',
		 '21' : 'Invalid index',
		 '22' : 'Not found',
		 '23' : 'Memory failure',
		 '24' : 'Text string too long',
		 '25' : 'Invalid characters in text string',
		 '26' : 'Dial string too long',
		 '27' : 'Invalid characters in dial string',
		 '30' : 'No network service',
		 '31' : 'Network timeout',
		 '32' : 'Network not allowed, emergency calls only',
		 '40' : 'Network personalization PIN required',
		 '41' : 'Network personalization PUK required',
		 '42' : 'Network subset personalization PIN required',
		 '43' : 'Network subset personalization PUK required',
		 '44' : 'Service provider personalization PIN required',
		 '45' : 'Service provider personalization PUK required',
		 '46' : 'Corporate personalization PIN required',
		 '47' : 'Corporate personalization PUK required',
		 '48' : 'PH-SIM PUK required',
		'100' : 'Unknown error',
		'103' : 'Illegal MS',
		'106' : 'Illegal ME',
		'107' : 'GPRS services not allowed',
		'111' : 'PLMN not allowed',
		'112' : 'Location area not allowed',
		'113' : 'Roaming not allowed in this location area',
		'126' : 'Operation temporary not allowed',
		'132' : 'Service operation not supported',
		'133' : 'Requested service option not subscribed',
		'134' : 'Service option temporary out of order',
		'148' : 'Unspecified GPRS error',
		'149' : 'PDP authentication failure',
		'150' : 'Invalid mobile class',
		'256' : 'Operation temporarily not allowed',
		'257' : 'Call barred',
		'258' : 'Phone is busy',
		'259' : 'User abort',
		'260' : 'Invalid dial string',
		'261' : 'SS not executed',
		'262' : 'SIM Blocked',
		'263' : 'Invalid block',
		'772' : 'SIM powered down',
	}
}


# This is a list of modems that need the PDU format for query
# As of now, these are all Huaweis...
pdu_modems = (
	'E160',
	'E165G',
	'E1550',
	'E3372',
)

def main():
	global modemport, modem_fh, timeout_for_answer, pin
	global use_cleartext, cancel_ussd_session, debug
	global expect, expect_logfilename, ussd_queries
	global modem_lockfile, saved_stty_value, gsm_codec

	# Set up signal handler for INT (Ctrl-C) and TERM
	signal.signal(signal.SIGINT, clean_exit)
	signal.signal(signal.SIGTERM, clean_exit)
	
	# Parse options and react to them
	parser = create_cmd_line_parser()
	parsed = parser.parse_args()
	
	if parsed.modem != None:
		modemport = parsed.modem
	if parsed.timeout:
		timeout_for_answer = parsed.timeout
	if parsed.pin != None:
		pin = parsed.pin
	if parsed.cleartext:
		use_cleartext = True
	if parsed.no_cleartext:
		use_cleartext = False
	if parsed.cancel:
		cancel_ussd_session = True
	if parsed.debug:
		debug = True
	if parsed.logfile != None:
		expect_logfilename = parsed.logfile
	
	loglevel = logging.DEBUG if debug else logging.INFO
	logging.basicConfig(level=loglevel)
						
	# Further arguments are USSD queries
	if parsed.ussd_queries:
		ussd_queries = parsed.ussd_queries
	
	logging.debug("Start, Version %s, Args: %s", VERSION, all_args)
	
	gsm_codec = smspdu.gsm0338()
	
	check_modemport(modemport)

	# Obtain exclusive access to modem
	modem_lockfile = lock_modemport(modemport)
	if not modem_lockfile:
		logging.error("Can't get lock file for %s!\n" +
			"* Wrong modem device? (use -m <dev>)?\n" +
			"* Stale lock file for %s in /var/lock?", 
			modemport, modemport)
		sys.exit(exit_error)
		
	# Locking succeeded, so set up exit hook
	atexit.register(clean_up)

	logging.debug("Opening modem")
	try:
		modem_fh = serial.serial_for_url(modemport, timeout=timeout_for_answer)
	except serial.SerialException as exc:
		logging.error("Modem port %s could not be opened: %s", 
			modemport, exc)
		sys.exit(exit_error)
		
	saved_stty_value = save_serial_opts(modem_fh)
	set_serial_opts(modem_fh)
	
	logging.debug("Initialising Expect")
	expect_logfile = None
	if expect_logfilename:
		expect_logfile = open(expect_logfilename, 'a')
	expect	= pexpect.fdpexpect.fdspawn(modem_fh.fileno(), 
		logfile=expect_logfile)
	expect_setup()
	
	set_modem_echo(True)
	
	modem_model = get_modem_model()
	if modem_model == None:
		modem_model = ''
		
	if use_cleartext == None:
		if modem_needs_pdu_format(modem_model):
			logging.debug("Modem type \"%s\" needs PDU format for " +
				"USSD query.", modem_model)
			use_cleartext = False
		else:
			logging.debug("Modem type \"%s\" needs cleartext " +
				"for USSD query.", modem_model)
			use_cleartext = True
	
	if pin_needed():
		logging.debug("PIN needed")
		if pin == None:
			logging.error("SIM card is locked, but no PIN to unlock " +
				"given.\nUse \"-p <pin>\"!\n")
			sys.exit(exit_nopin)
		if enter_pin(pin):
			logging.debug("Pin %s accepted.", pin)
		else:
			logging.error("SIM card is locked, PIN %s not accepted!\n" +
				"Start me again with the correct PIN!\n", pin)
			sys.exit(exit_wrongpin)

	net_is_available, reason = get_net_registration_state(
		num_net_reg_retries)
	if not net_is_available:
		logging.error("Sorry, no network seems to be available:\n%s\n",
			reason)
		sys.exit(exit_nonet)
		
	if cancel_ussd_session:
		cancel_result = try_cancel_ussd_session()
		if cancel_result['ok']:
			print(cancel_result['msg'])
		else:
			sys.stderr.write(cancel_result['msg'] + "\n")
	else:
		for ussd_query in ussd_queries:
			if not is_valid_ussd_query(ussd_query):
				sys.stderr.write(("\"{0}\" is not a valid USSD " +
					"query - ignored.\n").format(ussd_query))
				continue
				
			ussd_result = do_ussd_query(ussd_query)
			if ussd_result['ok']:
				print(ussd_result['msg'])
			else:
				sys.stderr.write(ussd_result['msg'] + "\n")

	logging.debug("Shutting down")
	sys.exit(exit_success) # will give control to clean_up

def clean_exit(signum, frame):
	"""This is the signal handler for SIGINT & SIGTERM
	
	Arguments:
		signum- Number of the caught signal
	Returns:  
		None; just exits giving control to the clean_up routine
	"""
	if signum == signal.SIGINT:
		logging.warn("SIGINT caught, terminating")
		sys.exit(128 + 2)
	elif signum == SIGTERM:
		logging.warn("SIGTERM caught, terminating")
		sys.exit(128 + 15)
	else:
		logging.error("Signal %d caught, terminating. This should not " +
			"have happened.", signum)
		sys.exit(exit_bug)
	
def clean_up():
	"""Check for resources in use and free them

	Returns:  
		None. Will be called during sys.exit().
	"""
	global modem_lockfile, modem_fh, saved_stty_value, expect
	
	logging.debug("END: Cleaning up")
	if modem_fh:
		if saved_stty_value != None:
			logging.debug("END: Resetting serial interface")
			restore_serial_opts(modem_fh, saved_stty_value)
		logging.debug("END: Closing modem interface")
		modem_fh.close()
	if expect and expect.logfile:
		logging.debug("END: Closing expect log file")
		expect.logfile.close()
	if modem_lockfile:
		logging.debug("END: Removing lock file %s", modem_lockfile)
		unlock_modemport(modem_lockfile)
		
def check_modemport(mp):
	"""Performs preliminary checks on provided modem port.
	
	Arguments:
		mp - File to check as modem port
	Returns:
		void, exits if modem port check fails
	"""
	try:
		fstat = os.lstat(mp)
	except OSError:
		logging.error("Modem port \"%s\" doesn't exist. Possible causes:\n" +
			"* Modem not plugged in/connected\n" +
			"* Modem broken\n" +
			"Perhaps use another device with -m?\n", mp)
		sys.exit(exit_error)
	# Check whether modem is a character device
	if not stat.S_ISCHR(fstat.st_mode):
		logging.error("Modem device \"%s\" is not character device file. Possible causes:\n" +
			"* Wrong device file given (-m ?)\n" +
			"* Device file broken?\n" +
			"Please check!\n", mp)
		sys.exit(exit_error)

	mode = stat.S_IMODE(fstat.st_mode)
	# Check whether modem port is readable
	if not (mode & stat.S_IRUSR):
		logging.error("Can't read from device \"%s\".\n" +
			"Set correct rights for \"%s\" with chmod?\n" +
			"Perhaps use another device with -m?\n", mp, mp)
		sys.exit(exit_error)
	# Check whether modem port is writable
	if not (mode & stat.S_IWUSR):
		logging.error("Can't write to device \"%s\".\n" +
			"Set correct rights for \"%s\" with chmod?\n" +
			"Perhaps use another device with -m?\n", mp, mp)
		sys.exit(exit_error)
	
def lock_modemport(modem_device):
	"""
	Creates a lock file to ensure exclusive access to modem.
	
	Arguments:
		modem_device - The device to set a lock file for
	Returns:
		The lock file name or None if no lockfilename can be worked out
	"""
	
	lock_dir = '/var/lock'
	lock_filename = re.search("/([^/]*)$", modem_device, 
		re.MULTILINE)
	if not lock_filename:
		logging.warn("Modem device \"%s\" looks strange, can't lock it",
			modem_device)
		return None
	
	# Extract the file name.
	lock_filename = lock_filename.group(1)
	lock_file = lock_dir + '/LCK..' + lock_filename
	
	# Now try obtaining lock
	lock_handle = None
	try:
		lock_handle = os.open(lock_file, 
				os.O_CREAT|os.O_WRONLY|os.O_EXCL, 0644)
	except OSError as exc:
		logging.warn("Can't get lockfile %s: %s", #- probably already in use!",
			lock_file, exc)
		return None
	else:
		logging.debug("Lock %s set", lock_file)
		return lock_file
	finally:
		if lock_handle:
			os.close(lock_handle)

def unlock_modemport(lock_filename):
	"""
	Unlocks mutex around modem.
	
	Arguments:
		lock_filename - Lockfile to delete
	Returns:
		None
	"""	
	
	try:
		fstat = os.lstat(lock_filename)
		if not stat.S_ISREG(fstat.st_mode):
			logging.debug("Lock file \"%s\" doesn't exist or is not " +
				"a normal file!", lock_filename)
		else:
			os.unlink(lock_filename)
	except OSError as exc:
		logging.warn("Can't remove lock file \"%s\": %s",
			lock_filename, exc)
			
def save_serial_opts(interface):
	"""
	Saves the current settings on a serial interface to allow for 
	a reset.
	
	Arguments:
		 interface - The file handle to remember termios values of
	
	Returns:  
		dictionary containing the termios values found;
		None in case of errors
	"""
	
	logging.debug("Saving serial state")
	try:
		termdata = termios.tcgetattr(interface)
		return termdata
	except Exception as exc:
		logging.error("Saving serial state failed: %s", exc)
		return None

def restore_serial_opts(interface, termdata):
	"""Resets state of serial interface
	
	Arguments:
		interface - The file handle to restore termios values for
		termdata - dictionary (return value of save_serial_opts)
	Returns:
		True if state was successfully reset; False if state could not
		be restored.
	"""
	logging.debug("Restore serial state")
	try:
		termios.tcsetattr(interface, termios.TCSANOW, termdata)
	except Exception as exc:
		logging.error("Restoring serial state failed: %s", exc)
		return False
	return True
	
def set_serial_opts(interface):
	"""Sets state of serial interface for use in ussd queries.
	
	Arguments:
		interface - The file handle to set termios values for
	Returns:
		True on success; false on failure.
	"""
	logging.debug("Setting serial state")
	try:
		termdata = termios.tcgetattr(interface)
		
		# Sets the terminal to raw mode/line discipline, as opposed to
		# cooked discipline: input is available character by character,
		# echoing is disabled, and all special processing of terminal 
		# input and output characters is disabled.
		
		# Check termios(2) unix man page, section on Raw mode.
		
		termdata[0] = 0 # Nothing on iflag!
		termdata[1] = 0 # oflag
		termdata[2] = termios.CS8 | termios.HUPCL | termios.CREAD | \
			termios.CLOCAL # cflag
		termdata[3] = 0  # Nothing on lflag!
		
		termios.tcsetattr(interface, termios.TCSANOW, termdata)
	except Exception as exc:
		logging.error("Setting serial state failed: %s", exc)
		return False
	return True
	
def expect_setup():
	global expect_programs
	
	def wait_for_OK_sub1(expect, actionMapUsed, startTime):
		"""AT command (TTY echo of input)"""
		
		logging.debug("AT found, -> %s", expect.match.group())
		my_expect(actionMapUsed, startTime) # exp_continue_timeout
		
	def wait_for_OK_sub2(expect, actionMapUsed, startTime):
		"""Modem answers to command"""
		
		logging.debug("OK/ERROR found: %s", expect.match.group(1))
	
	def wait_for_cmd_ans_sub1(expect, actionMapUsed, startTime):
		"""The expected result"""
		
		match = expect.match.group()		
		
		match = re.sub(r'(?:^\s+|\s+$)', '', match) # Trim match
		logging.debug("Expected answer: %s", match)
		
	def wait_for_cmd_ans_sub2(expect, actionMapUsed, startTime):
		"""AT command (TTY echo of input)"""
		
		logging.debug("AT found, -> %s", expect.match.group())
		my_expect(actionMapUsed, startTime) # exp_continue_timeout
	
	def wait_for_cmd_ans_sub3(expect, actionMapUsed, startTime):
		"""OK means that the query was successfully sent into the
		net. Carry on!"""
		
		logging.debug("OK found, continue waiting for result") 
		my_expect(actionMapUsed) # exp_continue
		
	def wait_for_cmd_ans_sub4(expect, actionMapUsed, startTime):
		"""ERROR means that the command wasn't syntactically correct
		order couldn't be understood (wrong encoding?). Stop here,
		as no more meaningful results can be expected."""
		
		logging.error("ERROR found, aborting")	
	
	# The Expect programs differ in the way they react to modem answers
	expect_programs = {
		# wait_for_OK:  The modem will react with OK/ERROR/+CM[SE] ERROR
		#               This in itself will be the result, further information
		#               might be available between AT... and OK.
		'wait_for_OK' :  [
			# Ignore status messages
			( 
				r'(?i)\r\n([\+\^](?:BOOT|DSFLOWRPT|MODE|RSSI|SIMST|SRVST)):[ ]*([^\r\n]*)\r\n',
					ignore_state_line
			),
			# Identify +CREG status message
			# (+CREG modem answer has got two arguments "\d,\d"!)
			( 
				r'(?i)\r\n(\+CREG):[ ]*(\d)\r\n',
					ignore_state_line
			),
			# Fail states of the modem (network lost, SIM problems, ...)
			( 
				r'(?i)\r\n(\+CM[SE] ERROR):[ ]*([^\r\n]*)\r\n',
					network_error
			),
			# AT command (TTY echo of input)
			( 
				r'(?i)^AT([^\r\n]*)\r',
					wait_for_OK_sub1
			),
			# Modem answers to command
			(
				r'(?i)\r\n(OK|ERROR)\r\n',
					wait_for_OK_sub2
			),
		],
		# wait_for_cmd_answer:
		#               The command answers with OK/ERROR, but the real
		#               result will arrive later out of the net
		'wait_for_cmd_answer' :  [
			# Ignore status messages
			(
				r'(?i)\r\n(\^(?:BOOT|DSFLOWRPT|MODE|RSSI|SIMST|SRVST)):[ ]*([^\r\n]*)\r\n',
					ignore_state_line
			),
			# Identify +CREG status message
			# (+CREG modem answer has got two arguments "\d+, \d+"!)
			( 
				'(?i)\r\n(\+CREG):[ ]*(\d)\r\n',
					ignore_state_line
			),
			# Fail states of the modem (network lost, SIM problems, ...)
			(
				r'(?i)\r\n(\+CM[SE] ERROR):[ ]*([^\r\n]*)\r\n',
					network_error
			),
			# The expected result - all state messages have already been
			# dealt with. Everything that reaches this part has to be the
			# result of the sent command.
			# Some more checks of that?
			( 
				#r'(?i)\r\n(\+[^:]+):[ ]*([^\r\n]*)\r\n',
				r'(?is)\r\n(\+[^:]+):[ ]*(.*)\r\n', # changed to deal with newlines in message
					wait_for_cmd_ans_sub1
			),
			# AT command (TTY echo of input)
			(
				r'(?i)^AT([^\r\n]*)\r',
					wait_for_cmd_ans_sub2
			),
			# OK means that the query was successfully sent into the
			# net. Carry on!
			(
				r'(?i)\r\n(OK)\r\n',
					wait_for_cmd_ans_sub3
			),
			# ERROR means that the command wasn't syntactically correct
			# order couldn't be understood (wrong encoding?). Stop here,
			# as no more meaningful results can be expected.
			(
				r'(?i)\r\n(ERROR)\r\n',
					wait_for_cmd_ans_sub4
			),
		],
	}

def ignore_state_line(expect, actionMapUsed, startTime):
	"""Ignore status messages"""
	
	state_name = expect.match.group(1)
	result = expect.match.group(2)

	logging.debug("%s: %s, ignored", state_name, result);
	my_expect(actionMapUsed, startTime) # exp_continue_timeout

def network_error(expect, actionMapUsed, startTime):
	"""Fail states of the modem (network lost, SIM problems, ...)
	"""

	error_msg_type = expect.match.group(1)
	error_msg_value = expect.match.group(2)

	logging.error("Network error %s with data \"%s\" detected.",
		error_msg_type, error_msg_value)

def my_expect(actionMap, startTime=0):
	"""Extends pexpect.expect() to dispatch matches to handlers,
	and implement Perl Expect's functions exp_continue and
	exp_continue_timeout.
	
	Arguments:
		actionMap - map of expectations to handlers (actually a list of
					pairing of pattern to handler).
		 startTime - If 0 (the default), expect is called with
					timeout reset to timeout_for_answer global. 
					Else function call is treated as a kind of
					continuation of some processing, and so the time
					spent since the startTime argument value is
					subtracted from the timeout_for_answer global.
	Returns:
		None. Exits if there are unmatched/unhandled expectations.
	"""
	global expect, timeout_for_answer
	
	# Determine time to subtract from timeout_for_answer
	timeAlreadyTaken = 0
	if startTime > 0:
		timeAlreadyTaken = time.time() - startTime
	else:
		startTime = time.time()

	# After expect...
	index = expect.expect(map(lambda x : x[0], actionMap), 
		timeout=timeout_for_answer - timeAlreadyTaken)
	# ... Call handler to process particular expectation.
	if index in range(len(actionMap)):
		handler = actionMap[index][1]
		handler(expect, actionMap, startTime)
	else:
		logging.error("Expect processing failure: No action found " +
			"for pattern %s", actionMap[index][0])
		sys.exit(exit_bug)
	
def set_modem_echo(echo_on):
	if echo_on:
		modem_echo_command = 'ATE1'
		logging.debug("Enabling modem echo (%s)",
			modem_echo_command)
	else:
		modem_echo_command = 'ATE0'
		logging.debug("Disabling modem echo (%s)",
			modem_echo_command)

	result = send_command(modem_echo_command, 'wait_for_OK')
	if result['ok']: 
		logging.debug("%s successful", modem_echo_command)
		return True
	else:
		logging.error("%s failed, error: %s", modem_echo_command,
			result['description'])
		return False
		
def get_modem_model():
	"""Queries modem for its model.
	
	Different modems report *very* different things here, 
	but it's enough to see if it's a Huawei E160 or K3565 modem.
	
	Returns: 
		Name of the modem model
		None if no name is found
	"""
	
	logging.debug("Querying modem type")
	result = send_command("AT+CGMM", 'wait_for_OK')
	if result['ok']:
		logging.info("Modem type found: %s", result['description'])
		return result['description']
	else:
		logging.error("No modem type found: %s", result['description'])
		return None
		
def send_command(cmd, how_to_react):
	"""Sends a command over serial line and waits for reply or error.

	Arguments:
		cmd - String holding the command to send (usually 
			  something like "AT...")
		how_to_react - String explaining which Expect program to use:
					   wait_for_OK
						   return immediately in case of OK/ERROR
					   wait_for_cmd_answer
						   Break in case of ERROR, but wait for 
						   the real result after OK
	Returns:  
		Dictionary result of sent command with the ff keys:
		   'ok':   	
					value of success global variable if AT command 
					successfully transmitted and answer received
					fail if AT command aborted or not able to send
		   'match': 
					What expect matched,
				   'OK'|'ERROR'|'+CME ERROR'|'+CMS ERROR'
		   'description':
					Error description, OK/ERROR, output of modem
					between AT command and OK, result of USSD query
					after OK, all in accordance to key 'ok' and
					arg how_to_react
	"""

	if how_to_react not in expect_programs:
		logging.error("This should not have happened - " +
			"unknown expect program \"%s\" wanted!\n" +
			"This is a bug, please report!\n", how_to_react)
		sys.exit(exit_bug)
		
	logging.debug("Sending command: %s", cmd)    
	try:
		expect.send("{0}\r".format(cmd))
		my_expect(expect_programs[how_to_react])
	except pexpect.TIMEOUT, error:
		return {
			'ok' 			: fail, # global variable
			'match' 		: error,
			'description' 	: "No answer for %d seconds!" %
				timeout_for_answer,
		}
	except pexpect.EOF, error:
		return {
			'ok' 			: fail, # global variable
			'match' 		: error,
			'description' 	: "EOF from modem received - modem unplugged?"
		}
	except Exception as exc:
		error = str(exc)
		return {
			'ok'          : fail, # global variable
			'match'       : error,
			'description' : "PANIC! Can't happen - unknown Expect " +
				"error \"%s\"" % error
		}

	matched_pattern_pos = expect.match.start(),
	match_string = expect.match.group()
	before_match = expect.before
	after_match = expect.after

	first_word = expect.match.group(1)
	args = expect.match.groups(2)
	first_word = first_word.upper()
	match_string = re.sub(r'(?:^\s+|\s+$)', '', 
		match_string) # crop whitespace
	if first_word == 'ERROR':
		# OK/ERROR are two of the three "command done" markers.
		return {
			'ok'          :  fail,
			'match'       :  match_string,
			'description' : 'Broken command',
		}
	elif first_word == '+CMS ERROR':
		# After this error there will be no OK/ERROR anymore
		errormessage = translate_gsm_error(first_word, args)
		return {
			'ok'          : fail,
			'match'       : match_string,
			'description' : "GSM network error: %s (%s)" %
								(errormessage, args),
		}
	elif first_word == '+CME ERROR':
		# After this error there will be no OK/ERROR anymore
		errormessage = translate_gsm_error(first_word, args)
		return {
			'ok'          : fail,
			'match'       : match_string,
			'description' : "GSM equipment error: %s (%s)" %
								(errormessage, args),
		}
	elif first_word == 'OK':
		# before_match contains data between AT and OK
		before_match = re.sub(r'(?:^\s+|\s+$)', '',
				before_match) # crop whitespace
		return {
			'ok'          : success,
			'match'       : match_string,
			'description' : before_match,
		}
	elif re.search(r'^[\^\+]', first_word):
		return {
			'ok'          : success,
			'match'       : match_string,
			'description' : match_string,
		}
	else:
		return {
			'ok'          : fail,
			'match;'      : match_string,
			'description' : "PANIC! Can't parse Expect " +
								"result: \"%s\"" % match_string
		}

def translate_gsm_error(error_type, error_number):
	"""Gets the description of a GSM error code.
	
	Arguments:
		error_type - "CMS ERROR" or "CME ERROR"
			CME ERRORs are equipment related errors (missing SIM etc.)
			CMS ERRORs are network related errors
		error_number - the error number to translate
			If the error number ist found not be a unsigned integer,
			it it returned as is - we were probably given a clear
			text error message
	Returns:  
		The error message corresponding to the error number
		GSM error codes found at 
		http://www.activexperts.com/xmstoolkit/sms/gsmerrorcodes/
	"""

	if not re.search(r'^\d+$', error_number):
		# We have probably been given an already readable error message.
		# The E160 is strange: Some error messages are english, some
		# are plain numbers!
		return error_number
	elif error_number in gsm_error[error_type]:
		# Translate the number into message
		return gsm_error[error_type][error_number]

	# Number not found
	return 'No error description available'
	
def modem_needs_pdu_format(model):
	"""Determines whether modem needs PDU forma for USSD queries.
	
	Arguments:
		model - The model type reported by the modem

	Returns:  
		False  -   Modem type needs cleartext USSD query
		True   -   Modem type needs PDU format
	"""
	
	return model in pdu_modems
	
def pin_needed():
	"""Determines whether SIM card needs to be unlocked with PIN/PUK.
	
	Returns:  
		False - No PIN needed, SIM card is unlocked
		True  - PIN (or PUK) still needed, SIM card still locked
	"""
	
	logging.debug ("Starting SIM state query (AT+CPIN?)")
	result = send_command('AT+CPIN?', 'wait_for_OK')
	if result['ok']:
		logging.debug ("Got answer for SIM state query")
		if result['match'] == 'OK':
			if re.search('READY', result['description']):
				logging.debug ("SIM card is unlocked")
				return False
			elif re.search('SIM PIN', result['description']):
				logging.debug ("SIM card is locked")
				return True
			else:
				logging.debug("Couldn't parse SIM state query result: " +
					result['description'])
				return  True
		else:
			logging.debug ("SIM card locked - failed query? -> " +
				result['match'])
			return True
	else:
		logging.debug ("SIM state query failed, error: " +
			result['description'])
		return True

def enter_pin(pin):
	"""Tries to unlock modem using given pin.
	
	Arguments:
		pin - The PIN to unlock the SIM card
	Returns:
		False - Unlocking the SIM card failed
		True - SIM is now unlocked
	"""

	logging.debug("Unlocking SIM using PIN $pin");
	result = send_command("AT+CPIN=" + pin, 'wait_for_OK')
	if result['ok']:
		logging.debug("SIM card unlocked: %s", result['match'])
		return True
	else:
		logging.debug("SIM card still locked, error: %s", 
			result['description'])
		return False


def get_net_registration_state(max_tries):
	"""Tries to get modem registration state
	
	Arguments:     
		max_tries - Number of tries 
	Returns:  
		False - No net available
		True  - Modem is registered in a net
	"""
	wait_time_between_net_checks    = 3
	last_state_message              = ''

	logging.debug("Waiting for net registration, max %d tries",
			max_tries)
	for num_tries in range(0, max_tries):
		logging.debug("Try: %d", num_tries+1)
		result = send_command('AT+CREG?', 'wait_for_OK')
		if result['ok']:
			logging.debug("Net registration query result received, " +
				'parsing')
			match = re.search(r'(?i)\+CREG:\s+(\d),(\d)', 
				result['description'])
			if not match or len(match.groups()) < 2:
				last_state_message = "Cannot parse +CREG answer: " +\
					result['description'] 
				logging.debug(last_state_message)
				return (False, last_state_message)
			n, stat = int(match.group(1)), int(match.group(2))
			if stat == 0:
				last_state_message = 'Not registered, MT not ' +\
					'searching a new operator to register to'
				logging.debug(last_state_message)
				return (False, last_state_message)
			elif stat == 1:
				last_state_message = 'Registered, home network'
				logging.debug(last_state_message)
				if num_tries != 0:
					logging.debug("Sleeping one more time for " +
						'settling in')
					time.sleep(wait_time_between_net_checks)
				return (True, last_state_message)
			elif stat == 2:
				last_state_message = 'Not registered, currently ' +\
					'searching new operator to register to'
				logging.debug(last_state_message)
			elif stat == 3:
				last_state_message = 'Registration denied'
				logging.debug(last_state_message)
				return (False, last_state_message)
			elif stat == 4:
				last_state_message = 'Registration state unknown'
				logging.debug(last_state_message)
			elif stat == 5:
				last_state_message = 'Registered, roaming'
				logging.debug(last_state_message)
				if num_tries != 0:
					logging.debug('Sleeping one more time for ' +
						'settling in')
					time.sleep(wait_time_between_net_checks)
				return (True, last_state_message)
			else:
				last_state_message = "Cannot understand net reg " +\
					"state code " + stat;
				logging.debug(last_state_message)
		else:
			last_state_message = "Querying net registration failed, " +\
				'error: ' + result['description']
			logging.debug(last_state_message)
			return (False, last_state_message)
		if (num_tries + 1) < max_tries:
			logging.debug ("Sleeping for %d seconds",
				wait_time_between_net_checks)
			time.sleep(wait_time_between_net_checks)
	return (False, ("No net registration in %d tries found, " +
		"last result:\n%s") % (max_tries, last_state_message))

def try_cancel_ussd_session():
	"""Tries to cancel a ussd session.
	
	Returns:  
		dictionary with the ff keys: 
			'ok':   value of success global variable if USSD query 
					successfully transmitted and answer received
					value of fail global variable if USSD query 
					aborted or not able to send
			'msg':  Error message or USSD query result, in accordance
					to the value of 'ok'.
	"""
	logging.debug('Trying to cancel USSD session')
	result = send_command("AT+CUSD=2\r", 'wait_for_OK')
	if result['ok']:
		msg = 'USSD cancel request successful'
		logging.debug(msg)
		return { 'ok' : success, 'msg' : msg }
	else:
		msg = 'No USSD session to cancel.'
		logging.debug(msg)
		return { 'ok' : fail, 'msg' : msg }
		
def is_valid_ussd_query(query):
	"""Checks that query is either a valid USSD code, or a 
	numeric input.

	Arguments:
		query - The USSD query to check

	Returns:  
		False -   Query contains illegal characters
		True  -   Query is legal
	"""
	
	# The first RegExp checks for a standard USSD
	# The second allows simple numbers as used by USSD sessions
	if re.search(r'^\*[0-9*]+#$', query) or \
			re.search(r'^\d+$', query):
		return True
	return False

def do_ussd_query(query):
	"""Dials a USSD code and gets response.
	
	 Arguments:
		query - The USSD query to send ('*124')
	 Returns:
		dictionary with the ff keys:
			'ok':   value of success global variable if USSD query 
					successfully transmitted and answer received
					value of fail global variable if USSD query 
					aborted or not able to send
			'msg':  Error message or USSD query result, in accordance
					to the value of 'ok'.
	"""
	
	logging.debug("Starting USSD query \"%s\"", query)

	result = send_command(
		ussd_query_cmd(query, use_cleartext),
		'wait_for_cmd_answer',
	)
	
	if result['ok']:
		logging.debug ("USSD query successful, answer received")
		match = re.search(
			r'''(?ix)
				(\d+)           # Response type
				(?:
					,"([^"]+)"  # Response
					(?:
						,(\d+)  # Encoding
					)?          # ... may be missing or ...
				)?              # ... Response *and* Encoding may be missing
			''',
			result['description'])
		if match:
			response_type = match.group(1)
			if response_type != None:
				response_type = int(response_type)
			response = match.group(2)
			encoding = match.group(3)
			if encoding != None:
				encoding = int(encoding)

		if match == None or response_type == None:
			# Didn't the RE match?
			logging.error("Can't parse CUSD message: \"%s\"",
				result['description'])
			return {
				'ok'  : fail,
				'msg' :  "Can't understand modem answer: \"{0}\"".format(
							result['description'])
			}
		elif response_type == 0:
			logging.info ("USSD response type: No further action required (0)")
		elif response_type == 1:
			logging.info ("USSD response type: Further action required (1)")
			sys.stderr.write("USSD session open, to cancel use \"gsm-ussd -c\".\n")
		elif response_type == 2:
			msg = "USSD response type: USSD terminated by network (2)"
			logging.error (msg)
			return { 'ok' : fail, 'msg' : msg }
		elif response_type == 3:
			msg = "USSD response type: Other local client has responded (3)"
			logging.error(msg)
			return { 'ok' : fail, 'msg' : msg }
		elif response_type == 4:
			msg = "USSD response type: Operation not supported (4)"
			logging.error (msg)
			return { 'ok' : fail, 'msg' : msg }
		elif response_type == 5:
			msg = "USSD response type: Network timeout (5)";
			logging.error(msg)
			return { 'ok' : fail, 'msg' : msg }
		else:
			msg = "CUSD message has unknown response type \"%s\"" % \
				response_type
			logging.error (msg);
			return { 'ok' : fail, 'msg' : msg }
		# Only reached if USSD response type is 0 or 1
		return { 'ok' : success, 'msg' : interpret_ussd_data(response, encoding) }
	else:
		logging.error ("USSD query failed, error: %s", result['description'])
		return { 'ok' : fail, 'msg' : result['description'] }

def ussd_query_cmd(ussd_cmd, use_cleartext):
	"""Constructs an AT+CUSD with necessary encoding for a ussd query.
	
	Arguments:
		ussd_cmd 	  - The USSD query to send
		use_cleartext - True if USSD query should not be encoded; False
						if it should be encoded
	Returns:  
		An AT+CUSD command with properly encoded args
	"""
	
	result_code_presentation    = '1'	# Enable result code presentation
	encoding                    = '15'  # No clue what this value means

	if use_cleartext:
		ussd_string = ussd_cmd
	else:
		# Although packSeptets expects byte arrays it accepts 
		# ascii strings, so no need to convert return value
		# of gsm_codec.encode.
		ussd_string = bytes_to_hex(packSeptets(gsm_codec.encode(ussd_cmd)))
	return 'AT+CUSD=%s,"%s",%s' % (result_code_presentation,
		ussd_string, encoding)
		
def interpret_ussd_data(response, encoding):
	"""Decodes USSD response using received encoding.

	Arguments:
		response - The USSD string response
		encoding - The USSD encoding as an integer (dcs)
	
	Returns:  
		String containing the USSD response in clear text
	"""
	
	if encoding == None:
		logging.debug("CUSD message has no encoding, " +
			"interpreting as cleartext")
		return response

	if dcs_is_default_alphabet(encoding):
		logging.debug("Encoding \"%d\" says response is " +
			"in default alphabet", encoding)
		if use_cleartext:
			logging.debug("Modem uses cleartext, interpreting " +
				"message as cleartext")
			return response
		elif encoding == 0:
			return hex_to_string(response)
		elif encoding == 15:
			# gsm_codec.decode expects ascii string.
			return gsm_codec.decode(str(unpackSeptets(hex_to_bytes(response))))
		else:
			logging.debug("CUSD message has unknown encoding \"%s\", " +
				"using 0", encoding)
			return hex_to_string(response)
	elif dcs_is_ucs2(encoding):
		logging.debug("Encoding \"%d\" says response is in UCS2-BE",
			encoding)
		return codecs.decode(hex_to_bytes(response), 'UTF-16BE')
	elif dcs_is_8bit(encoding):
		logging.debug("Encoding \"%d\" says response is in 8bit",
			encoding)
		return hex_to_string(response) # Should this be cleartext?
	else:
		logging.debug("CUSD message has unknown encoding \"%d\", " +
			"using 0", encoding)
		return hex_to_string(response)
			
def dcs_is_default_alphabet(enc):
	"""Determines whether the USSD data coding scheme is the default
	alphabet.

	Arguments:
		enc - the USSD dcs (integer)
	Returns:  
		True   - dcs indicates default alpabet
		False  - dcs does not indicate default alphabet
	"""
	
	if not bit_is_set(6, enc) and not bit_is_set (7, enc):
		return True
		
	if bit_is_set(6, enc) and \
			not bit_is_set(7, enc) and \
			not bit_is_set(2, enc) and \
			not bit_is_set(3, enc):
		return True
		
	return False

def dcs_is_ucs2(enc):
	"""Tests whether USSD dcs is UCS2-BE (i.e. Unicode or UTF16-BE)

	Arguments:     
		enc    - the USSD dcs
	Returns:  
		True   - dcs indicates UCS2-BE
		False  - dcs does not indicate UCS2-BE
	"""
	
	if bit_is_set(6, enc) and \
			not bit_is_set(7, enc) and \
			not bit_is_set(2, enc) and \
			bit_is_set(3, enc):
		return True
		
	return False

def dcs_is_8bit(enc):
	"""Determines whether USSD data coding scheme is 8 bit.
	
	Arguments:
		enc - USSD dcs as integer
		
	Returns:
		bool
	"""
	
	if bit_is_set(6, enc) and \
			not bit_is_set(7, enc) and \
			bit_is_set(2, enc) and \
			not bit_is_set(3, enc):
		return True
		
	return False

def bit_is_set(pos, val):
	"""Gets the bit at a specified position in an integer which is
	treated as an array of bits.
	
	Arguments:     
		pos - index of bit, counting from 0 and from the right (LSB)
		val - integer as bit array from which bit will be fetched

	Returns:
		bit (0 or 1) in val at pos
	"""
	return val & (1 << pos) # or (2 ** pos)
	
def hex_to_bytes(hexstr):
	return binascii.unhexlify(hexstr)
	
def hex_to_string(hexstr):
	return codecs.decode(binascii.unhexlify(hexstr))

def bytes_to_hex(data):
	return binascii.hexlify(data).upper()
	
def string_to_hex(s):
	return binascii.hexlify(codecs.encode(s)).upper()
	
def packSeptets(octets, padBits=0):
	""" Packs the specified octets into septets
	
	Typically the output of encodeGsm7 would be used as input to this function. The resulting
	bytearray contains the original GSM-7 characters packed into septets ready for transmission.
	
	@rtype: bytearray
	"""
	result = bytearray()    
	if type(octets) == str:
		octets = iter(bytearray(octets))
	elif type(octets) == bytearray:
		octets = iter(octets)
	shift = padBits
	if padBits == 0:
		prevSeptet = next(octets)
	else:
		prevSeptet = 0x00
	for octet in octets:
		septet = octet & 0x7f;
		if shift == 7:
			# prevSeptet has already been fully added to result
			shift = 0        
			prevSeptet = septet
			continue            
		b = ((septet << (7 - shift)) & 0xFF) | (prevSeptet >> shift)
		prevSeptet = septet
		shift += 1
		result.append(b)    
	if shift != 7:
		# There is a bit "left over" from prevSeptet
		result.append(prevSeptet >> shift)
	return result

def unpackSeptets(septets, numberOfSeptets=None, prevOctet=None, shift=7):
	""" Unpacks the specified septets into octets 
	
	@param septets: Iterator or iterable containing the septets packed into octets
	@type septets: iter(bytearray), bytearray or str
	@param numberOfSeptets: The amount of septets to unpack (or None for all remaining in "septets")
	@type numberOfSeptets: int or None
	
	@return: The septets unpacked into octets
	@rtype: bytearray
	"""    
	result = bytearray()    
	if type(septets) == str:
		septets = iter(bytearray(septets))
	elif type(septets) == bytearray:
		septets = iter(septets)    
	if numberOfSeptets == None:        
		numberOfSeptets = sys.maxint # Loop until StopIteration
	i = 0
	for octet in septets:
		i += 1
		if shift == 7:
			shift = 1
			if prevOctet != None:                
				result.append(prevOctet >> 1)            
			if i <= numberOfSeptets:
				result.append(octet & 0x7F)
				prevOctet = octet                
			if i == numberOfSeptets:
				break
			else:
				continue
		b = ((octet << shift) & 0x7F) | (prevOctet >> (8 - shift))
		
		prevOctet = octet        
		result.append(b)
		shift += 1
		
		if i == numberOfSeptets:
			break
	if shift == 7:
		b = prevOctet >> (8 - shift)
		if b:
			# The final septet value still needs to be unpacked
			result.append(b)        
	return result
	
def create_cmd_line_parser():
	parser = argparse.ArgumentParser(
		description="""Sends USSD queries from your modem.""")
	parser.add_argument('ussd_queries', metavar='<ussd_cmd>', nargs='*',
		help="""Everything else on the command line is supposed
				to be a USSD query. Default is '*124#'.""")
	parser.add_argument("-m", "--modem", metavar='<modem>', 
		help="""Sets the device file to use to connect to the  
				modem. Default is /dev/ttyUSB1.""")
	parser.add_argument("-t", "--timeout", metavar='<timeout_in_seconds>', 
		help="""The timeout in seconds that the script will wait 
				for an answer after each command sent to the  
				modem. Default is 20 seconds.""", type=int)
	parser.add_argument("-p", "--pin", metavar='<pin>', 
		help="The SIM PIN, if the card is still locked.")
	group = parser.add_mutually_exclusive_group()
	group.add_argument("--cleartext", 
		help="""This option causes gsm-ussd to send USSD queries  
				in cleartext, i.e. without encoding them into a 
				7bit-packed-hex-string.""", action="store_true")
	group.add_argument("--no-cleartext", 
		help="""This is the opposite of the previous option: 
				Use encoding, even if the modem type does not 
				indicate that it is needed.""", action="store_true")
	parser.add_argument("-l", "--logfile", metavar='<logfilename>', 
		help="""Writes the chat between modem and script 
				into the named log file.""")
	parser.add_argument("-d", "--debug", 
		help="""Switches debug mode on. The script will 
				then explain its actions""", action="store_true")
	parser.add_argument("-c", "--cancel", 
		help="""Sends a command to cancel any ongoing 
				USSD session. Cancelling while no session is
				active does no harm.""",
		action="store_true")
	return parser

if __name__ == "__main__":
	main()
