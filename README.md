# gsm_ussd.py

This is a port of Jochen Gruse's [gsm_ussd](https://github.com/JochenHoch2/gsm-ussd) from Perl to Python 2 in December 2016. It is meant for the same purpose of making USSD requests with GSM modems from the command line.

My motivation for this port was my inability to get the Perl script to work with USSD codes which generate multiline responses, and also my better familiarity with Python than Perl. This was my first attempt at understanding Perl code and thank God I did it successfully.

## Requirements

* Python 2
* **pexpect**, **smspdu**, **serial** pip packages
* \*nix systems (specifically wherever pexpect package is fully supported). I used Ubuntu 14.04.

Tested with the following modems

* MTN E3372
* Vodafone K4201

## Running

In Ghana almost all telecom networks assign \*124# for checking airtime credit balance. So that is the default ussd request made by the gsm_ussd.py script when launched with no arguments.

The acceptable arguments closely match that of the mother Perl [gsm_ussd](https://github.com/JochenHoch2/gsm-ussd) project:

```
usage: gsm_ussd.py [-h] [-m <modem>] [-t <timeout_in_seconds>] [-p <pin>]
                   [--cleartext | --no-cleartext] [-l <logfilename>] [-d] [-c]
                   [<ussd_cmd> [<ussd_cmd> ...]]

Sends USSD queries from your modem.

positional arguments:
  <ussd_cmd>            Everything else on the command line is supposed to be
                        a USSD query. Default is '*124#'.

optional arguments:
  -h, --help            show this help message and exit
  -m <modem>, --modem <modem>
                        Sets the device file to use to connect to the modem.
                        Default is /dev/ttyUSB1.
  -t <timeout_in_seconds>, --timeout <timeout_in_seconds>
                        The timeout in seconds that the script will wait for
                        an answer after each command sent to the modem.
                        Default is 20 seconds.
  -p <pin>, --pin <pin>
                        The SIM PIN, if the card is still locked.
  --cleartext           This option causes gsm-ussd to send USSD queries in
                        cleartext, i.e. without encoding them into a 7bit-
                        packed-hex-string.
  --no-cleartext        This is the opposite of the previous option: Use
                        encoding, even if the modem type does not indicate
                        that it is needed.
  -l <logfilename>, --logfile <logfilename>
                        Writes the chat between modem and script into the
                        named log file.
  -d, --debug           Switches debug mode on. The script will then explain
                        its actions
  -c, --cancel          Sends a command to cancel any ongoing USSD session.
                        Cancelling while no session is active does no harm.
```
