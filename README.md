*** note ***

Current PoC requires an OffPAD, and a rooted Android phone (sources not availables).

PoC are currently being rewritten and refactored for PCs. TLS Switching demo and documentations will be available soon.

***********

# OTDP and TLS Switching PoC

Contact : denis@migdal.ovh.


## TLS Switching

### Installation

An configured VirtualBox virtual machine can be downloaded at : .
 

### Usage

tlsswitch.jar help
tlsswitch help|proxy|trusted|server|init [options...]
	tlsswitch server [--server-port port]
	tlsswitch proxy [--proxy-port port] [--initial-state StateT]
	tlsswitch trusted [--proxy-ip ip] [--proxy-port port] [--server-ip ip] [--server-port port] [--switch-mode naive]
	java -javaagent:/poc/bin/agent.jar -jar /poc/bin/tlsswitch.jar trusted [--proxy-ip ip] [--proxy-port port] [--server-ip ip] [--server-port port] [--switch-mode choose|normal]

For more details, see documentation at https://github.com/denis-migdal/OTDP-and-TLS-Switching-PoC

openssl s_server -accept 8001 -key ~/.tlsswitch/key.pem -cert ~/.tlsswitch/cert.pem -pass pass:123456
tlsswitch.jar proxy
java -javaagent:/poc/bin/agent.jar -jar /poc/bin/tlsswitch.jar trusted --switch-mode normal



## OTDP

Coming very soon.
