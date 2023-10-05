# vpnazure-go
Privately hosted VPN Azure solution for SoftEther VPN

## Description

  VPN Azure is a VPN relay service provided by SoftEther Corporation for free to users of SoftEther VPN.
  It saves the need for VPN servers to sit on public IP addresses.
  
  This is an open-sourced implementation of the VPN Azure function in Go that works with custom domain names.
  
  It's NOT an official product of SoftEther Corporation.

  The support for custom VPN Azure service has not been incorporated to SoftEther VPN.
  See https://github.com/SoftEtherVPN/SoftEtherVPN/pull/1739.
  You can try the feature with our fork at https://github.com/domosekai/SoftEtherVPN.
  
## Feature

  - Custom DNS suffix
  
    You can use any domain that you have control, such as `myazure.net`.
    
    Multiple suffixes are also supported.
  
  - No need for DDNS
  
    Handle DNS records on your own. Usually a wildcard record like `*.myazure.net` works best.
    
    The real destinations are sniffed from TLS Server Name Indication (SNI).
  
  - Authentication
  
    The original VPN Azure does not require authentication to connect.
    
    As a privately hosted solution, both password and certificate-based authentication is supported.
    
  - Security
  
    All control and data sessions speak standard TLS.
    
  - Flexibility
  
    Handle configuration changes on the fly. Send program a SIGHUP signal to reload all config files.
    
    Perfect for altering authentication info or updating server certificates, without interrupting VPN sessions.
    
    Not available on Windows.
    
## Usage

  ```
  vpnazure-go version unknown (build unknown) usage:
  -auth string
        File that contains server credentials
  -b string
        Listening address and port
  -log string
        Path to the log file
  -suffix string
        File that contains DNS suffixes of the service
  ```
  
## Sample Setup

  ```
                Connect to vpn123.myazure.net                Connect to cloud.myazure.net
    VPN Client ------------------------------> vpnazure-go <---------------------------- VPN Server
                                                             Azure hostname: vpn123.myazure.net
                                                             Password:  somepassword
  ```
  Let's suppose you own `.myazure.net` and have decided to host VPN Azure service on it.
  Azure clients (i.e. VPN servers) will use hostnames in the form `vpn*.myazure.net`.
  The control server will be `cloud.myazure.net`.
  
  First, setup wildcard DNS record to resolve `*.myazure.net` to the actual server address.
  
  Compile `vpnazure-go` on the server and create the following configuration files.
  Let's say `fullchain.pem` and `privkey.pem` contain the server certificate and its key.
  
  *suffix.txt*
  ```
  // Format: DNS suffix | server address | certificate chain file | private key file
  // Fields must be separated by a single TAB.
  .myazure.net	cloud.myazure.net	fullchain.pem	privkey.pem
  ```
  
  *auth.txt*
  ```
  // Format: hostname | suffix | method | secret
  // Fields must be separated by a single TAB.
  vpn*	.myazure.net	password	somepassword
  ```
  
  Start the Azure server:
  ```
  ./vpnazure-go -b 0.0.0.0:443 -auth auth.txt -suffix suffix.txt
  ```
  
  Setup the custom Azure service on a SoftEther VPN server with these information:
  
  - Server address: `cloud.myazure.net:443`
  - Hostname: `vpn123.myazure.net`
  - Password: `somepassword`
  
  Clients can connect to the server by using `vpn123.myazure.net`.
    
## License

  Released under Apache License 2.0, the same as SoftEther VPN.
