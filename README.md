# vpnazure-go
Privately hosted VPN Azure solution for SoftEther VPN

## Description

  VPN Azure is a VPN relay service provided by SoftEther Corporation for free to users of SoftEther VPN.
  It saves the need for VPN servers to sit on public IP addresses.
  
  This is a open-sourced implementation of the VPN Azure function in Go.
  
  It's NOT an official product by SoftEther Corporation.
  
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
  
    All control and data connections speak standard TLS.
    
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
  
## License

  Released under Apache License 2.0, the same as SoftEther VPN.
