# High performance STUN server

## Introduction

- High-performance Shared-nothing Design - [SeaStar](http://seastar.io/): sharded, cooperative, non-blocking, micro-task scheduled design.
- Networking - [Intel DPDK](https://www.dpdk.org/): user-space TCP/IP stack, provide low-latency, high-throughput. Enjoy zero-copy, zero-lock, and zero-context-switch performance.
- STUN server: implement [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489), Prometheus metric reporting, long-term and short-term credential mechanisms, fingerprint mechanism, DNS discovery, IP rate limiting.
- STUN client.
- Tests: implement test vectors from [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769), [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489#appendix-B) and [RFC Errata 8489](https://www.rfc-editor.org/errata/rfc8489).

TODO: write stuff here

## License

MIT License.

## Building STUN server

- (Optional) Install [DPDK](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html).
- Install [SeaStar](https://github.com/scylladb/seastar#building-seastar) (set `Seastar_DPDK` flag to enable DPDK support).
- Install OpenSSL package (libssl-dev on Ubuntu-based distros).
- Install [uriparser](https://uriparser.github.io/).
- Configure [HugePages](http://doc.dpdk.org/spp/setup/getting_started.html).
- Tune [aio-max-nr](https://www.kernel.org/doc/Documentation/sysctl/fs.txt) if using linux-aio reactor backend.
- Build ministun project with CMake.

## Getting Started

- Run STUN server

```
./stunserver --log-level <level> --config <path-to-config-file>
```

Log levels: "trace", "debug", "info", "warn" or "error".

To enable userspace network stack, add `--network-stack native --dpdk-pmd --dhcp true`.

- Run STUN client

```
./stunclient --local-ip <local-ip> --server <server-uri>
```

server URI can be

    stun://<server-domain-name>:<server-port>
    stun://<server-ip>:<server-port>

`stuns` scheme is not supported.

Other options:

```
stunclient options:
  -h [ --help ]           show help message
  --help-seastar          show help message about seastar options
  --help-loggers          print a list of logger names and exit
  --log-level arg (=info) either "trace", "debug", "info", "warn" or "error"
  --family arg (=4)       either "4" or "6" to specify the usage of INET or 
                          INET6
  --protocol arg (=udp)   either "udp" or "tcp"
  --mechanism arg         either "ShortTerm" or "LongTerm"
  --username arg          username
  --username arg          password
  --local-ip arg          local IP
  --local-port arg        local port
  --server arg            server URI
```

- Run tests: support CTest

## Sample config file

```xml
<?xml version="1.0" encoding="utf-8" ?>
<Config>
    <!-- either "trace", "debug", "info", "warn" or "error", default: info -->
    <LogLevel>info</LogLevel>
    <MetricReporter>
        <!-- default: false -->
        <Enabled>false</Enabled>
        <!-- default: empty (bind to all addresses on the local machine) -->
        <Ip></Ip>
        <!-- default: 9180 -->
        <Port>9180</Port>
    </MetricReporter>
    <RateLimiter>
        <!-- default: ModuloRateLimiter (use division hashing) -->
        <Type>ModuloRateLimiter</Type>
        <!-- default: false -->
        <Enabled>false</Enabled>
        <!-- if Type is "ModuloRateLimiter", this node will be checked -->
        <ModuloRateLimiter>
            <!-- permits per minute, default: 30 -->
            <Rate>30</Rate>
            <!-- default: 15 minutes -->
            <BlockTimeout>15</BlockTimeout>
            <!-- default: 20000 -->
            <MaxTrackedAddresses>15</MaxTrackedAddresses>
        </ModuloRateLimiter>
    </RateLimiter>
    <Authenticator>
        <!-- either "StaticShortTermAuthenticator" or "StaticLongTermAuthenticator", default: StaticShortTermAuthenticator -->
        <Type>StaticLongTermAuthenticator</Type>
        <!-- default: false -->
        <Enabled>false</Enabled>
        <!-- if Type is "StaticLongTermAuthenticator", this node will be checked -->
        <StaticLongTermAuthenticator>
            <!-- used to validate nonce -->
            <Key>P@ssword!</Key>
            <!-- It is recommended that the Realm value be the domain name of the provider of the STUN server -->
            <Realm>example.com</Realm>
            <SecurityFeatures>
                <!-- supported algorithm in preferential order: SHA256 -> MD5, default: true -->
                <PasswordAlgorithms>true</PasswordAlgorithms>
                <!-- default: true -->
                <UsernameAnonymity>true</UsernameAnonymity>
            </SecurityFeatures>
            <!-- default: 3 minutes -->
            <NonceTimeout>3</NonceTimeout>
        </StaticLongTermAuthenticator>
        <Users>
            <User>
                <Username>user1</Username>
                <Password>123456789</Password>
            </User>
        </Users>
    </Authenticator>
    <Servers>
        <Server>
            <!-- either "4" or "6" to specify the usage of INET or INET6, default: 4 -->
            <Family>4</Family>
            <!-- either "udp" or "tcp", default: udp -->
            <Protocol>udp</Protocol>
            <!-- default: empty (bind to all INET/INET6 addresses on the local machine) -->
            <Ip></Ip>
            <!-- specify UDP/TCP port for STUN server to start on, default: 3478 -->
            <Port>3478</Port>
        </Server>
    </Servers>
</Config>
```
