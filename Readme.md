# EAP-TLS Debugging

This tool is designed to capture and observe EAP-TLS logins, especially in the eduroam environment.

It was developed by Jan-Frederik Rieckers as part of a bachelor thesis at the University of Bremen in cooperation with the German Research Network (DFN-Verein).
This bachelor thesis is [publicly available][ba-thesis].

## Features

This tool analyses the EAP-TLS handshakes and saves the parsed information into elasticsearch.
For details please read section 3 of the [Bachelor Thesis][ba-thesis].

Additionally, the tool outputs all observed certificates to the file system for later analysis.

In case of errors the communication is saved into the directory `debugcapture`

Additionally, the tool offers a possibility to observe the functionality via munin scripts, see the `tools/` directory.

THIS TOOL IS NOT YET FULLY PRODUCTION READY for the following reasons:
* The logging contains too much information from both quantity and privacy viewpoints
  * The policy error logging includes the actual MAC addresses and usernames of the errored packages
  * The debugcapture outputs also include the raw packets, which contain private data of the authenticating users
* The debugcapture outputs too many communications, thus possibly using up all available storage
* In case of an elasticsearch failure, the data is stored on hard drive, which also could eat up all available storage
* A number of special cases may cause the whole tool or some parts to crash
* If used with MRI ruby (see next section) due to the single CPU core used, queues may build up, eating up all available memory.
* The code still contains a lot of legacy code which was replaced by new code segments, but the old segments remained.

Any help in fixing these errors or notice about new observed errors is highly appreciated.
See https://github.com/Janfred/radius_cap/issues

## Install
The install instructions are based on a Debian 11.

For this tutorial it is assumed that the elasticsearch and kibana are also installed on the same machine.

```
# Install needed packets
$> apt-get install build-essential ruby ruby-dev gnupg curl git

# Fetch elastic gpg key, add list, install elasticsearch and kibana
# You can leave this out, if you have elasticsearch running on a different server.
$> curl https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmour > /usr/share/keyrings/elasticsearch.gpg
$> echo "deb [signed-by=/usr/share/keyrings/elasticsearch.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elasticsearch.list
$> apt-get update && apt-get install elasticsearch kibana

```

Depending on the capturing scenario, different steps have to be performed:

### Capturing raw RADIUS packets

CAUTION: This uses MRI Ruby, which does not support using multiple CPU cores.
If more packets are captured than the script can process, the queues will build up, resulting in massive memory usage and the script failure.

To be able to open a raw socket, which is used to capture the RADIUS packets, the script has to run under the root users.

```
# Install last needed packets
$> apt-get install libcap-dev

# Install bundler
$> gem install bundler

# Clone repository and install gems
$> git clone https://github.com/Janfred/radius_cap.git /srv/radius_cap
$> cd /srv/radius_cap
$> bundle config set deployment 'true'
$> bundle install

# To check the correct functionality run
$> ruby radius_cap.rb
# You can abort with Ctrl+C
```


### Capturing via Radsecproxy

This capturing process makes use of a modified radsecproxy version.
The modifications have not yet been merged to the upstream repository but can be found [here][radsec].

This version uses jruby, which supports multithreading.
Since this script does not need root privileges to open a raw socket, it should run under reduced privileges.

```
$> apt-get install openjdk-11-jre-headless

# Create user and clone the repository
$> adduser --home /srv/radius_cap --disabled-password --gecos "" radius_cap
$> su - radius_cap
#> git clone https://github.com/Janfred/radius_cap.git

# Install and configure rbenv
#> curl -fsSL https://github.com/rbenv/rbenv-installer/raw/HEAD/bin/rbenv-installer | bash
#> echo 'PATH="$HOME/.rbenv/bin:$PATH"' >> .bashrc
#> echo 'eval "$(rbenv init - bash)"' >> .bashrc
#> exec bash
#> rbenv install jruby-9.2.19.0
#> cd radius_cap
#> rbenv local jruby-9.2.19.0

# Install and configure Bundler and install gems
#> gem install bundler
#> bundle config set deployment 'true'
#> bundle config set gemfile Gemfile.radsec
#> bundle install

# You can check the correct functionality with
#> BUNDLE_GEMFILE=Gemfile.radsec ruby radsecproxy_cap.rb
```


### Systemd Units

To run the capturing as systemd units, systemd files can be found in the `systemd/` directory.
Copy the according file (`radius_cap.service` or `radsecproxy_cap.service`) to the directory `/etc/systemd/system` and execute `systemctl daemon-reload`.

After that you can start the capturing tool with `systemctl start radius_cap` or `systemctl start radsecproxy_cap`

To start the tool on startup run `systemctl enable radius_cap` or `systemctl enable radsecproxy_cap`

In order to ensure data protection, the data older than 3 months can be archived.
This archiving process will use a randomly generated identifier, thus ensuring that the data is completely anonymized.

To enable this process, copy the files `radiuscap_archive.service` and `radiuscap_archive.timer` to the directory `/etc/systemd/system`.
Depending on your environment you may have to modify the content of `radiuscap_archive.service`.
To enable the archive process, run `systemctl enable radiuscap_archive.timer` to enable the timer for the next boot and `systemctl start radiuscap_archive.timer` to activate the timer.

If you want to run the archive process manually, you can run `systemctl start radiuscap_archive.service`.

## Configuration

The configuration is done via the file `localconfig.rb`

It has the following configuration options:
* `ipaddrs` -> Array, IP addresses of the RADIUS Servers. Only packets from and to these IP addresses will be analysed
* `ignoreips` -> Array, Traffic from and to these IP addresses will be ignored. Useful for ignoring requests from testing infrastructure.
* `debug` -> Boolean, output the logs to `stdout` in addition to `development.log` and adds more debugging output. Useful to trace errors. DO NOT USE IN PRODUCTION!
* `noelastic` -> Boolean, Omit the elastic write actions. Useful for debugging if elasticsearch is not available and combined with `filewrite`. Defaults to `false`
* `filewrite` -> Boolean, Write the JSON output for the elasticsearch into files. Defaults to `false`
* `debug_level` -> Boolean, Standard debug level for logging. Can be (ordered from most verbose to most silent): `:trace`, `:debug`, `:info`, `:warn`, `:error`, `:fatal` . Defaults to `:warn`, can be set to `:info` in Production to observe the functionality. Do not set to `:debug` or `:trace` in production.
* `elastic_filter` -> Array of Hashes, List of communications that should not be saved. Can be used to ignore testing accounts. Both attributes have to match
  * `username` -> String, Outer Username to ignore. `nil` for wildcard
  * `mac` -> String, MAC address to ignore. `nil` for wildcard
* `socket_files` -> Array of Hashes, List of all sockets the script should listen to.
  * `path` -> String, Path to the Unix socket for the radsecproxy connection
  * `label` -> String, Label to be used in debug-messages and the munin statistics
* `bulk_insert` -> Integer, Number of inserts to perform simultaneously. Set to 1,000 for big deployments. If omitted, each insert is made individually
* `elastic_username` -> String, Username for elasticsearch inserts. Omit if elasticsearch security is not enabled.
* `elastic_password` -> String, Password for elasticsearch inserts. Omit if elasticsearch security is not enabled.
* `profiler` -> Boolean, used for debugging to profile memory usage. Set to true to output memory profiler details. DO NOT USE IN PRODUCTION!
* `certificate_dontsave` -> Boolean, do not save certificates to the file system

A sample can be found in `localconfig.rb.templates`

## Log files

The tool outputs the following log files:

* `development.log`
  * This is the central log file for all log messages. Depending on the `debug_level` in the configuration, 
* `policy_violation.log`
  * This log contains all policy/protocol violations observed with source and destination
* `policy_violation_detail.log`
  * This log contains more detailed information about the policy violations. Useful for debugging policy violations.
* `statistics.log`
  * Outputs Statistics about captured, parsed and saved packets and streams every minute

And the following directories are used:
* `data`
  * Output-Directory for filewrite option
* `debugcapture`
  * Output-Directory for debugcapture and failed elasticsearch inserts
* `known_certs`
  * Legacy-Directory for saving certificates
* `seen_certs`
  * Legacy-Directory for saving certificates
* `seen_certs_raw`
  * Output-Directory for observed certificates. Filename is `<sha256sum of PEM encoding>.pem`
* `statistics`
  * Output-Directory for `profiler` files, subdirectories for each profiler call with the timestamp

## Capturing sources configuration

I order to not disrupt the production environment, it is highly recommended to run this analysis tool on a different server.
To still be able to capture the RADIUS packets, a copy of all RADIUS packets has to be forwarded to the analysis server.

### Capturing raw RADIUS packets

For the raw RADIUS packets, this can be achieved by using the `iptables -j TEE` option.
In order for this to function, the analysis server has to be in the same layer 2 domain as the RADIUS server.
On the RADIUS server you can add the following rules to iptables (either directly or through netfilter-persistent or similar tools)

```
# IP-Addr of RADIUS server: 192.0.2.1
# IP-Addr of the analysis server: 192.0.2.10

# To forward all incoming RADIUS packets
iptables -t mangle -A PREROUTING -d 192.0.2.1 -p udp -m udp --dport 1812 -j TEE --gateway 192.0.2.10
# To forward all outgoing RADIUS packets
iptables -t mangle -A POSTROUTING -s 192.0.2.1 -p udp -m udp --dport 1812 -j TEE --gateway 192.0.2.10
```

If you have multiple RADIUS servers, you have to do this on all of them to capture all packets.

### Capturing via radsecproxy socket

For the radsecproxy capture, the output socket of the Radsecproxy has to be forwarded to the analysis machine.
For this purposes the `systemd/` directory contains the `radsec_ssh_tunnel@.service` unit.

For this to work, on the destination server there must exist a user `radius_cap` with the privileges to open the UNIX socket.
It is assumed that the socket is located under `/tmp/radsecproxy.sock`.
The local socket is then put under `/tmp/radsecproxy.<servername>.sock`.

To start the SSH tunnel run `systemctl start radsec_ssh_tunnel@<servername>`.
To start the tunnel on startup, run `systemctl enable radsec_ssh_tunnel@<servername>`.


## License and contact to maintainers

This tool is released under GNU GPLv3. See [License][LICENSE.txt]

The tool was written by Jan-Frederik Rieckers. You can contact the author under `rieckers@uni-bremen.de`

If in doubt of license restrictions or you would like to use the tool under a different license, contact the author.

---
[ba-thesis]: https://user.informatik.uni-bremen.de/rieckers/Bachelor_EAP-TLS.pdf
[radsec]: https://github.com/Janfred/radsecproxy/tree/DFN/outputsocket