### roce-preflight-checks

### Description
```
A script that assures a networking topology is ready for RoCEv2 testing
```
  
### Prechecks
|Param|Default Value|Description|
|-----|-------------|-----------|
|license_check|True|Checks all licenses for expirations|
|check_connectivity|False|Checks connectivities to chassis, ports and IxNetwork|
|setup_ports|False|Automatically configure the right port mode and speed setting|
|setup_layer1|False|Set up autoneg, rs_fec, link_speed, ieee_defaults|
|check_link_state|False|Verify port link state|
|configure_interfaces|False|Configures IPv4/IPv6 and RoCEv2 protocol stacks|
|arp_gateways|False|Verify ARP response on all hosts L3 gateway|
|ping_mesh|False|Ping from each host to all endpoints|
|apply_rocev2_traffic|False|Validate RoCEv2 configurations|
|pfc_incast|False|Run incast test with DCQCN disabled to assure DUT sends PFC<br>Verify for packet drops<br>Verify the incast receiving port receives all Tx frames|

### Requirements
```
- Linux Server to run the script
- AresOne chassis with IxNetwork Web Edition
- Licenses: Ixos, IxNetwork, AresOne
- Python 3.10
- Python dependencies: pip install -r requirements.txt
- Yaml config files
```

### Sample Yaml Config Files
[configs/preflight_checks_pfc_incast.yml](configs/preflight_checks_pfc_incast.yml)
```
- Performs prechecks
- 3:1 incast with DCQCN disabled to verify DUT sends PFC frames
- Verify no packet drop
- Verify PFC frames on all Tx ports
- Verify incast receiving port for all Tx frames
```

[configs/preflight_checks_noRoCEv2.yml](configs/preflight_checks_noRoCEv2.yml)
```
- Performs prechecks without RoCEv2 configurations
```

[configs/ipv4_allToAll.yml](configs/ipv4_allToAll.yml)
```
- Including prechecks are optional
- Runs full-mesh RoCEv2 on IxNetwork
```
     
### Command
```
python3 rocev2_preflight_checks.py --config configs/preflight_checks_pfc_incast.yml --ixnetwork-host <chassis IP>; 
```

### Optional Command Line Args
```
--ixnetwork-host:          IP address to AresOne chassis where IxNetwork is running
--ixnetwork-uid:           IxNetwork login username
--ixnetwork-pwd:           IxNetwork login password
--ixnetwork-debug:         Flag to enable debug level tracing (default is info)
--ixnetwork-session-name:  Name for the IxNetwork session
--output-dir:              Directory that will hold all result artifacts
--validate:                Flag to only validate the configuration and exit
--ixnetwork-rest-port:     IxNetwork Rest API listening port
--noCloseSession:          Don't close the IxNetwork session for viewing after the test
``` 

### Credits
```
Andy Balogh
Hubert Gee
Russil WVong
Alex Bortok
```


### License: MIT

