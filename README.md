### roce-preflight-checks

### Terminology
  &emsp;&emsp;KCCB = Keysight Collective Communication Benchmarks

### Description
  &emsp;&emsp;A script that assures a networking topology is ready for RoCEv2/KCCB testing
  
### Prechecks
   - license_check: true|false (Defaults to True)
       - Checks all licenses for expirations
         
   - check_connectivity: true|false
       - Checks connectivities to chassis, ports and IxNetwork
         
   - setup_ports: true|false
       - Automatically configure the right port mode and speed setting
         
   - setup_layer1: true|false
       - Set up autoneg, rs_fec, link_speed, ieee_defaults
         
   - check_link_state: true|false
       - Verify port link state
         
   - configure_interfaces: true|false
       - Configures IPv4/IPv6 and RoCEv2
         
   - arp_gateways: true|false
       - Verify ARP response on all hosts L3 gateway
         
   - ping_mesh: true|false
       - Ping from each host to all endpoints
         
   - apply_rocev2_traffic: true|false
       - Validate RoCEv2 configurations
         
   - pfc_incast: true|false
       - Run incast test with DCQCN disabled to assure DUT sends PFC
       - Verify for packet drops
       - Verify the incast receiving port receives all Tx frames

### Requirements
   - Linux Server to run the script
   - AresOne chassis with IxNetwork and AresOne licenses
   - Python 3.7+
   - Python dependencies: pip install requirements.txt
   - Yaml config files

### Sample Yaml Config Files
   - configs/preflight_checks_pfc_incast.yml
       - Performs prechecks
       - 3:1 incast with DCQCN disabled to verify DUT sends PFC frames
       - Verify no packet drop
       - Verify PFC frames on all Tx ports
       - Verify incast receiving port for all Tx frames

   - configs/preflight_checks_noRoCEv2.yml
       - Just perform prechecks without RoCEv2 configurations

   - configs/ipv4_allToAll.yml
       - Optional to perform prechecks
       - Run full-mesh RoCEv2 on IxNetwork
          
### Command
   &emsp;&emsp;python3.10 rocev2_preflight_checks.py   --config   configs/preflight_checks_pfc_incast.yml  --ixnetwork-host &lt;ip&gt; 

### Optional Command Line Args
    --ixnetwork-host: IP address to AresOne chassis where IxNetwork is running<br>&emsp;&emsp;
    --ixnetwork-uid:  IxNetwork login username<br>&emsp;&emsp;
    --ixnetwork-pwd:  IxNetwork login password<br>&emsp;&emsp;
    --ixnetwork-debug: Flag to enable debug level tracing (default is info)<br>&emsp;&emsp;
    --ixnetwork-session-name: Name for the IxNetwork session<br>&emsp;&emsp;
    --output-dir: Directory that will hold all result artifacts<br>&emsp;&emsp;
    --validate: Flag to only validate the configuration and exit<br>&emsp;&emsp;
    --ixnetwork-rest-port: IxNetwork Rest API listening port<br>&emsp;&emsp;
    --noCloseSession: Don't close the IxNetwork session for viewing after the test<br>
    
