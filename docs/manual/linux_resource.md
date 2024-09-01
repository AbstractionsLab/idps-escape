# Monitoring Linux resource usage

Wazuh can be set up to monitor Linux resource usage. This information can be used to complement the SIDS and other metrics, see this [example](./example.md).

This feature can be enabled following this [blog post](https://wazuh.com/blog/monitoring-linux-resource-usage-with-wazuh/), with some adjustments because we use the docker deployment that we list below.

### Agent 
Take the following steps to configure the Wazuh command monitoring module.

1. Edit the Wazuh agent `/var/ossec/etc/ossec.conf` file and add the following command monitoring configuration within the `<ossec_config>` block:

```XML
<!-- CPU, memory, disk metric -->
  <localfile>
     <log_format>full_command</log_format>
     <command>echo $(top -bn1 | grep Cpu | awk '{print $2+$4+$6+$12+$14+$16}' ; free -m | awk 'NR==2{printf "%.2f\t\t\n", $3*100/$2 }' ; df -h | awk '$NF=="/"{print $5}'|sed 's/%//g')</command>
     <alias>general_health_metrics</alias>
     <out_format>$(timestamp) $(hostname) general_health_check: $(log)</out_format>
     <frequency>30</frequency>
  </localfile>

<!-- load average metrics -->
  <localfile>
     <log_format>full_command</log_format>
     <command>uptime | grep load | awk '{print $(NF-2),$(NF-1),$NF}' | sed 's/\,\([0-9]\{1,2\}\)/.\1/g'</command>
     <alias>load_average_metrics</alias>
     <out_format>$(timestamp) $(hostname) load_average_check: $(log)</out_format>
     <frequency>30</frequency>
  </localfile>

<!-- memory metrics -->
  <localfile>
     <log_format>full_command</log_format>
     <command>free --bytes| awk 'NR==2{print $3,$7}'</command>
     <alias>memory_metrics</alias>
     <out_format>$(timestamp) $(hostname) memory_check: $(log)</out_format>
     <frequency>30</frequency>
  </localfile>

<!-- disk metrics -->
  <localfile>
     <log_format>full_command</log_format>
     <command>df -B1 | awk '$NF=="/"{print $3,$4}'</command>
     <alias>disk_metrics</alias>
     <out_format>$(timestamp) $(hostname) disk_check: $(log)</out_format>
     <frequency>30</frequency>
  </localfile>
```

```sh
sudo systemctl restart wazuh-agent
```

### Manager (server)

1. Add the following decoders to decode the logs from the command monitoring module in 

```sh
vi  /var/lib/docker/volumes/single-node_wazuh_etc/_data/decoders/local_decoder.xml
```

```xml
<!-- CPU, memory, disk metric -->
<decoder name="general_health_check">
     <program_name>general_health_check</program_name>
</decoder>

<decoder name="general_health_check1">
  <parent>general_health_check</parent>
  <prematch>ossec: output: 'general_health_metrics':\.</prematch>
  <regex offset="after_prematch">(\S+) (\S+) (\S+)</regex>
  <order>cpu_usage_%, memory_usage_%, disk_usage_%</order>
</decoder>

<!-- load average metric -->
<decoder name="load_average_check">
     <program_name>load_average_check</program_name>
</decoder>

<decoder name="load_average_check1">
  <parent>load_average_check</parent>
  <prematch>ossec: output: 'load_average_metrics':\.</prematch>
  <regex offset="after_prematch">(\S+), (\S+), (\S+)</regex>
  <order>1min_loadAverage, 5mins_loadAverage, 15mins_loadAverage</order>
</decoder>

<!-- Memory metric -->
<decoder name="memory_check">
     <program_name>memory_check</program_name>
</decoder>

<decoder name="memory_check1">
  <parent>memory_check</parent>
  <prematch>ossec: output: 'memory_metrics':\.</prematch>
  <regex offset="after_prematch">(\S+) (\S+)</regex>
  <order>memory_used_bytes, memory_available_bytes</order>
</decoder>

<!-- Disk metric -->
<decoder name="disk_check">
     <program_name>disk_check</program_name>
</decoder>

<decoder name="disk_check1">
  <parent>disk_check</parent>
  <prematch>ossec: output: 'disk_metrics':\.</prematch>
  <regex offset="after_prematch">(\S+) (\S+)</regex>
  <order>disk_used_bytes, disk_free_bytes</order>
</decoder>
```

2. Create rules to detect metrics in the logs from the command monitoring module. Add the rules to the custom rules file  on the Wazuh server:

```sh
nano /var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml
```

```xml
<group name="performance_metric,">

<!-- CPU, Memory and Disk usage -->
<rule id="100054" level="3">
  <decoded_as>general_health_check</decoded_as>
  <description>CPU | MEMORY | DISK usage metrics</description>
</rule>

<!-- High memory usage -->
<rule id="100055" level="12">
  <if_sid>100054</if_sid>
  <field name="memory_usage_%">^[8-9]\d|100</field>
  <description>Memory usage is high: $(memory_usage_%)%</description>
  <options>no_full_log</options>
</rule>

<!-- High CPU usage -->
<rule id="100056" level="12">
  <if_sid>100054</if_sid>
  <field name="cpu_usage_%">^[8-9]\d|100</field>
  <description>CPU usage is high: $(cpu_usage_%)%</description>
  <options>no_full_log</options>
</rule>

<!-- High disk usage -->
<rule id="100057" level="12">
  <if_sid>100054</if_sid>
  <field name="disk_usage_%">^[7-9]\d|100</field>
  <description>Disk space is running low: $(disk_usage_%)%</description>
  <options>no_full_log</options>
</rule>

<!-- Load average check -->
<rule id="100058" level="3">
  <decoded_as>load_average_check</decoded_as>
  <description>load average metrics</description>
</rule>

<!-- memory check -->
<rule id="100059" level="3">
  <decoded_as>memory_check</decoded_as>
  <description>Memory metrics</description>
</rule>

<!-- Disk check -->
<rule id="100060" level="3">
  <decoded_as>disk_check</decoded_as>
  <description>Disk metrics</description>
</rule>

</group>
```

```sh
docker restart single-node-wazuh.manager-1
```

### Template modification

1. Add the custom fields in the Wazuh template. Find the data section in 

```sh
nano /var/lib/docker/volumes/single-node_filebeat_etc/_data/wazuh-template.json  
```


```json
 {

"order": 0,

"index_patterns": [

"wazuh-alerts-4.x-*",

"wazuh-archives-4.x-*"

],

"settings": {

...

},

"mappings": {

"dynamic_templates": [

{

...

"data": {

"properties": {

"1min_loadAverage": {

"type": "double"

},

"5mins_loadAverage": {

"type": "double"

},

"15mins_loadAverage": {

"type": "double"

},

"cpu_usage_%": {

"type": "double"

},

"memory_usage_%": {

"type": "double"

},

"memory_available_bytes": {

"type": "double"

},

"memory_used_bytes": {

"type": "double"

},

"disk_used_bytes": {

"type": "double"

},

"disk_free_bytes": {

"type": "double"

},

"disk_usage_%": {

"type": "double"

},

"audit": {

"properties": {

"acct": {

"type": "keyword"
```

To apply the changes to the Wazuh template, run the command below:

```sh
docker exec -it single-node-wazuh.manager-1 bash
```

```sh
filebeat setup -index-management
```

An expected output is shown below:

```sh
ILM policy and write alias loading not enabled.

Index setup finished.
```