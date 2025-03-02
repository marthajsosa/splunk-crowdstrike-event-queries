# BITS Transfers
## CrowdStrike Logscale Query
<blockquote>
Detect adversaries using BITSAdmin for data exfiltration.
</blockquote>

### Method 1: Command History

```Logscale
// Filters for command history executed from bitsadmin.exe with 'transfer' or 'addfile' in the command
#event_simpleName=CommandHistory CommandHistory=/transfer|addfile/iF FileName=/bitsadmin\.exe/iF
// Aggregate results
| groupBy([CommandHistory, ComputerName, timestamp], function=([
    collect([aid, aip, LocalAddressIP4, UserName]),  
    count(aid, distinct=true, as=EndpointCount), 
    count(aid, as=ExecutionCount)
    ]), limit=20000)
// Rename fields for clarity
| rename([[aid,HostSensorID],[aip,RemoteAddressIP4]])
// Converts timestamp to human-readable date and time 
| timestamp := formatTime("%m/%d/%Y %H:%M:%S %a", field=timestamp, timezone=Z)
// Creates a table for easy readability
| table([timestamp, HostSensorID, ComputerName, RemoteAddressIP4, LocalAddressIP4, UserName, CommandHistory, EndpointCount, ExecutionCount])
// Sorts results starting with most recent events
| sort(timestamp, order=desc)
```

### Method 2: Processes

```Logscale
// Filters for processes executed from bitsadmin.exe with 'transfer' or 'addfile' in the command
#event_simpleName=/ProcessRollup2/F CommandLine=/transfer|addfile/iF FileName=/bitsadmin\.exe/iF
// Aggregate results
| groupBy([CommandLine, ComputerName, timestamp], function=([
    collect([aid, aip, LocalAddressIP4, UserName]),  
    count(aid, distinct=true, as=EndpointCount), 
    count(aid, as=ExecutionCount)
    ]), limit=20000)
// Rename fields for clarity
| rename([[aid,HostSensorID],[aip,RemoteAddressIP4]])
// Converts timestamp to human-readable date and time 
| timestamp := formatTime("%m/%d/%Y %H:%M:%S %a", field=timestamp, timezone=Z)
// Creates a table for easy readability
| table([timestamp, HostSensorID, ComputerName, RemoteAddressIP4, LocalAddressIP4, UserName, CommandLine, EndpointCount, ExecutionCount])
// Sorts results starting with most recent events
| sort(timestamp, order=desc)
```
