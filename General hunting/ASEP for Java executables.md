# ASEP for Java Executable
## CrowdStrike Logscale Query
<blockquote>

Detecting Java-based persistence mechanisms in the Windows Registry Run keys) (MITRE ATTACK ID: T1547.001).

</blockquote>

```Logscale
// Filter for AsepValueUpdate events in Run registry keys
#event_simpleName=AsepValueUpdate RegObjectName=/\\Run$/iF 
// Match entries referencing .jar files in registry values, file names, or command lines
| (RegValueName=/\.jar/iF OR TargetFileName=/\.jar/iF OR TargetCommandLineParameters=/\.jar/iF)
// Display relevant fields in a table  
| table([@timestamp, #event_simpleName, ContextImageFileName, RegPostObjectName, RegObjectName, RegStringValue, RegValueName, CommandLineParameters, ImageFileName]) 
// Sort by timestamp (descending), limit results to 5000 
| sort(@timestamp, order=desc, limit=5000)
```
