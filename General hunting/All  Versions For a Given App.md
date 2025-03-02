# All Versions of a Given App
## CrowdStrike Logscale Query
<blockquote>

</blockquote>

```Logscale
// Filter for ProcessRollup2 or ImageHash events where the FileName matches the targeted executable
(#event_simpleName=/ProcessRollup2/iF OR #event_simpleName=/ImageHash/iF) FileName=/<target_executable_name>/iF
// Enrich data with IntegrityLevel information
| $falcon/helper:enrich(field=IntegrityLevel)
// Group results by ImageFileName and ComputerName, counting unique aid values and collecting IntegrityLevel and CommandLine
| groupBy([ImageFileName, ComputerName], function=[count(aid, distinct=true, as=aidCount), collect([IntegrityLevel, CommandLine])], limit=20000)
// Sort results by aidCount in descending order
| sort(aidCount, order=desc

```