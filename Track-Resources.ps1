"$(Get-Counter '\LogicalDisk(_Total)\% Free Space' | foreach {$_.Timestamp})/HDD: $(Get-Counter '\LogicalDisk(_Total)\% Free Space' | foreach {$_.CounterSamples.CookedValue[0]})" >> 'C:\Temp\Resources.log'
"$(Get-Counter '\Memory\Available MBytes' | foreach {$_.Timestamp})/RAM: $(Get-Counter '\Memory\Available MBytes' | foreach {$_.CounterSamples.CookedValue[0]})" >> 'C:\Temp\Resources.log'
