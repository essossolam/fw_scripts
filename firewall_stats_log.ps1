Write-Host "*************************************************************************************"
Write-Host "JORDY AQUITEME - FIREWALL LOG STATS SCRIPT"
Write-Host "FILTERS `nMOST USED SOURCE | MOST USED DEST | MOST USED PORTS | PERCENTAGE OF DROPS AND MATCH"
Write-Host "MATCH WITH PFSENSE AND OPNSENSE LOGS"
Write-Host "************************************************************************************"

class Rule {
    [string] $interface
    [string] $action
    [string] $direction
    [string] $protocol
    [string] $source
    [string] $sPort
    [string] $dest
    [string] $dPort
}

$logFiles = @("filter_fw_admin.log", "filter_fw_prod.log")
$filepath = "your_firewall_dir_relative_path"
$statsFileRelativePath = "your_stats_relative_path"

for ($i = 0; $i -lt $logFiles.Count; $i++) {
    $filename = $logFiles[$i]

    Write-Host "*************[FILE $($filename)]*****************"

    $logFileContent = Get-Content $filepath$filename
    $rules = [System.Collections.ArrayList]::new()

    Write-Host "*************EXTRACT DATA*****************"
    $logFileContent | ForEach-Object {
        $line = $_ -split ','
        if ($line[16] -eq 'tcp' -or $line[16] -eq 'udp') {
            $lineRule = [Rule]::new()
            $lineRule.interface = $line[4]
            $lineRule.action = $line[6]
            $lineRule.direction = $line[7]
            $lineRule.protocol = $line[16]    
            $lineRule.source = $line[18]
            $lineRule.dest = $line[19]
            $lineRule.sPort = $line[20]
            $lineRule.dPort = $line[21]

            [void]$rules.Add($lineRule)
        }
    }
    Write-Host "*************EXTRACT DATA END*****************"
    Write-Host "*************START GENERATING STATS*****************"

    $sourceHashTable = @{}
    $destHashTable = @{}
    $sourcePortHashTable = @{}
    $acceptBlockRuleHashTable = @{}

    foreach ($rule in $rules) {
        ##SOURCES
        if ($sourceHashTable.ContainsKey($rule.source.Trim())) {
            $tmpSCount = $sourceHashTable[$rule.source.Trim()]
            $sourceHashTable[$rule.source.Trim()] = ($tmpSCount + 1)
        }
        else {
            $sourceHashTable.Add($rule.source.Trim(), 1)
        }
        ##DESTINATIONS
        if ($destHashTable.ContainsKey($rule.dest.Trim())) {
            $tmpDCount = $destHashTable[$rule.dest.Trim()]
            $destHashTable[$rule.dest.Trim()] = ($tmpDCount + 1)
        }
        else {
            $destHashTable.Add($rule.dest.Trim(), 1)
        }
        ##SOURCE PORTS 
        if ($sourcePortHashTable.ContainsKey($rule.sPort.Trim())) {
            $tmpSpCount = $sourcePortHashTable[$rule.sPort.Trim()]
            $sourcePortHashTable[$rule.sPort.Trim()] = ($tmpSpCount + 1)
        }
        else {
            $sourcePortHashTable.Add($rule.sPort.Trim(), 1)
        }
        ##ACCEPT BLOCK RULES
        if ($acceptBlockRuleHashTable.ContainsKey($rule.action.Trim())) {
            $tmpAbCount = $acceptBlockRuleHashTable[$rule.action.Trim()]
            $acceptBlockRuleHashTable[$rule.action.Trim()] = ($tmpAbCount + 1)
        }
        else {
            $acceptBlockRuleHashTable.Add($rule.action.Trim(), 1)
        }
    }

    $orderedSourceDictionary = [ordered]@{}
    $orderedDestDictionary = [ordered]@{}
    $orderedSourcePortDictionary = [ordered]@{}

    Write-Host "*************STATS ORDERING START*****************"

    foreach ($item in ($sourceHashTable.GetEnumerator() | Sort-Object -Property Value -Descending)) {
        $orderedSourceDictionary[$item.Key] = $item.Value
    }

    foreach ($item in ($destHashTable.GetEnumerator() | Sort-Object -Property Value -Descending)) {
        $orderedDestDictionary[$item.Key] = $item.Value
    }

    foreach ($item in ($sourcePortHashTable.GetEnumerator() | Sort-Object -Property Value -Descending)) {
        $orderedSourcePortDictionary[$item.Key] = $item.Value
    }

    Write-Host "*************STATS ORDERING END*****************"
    Write-Host "*************WRITE STATS IN FILE START *****************"

    Add-Content -Path $statsFileRelativePath -Value "*********[FILE $($filename)]********** `n"

    Add-Content -Path $statsFileRelativePath -Value  "Source IP `t `t Stat"
    Add-Content -Path $statsFileRelativePath -Value  "----------- `t `t -----------"
    $orderedSourceDictionary.GetEnumerator() | Select-Object -First 10 | 
    ForEach-Object { Add-Content -Path $statsFileRelativePath -Value  "$($_.Name) `t `t $($_.Value)" }
    Add-Content -Path $statsFileRelativePath -Value  "`n "

    Add-Content -Path $statsFileRelativePath -Value  "Dest IP `t `t Stat"
    Add-Content -Path $statsFileRelativePath -Value  "----------- `t `t -----------"
    $orderedDestDictionary.GetEnumerator() | Select-Object -First 15 | 
    ForEach-Object { Add-Content -Path $statsFileRelativePath -Value  "$($_.Name) `t `t $($_.Value)" }
    Add-Content -Path $statsFileRelativePath -Value  "`n"

    Add-Content -Path $statsFileRelativePath -Value  "Port `t `t Stat"
    Add-Content -Path $statsFileRelativePath -Value  "------- `t ------"
    $orderedSourcePortDictionary.GetEnumerator() | Select-Object -First 5 | 
    ForEach-Object { Add-Content -Path $statsFileRelativePath -Value  "$($_.Name) `t `t $($_.Value)" }
    Add-Content -Path $statsFileRelativePath -Value  "`n "

    Add-Content -Path $statsFileRelativePath -Value  "Action `t `t Perc (%)"
    Add-Content -Path $statsFileRelativePath -Value  "------- `t ------"
    $acceptBlockRuleHashTable.GetEnumerator() | 
    ForEach-Object { Add-Content -Path $statsFileRelativePath -Value "$($_.Key) `t `t $([math]::round(($_.Value / $rules.Count) * 100)) %" }
    Add-Content -Path $statsFileRelativePath -Value  "`n "

    Write-Host "*************WRITE STATS IN FILE END *****************"
    Write-Host "*************END GENERATING STATS*****************"
    # Remove-Variable 
}

Write-Host "************************************************************************************"
Write-Host "END OF SCRIPT - GOODBYE"
Write-Host "************************************************************************************"