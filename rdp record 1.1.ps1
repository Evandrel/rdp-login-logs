#admin previllage check
if (-not ([security.principal.windowsprincipal][security.principal.windowsidentity]::getcurrent()).isinrole([security.principal.windowsbuiltinrole]::administrator)) {
    write-warning "please run powershell as administrator."
    exit
}
write-host "fetching rdp activities..." -foregroundcolor cyan
#4624 logins
$seclogin = get-winevent -filterhashtable @{logname='Security'; id=4624} -erroraction silentlycontinue | 
    where-object { $_.properties[8].value -eq 10 } | 
    select-object @{n='time'; e={$_.timecreated.tostring("yyyy-MM-dd HH:mm:ss")}},
                  @{n='event'; e={'new rdp login (4624)'}},
                  @{n='user'; e={$_.properties[5].value}},
                  @{n='source ip'; e={$_.properties[18].value}}
#reconnect 4778
$secreconnect = get-winevent -filterhashtable @{logname='Security'; id=4778} -erroraction silentlycontinue | 
    select-object @{n='time'; e={$_.timecreated.tostring("yyyy-MM-dd HH:mm:ss")}},
                  @{n='event'; e={'session reconnected (4778)'}},
                  @{n='user'; e={$_.properties[1].value}},
                  @{n='source ip'; e={$_.properties[4].value}}
#fails 4625
$secfails=get-winevent -filterhashtable @{logname='Security'; id=4625} -erroraction silentlycontinue | 
    select-object @{n='time'; e={$_.timecreated.tostring("yyyy-MM-dd HH:mm:ss")}},
                  @{n='event'; e={'connection failed (4625)'}},
                  @{n='user'; e={$_.properties[5].value}},
                  @{n='source ip'; e={$_.properties[19].value}}
#21 24 25
$tslocal = get-winevent -logname "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -erroraction silentlycontinue | 
    where-object { $_.id -in 21, 24, 25 } | 
    select-object @{n='time'; e={$_.timecreated.tostring("yyyy-MM-dd HH:mm:ss")}},
                  @{n='event'; e={
                      switch($_.id) {
                          21 { 'session logon (21)' }
                          24 { 'session disconnected (24)' }
                          25 { 'session reconnected (25)' }
                      }
                  }},
                  @{n='user'; e={$_.properties[0].value}},
                  @{n='source ip'; e={$_.properties[2].value}}
#1149
$tsremote = get-winevent -logname "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -erroraction silentlycontinue | 
    where-object { $_.id -eq 1149 } | 
    select-object @{n='time'; e={$_.timecreated.tostring("yyyy-MM-dd HH:mm:ss")}},
                  @{n='event'; e={'rdp authentication (1149)'}},
                  @{n='user'; e={$_.properties[0].value}},
                  @{n='source ip'; e={$_.properties[2].value}}
# combine n sort
$allreport = ($seclogin + $secreconnect + $secfails + $tslocal + $tsremote) | sort-object time -descending
if ($allreport) {
    $reportpath = "$env:TEMP\rdp connections.html"
    $allreport | convertto-html -title "rdp connections" | out-file $reportpath -encoding utf8
    invoke-item $reportpath
    write-host "success." -foregroundcolor green
} else {
    write-host "no additional rdp logs found on this system" -foregroundcolor red
}