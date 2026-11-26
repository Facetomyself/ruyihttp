# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
param([string]$Python, [string]$Release, [string]$Work, [string]$Evidence, [int]$Samples = 2)
$ErrorActionPreference = 'Stop'
$setting = Get-NetFirewallProfile
if ($setting | Where-Object { -not $_.Enabled }) { throw 'Windows Firewall must be enabled' }
$browser = (Resolve-Path (Join-Path $Work 'core/firefox.exe')).Path
$deny = @('0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255', '::/128', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
$rules = @()
try {
    foreach ($program in @($browser) + @(Get-ChildItem (Split-Path $browser) -File -Filter '*.exe' | Where-Object FullName -ne $browser | Select-Object -ExpandProperty FullName)) {
        $name = 'RuyiHttpFirefoxWire-' + [Guid]::NewGuid().ToString()
        New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block -Profile Any `
            -Program $program -RemoteAddress $deny | Out-Null
        $rules += $name
    }
    & $Python ci/firefox_reference_capture.py capture win_amd64 $Release $Work $Evidence --samples $Samples
    $result = $LASTEXITCODE
} finally {
    foreach ($name in $rules) { Remove-NetFirewallRule -Name $name }
}
exit $result
