$CurrentDomain = $env:USERDNSDOMAIN 
$SrvQuery = "_ldap._tcp.dc._msdcs.$CurrentDomain" 
$TimeoutMS = 1000 

Resolve-DnsName -Name $SrvQuery -Type SRV -ErrorAction SilentlyContinue | ForEach-Object { 
	$Target = $_.Target 
	$IP = (Resolve-DnsName $Target -Type A -ErrorAction SilentlyContinue).IPAddress | Select-Object -First 1 
	
	if ($IP) { 
		$TcpClient = New-Object System.Net.Sockets.TcpClient 
		$Connect = $TcpClient.BeginConnect($IP, 389, $null, $null) 
		$Wait = $Connect.AsyncWaitHandle.WaitOne($TimeoutMS, $false) 
		
		$IsOpen = if ($Wait) { 
			try { $TcpClient.EndConnect($Connect); $true } catch { $false } 
		} else { $false } 
		
		$TcpClient.Close(); $TcpClient.Dispose() 
		
		[PSCustomObject]@{ 
			DC = $Target 
			IP = $IP 
			LDAP_Open = $IsOpen 
			Domain = $CurrentDomain 
		}
	} 
} | Format-Table -AutoSize
