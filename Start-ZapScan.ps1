Write-Host "Script execution started."

#> {{.SYNOPSIS}}
#> Script to launch OWASP ZAP in headless mode.
#>
#> {{.DESCRIPTION}}
#> This script launches OWASP ZAP as a daemon (without GUI),
#> making its API available on a specified port for automated interaction.
#>
#> {{.PARAMETER PathToZap}}
#> Full path to the zap.bat executable (or zap.sh on other OS).
#>
#> {{.PARAMETER ApiPort}}
#> The port on which the ZAP API will be available. Defaults to 8080.
#>
#> {{.EXAMPLE}}
#> .\Start-ZapScan.ps1 -PathToZap "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -ApiPort 8081
#>
#> {{.NOTES}}
#> Requires OWASP ZAP to be installed.
#>
function Start-ZapScan {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$PathToZap,

        [Parameter(Mandatory=$false)]
        [int]$ApiPort = 8080
    )

    # Check if ZAP executable exists (we will still check for zap.bat path existence as it implies ZAP installation)
    if (-not (Test-Path $PathToZap)) {
        Write-LogMessage -Level ERROR -Message "ZAP installation not found at '$PathToZap'. Check the path and try again."
        return
    }

    # Get the directory of zap.bat, which should be the ZAP installation directory
    $zapDirectory = Split-Path -Path $PathToZap -Parent

    # Construct the full path to the ZAP JAR file based on the ZAP directory and expected JAR name
    # NOTE: If the JAR file name changes in future ZAP versions, this might need updating.
    $zapJarPath = Join-Path -Path $zapDirectory -ChildPath "zap-2.16.1.jar"

    # Check if the ZAP JAR file exists
    if (-not (Test-Path $zapJarPath)) {
        Write-LogMessage -Level ERROR -Message "ZAP JAR file not found at '$zapJarPath'. Ensure ZAP 2.16.1 is correctly installed."
        return
    }

    Write-LogMessage -Level INFO -Message "Starting OWASP ZAP in headless mode on port $ApiPort directly via java.exe..."

    # Command to launch ZAP JAR directly using java.exe
    # -Xmx512m sets max heap size (can be adjusted)
    # -jar specifies the JAR file to execute
    # -daemon runs ZAP without a GUI
    # -port sets the API port
    $javaArgs = "-Xmx512m -jar `"$zapJarPath`" -daemon -port $ApiPort"

    # Use Start-Process to launch java.exe with arguments using the absolute path
    # -WorkingDirectory ensures java.exe runs from the ZAP installation directory, which might help with ZAP's internal file lookups
    $javaExePath = "C:\Program Files\Eclipse Adoptium\jdk-21.0.7.6-hotspot\bin\java.exe"
    Start-Process -FilePath $javaExePath -ArgumentList $javaArgs -NoNewWindow -WorkingDirectory $zapDirectory

    Write-LogMessage -Level INFO -Message "Startup command executed. Check ZAP logs for confirmation of successful launch and API availability."
}

# Example usage:
# Replace the path to zap.bat with the actual path on your system
# Start-ZapScan -PathToZap "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -ApiPort 8080

#> {{.SYNOPSIS}}
#> Script to stop OWASP ZAP via API.
#>
#> {{.DESCRIPTION}}
#> This script sends a shutdown command to a running OWASP ZAP instance
#> through its API.
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.EXAMPLE}}
#> .\Start-ZapScan.ps1; Stop-ZapScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY"
#>
#> {{.NOTES}}
#> Requires ZAP to be running with API enabled and an API Key set.
#>
function Stop-ZapScan {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZapApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey
    )

    Write-LogMessage -Level INFO -Message "Stopping OWASP ZAP via API..."

    try {
        $headers = @{"X-ZAP-API-Key" = $ZapApiKey}
        $uri = "$ZapApiUrl/JSON/core/action/shutdown/"

        # Use Invoke-RestMethod to send a GET request for shutdown
        Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30

        Write-LogMessage -Level INFO -Message "Shutdown command sent. ZAP should be terminating."
    }
    catch {
        Write-LogMessage -Level ERROR -Message "Error attempting to stop ZAP: $($_.Exception.Message)"
        Write-LogMessage -Level WARNING -Message "ZAP may have already been stopped or is unreachable."
    }
}

#> {{.SYNOPSIS}}
#> Starts a Spider scan in OWASP ZAP.
#>
#> {{.DESCRIPTION}}
#> Sends a command to the OWASP ZAP API to start the Spider on the specified URL.
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.PARAMETER TargetUrl}}
#> URL of the target web application for Spider scanning.
#>
#> {{.EXAMPLE}}
#> Start-ZapSpiderScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -TargetUrl "http://testphp.vulnweb.com/"
#>
#> {{.NOTES}}
#> Requires ZAP to be running and API accessible.
#>
function Start-ZapSpiderScan {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetUrl,
        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey
    )

    Write-LogMessage -Level INFO -Message "Starting spider scan for '$TargetUrl'..."

    try {
        $headers = @{"X-ZAP-API-Key" = $ZapApiKey}
        # Assuming ZAP API is running on localhost:8080
        $zapApiUrl = "http://localhost:8080/JSON/spider/action/scan/"
        $body = @{ url = $TargetUrl }

        # Invoke the ZAP API endpoint to start the spider scan using form-urlencoded body
        $response = Invoke-RestMethod -Uri $zapApiUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -Headers $headers

        # Check the response for the scan ID (adjust based on actual ZAP API response structure)
        if ($response.scan) {
            $scanId = $response.scan
            Write-LogMessage -Level INFO -Message "Spider scan started with scan ID: $scanId"
            return $scanId
        } else {
            Write-LogMessage -Level WARNING -Message "Spider scan started, but no scan ID returned."
            return $null # Or handle appropriately if no ID is expected/needed immediately
        }

    } catch {
        $errorMessage = $_.Exception.Message
        Write-LogMessage -Level ERROR -Message "Error starting spider scan: $errorMessage"
        # Decide how to handle the error - e.g., re-throw, return specific error code
        throw "Failed to start spider scan: $errorMessage"
    }
}

#> {{.SYNOPSIS}}
#> Waits for a Spider scan in OWASP ZAP to complete.
#>
#> {{.DESCRIPTION}}
#> Periodically polls the ZAP API for the status of a Spider scan by its
#> ID and waits for it to finish (status 100%).
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.PARAMETER ScanId}}
#> ID of the Spider scan to track.
#>
#> {{.PARAMETER DelaySeconds}}
#> Delay in seconds between status checks. Defaults to 5 seconds.
#>
#> {{.PARAMETER TimeoutSeconds}}
#> Maximum wait time in seconds. Defaults to 3600 seconds (1 hour).
#>
#> {{.EXAMPLE}}
#> $spiderScanId = Start-ZapSpiderScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -TargetUrl "http://testphp.vulnweb.com/"
#> if ($spiderScanId) {
#>     Wait-ZapSpiderScanComplete -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -ScanId $spiderScanId
#> }
#>
#> {{.NOTES}}
#> Requires ZAP to be running and API accessible.
#>
function Wait-ZapSpiderScanComplete {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZapApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey,

        [Parameter(Mandatory=$true)]
        [string]$ScanId,

        [Parameter(Mandatory=$false)]
        [int]$DelaySeconds = 5,

        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 3600
    )

    Write-LogMessage -Level INFO -Message "Waiting for Spider scan with ID '$ScanId' to complete..."

    $startTime = Get-Date
    $status = "-1" # Initially unknown status

    while ($status -ne "100") {
        $elapsedTime = (Get-Date) - $startTime

        if ($elapsedTime.TotalSeconds -ge $TimeoutSeconds) {
            Write-LogMessage -Level ERROR -Message "Timeout ($TimeoutSeconds sec.) reached waiting for Spider scan with ID '$ScanId'. Current status: $status%"
            return $false
        }

        try {
            $headers = @{"X-ZAP-API-Key" = $ZapApiKey}
            # Endpoint to get Spider status: /JSON/spider/view/status/
            $uri = "$ZapApiUrl/JSON/spider/view/status/?scanId=$ScanId"

            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 10 # Short timeout for polling

            if ($response -and $null -ne $response.status) {
                $status = $response.status
            } else {
                # Could add retry logic or termination for repeated API status errors
            }
        }
        catch {
            # Polling errors can be temporary, log them as Warning
            Write-LogMessage -Level WARNING -Message "Error getting status for Spider scan with ID '$ScanId': $($_.Exception.Message)"
            # Continue attempts if it's a temporary network error or ZAP is loading
        }

        if ($status -ne "100") {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    Write-LogMessage -Level INFO -Message "Spider scan with ID '$ScanId' completed (100%)."
    return $true
}

#> {{.SYNOPSIS}}
#> Starts an Active Scan in OWASP ZAP.
#>
#> {{.DESCRIPTION}}
#> Sends a command to the OWASP ZAP API to start an Active Scan on the specified URL
#> or context.
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.PARAMETER TargetUrl}}
#> URL of the target web application or a URL from a context for the Active Scan.
#>
#> {{.PARAMETER ContextId}}
#> ID of the context for scanning (optional). If specified, the entire context is scanned.
#>
#> {{.EXAMPLE}}
#> Start-ZapActiveScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -TargetUrl "http://testphp.vulnweb.com/"
#>
#> {{.EXAMPLE}}
#> # Scanning by context (assumes context with ID 1 exists and is configured)
#> Start-ZapActiveScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -ContextId "1"
#>
#> {{.NOTES}}
#> Requires ZAP to be running and API accessible.
#> Can take significant time depending on the application size and scan settings.
#>
function Start-ZapActiveScan {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZapApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey,

        [Parameter(Mandatory=$false)]
        [string]$TargetUrl,

        [Parameter(Mandatory=$false)]
        [string]$ContextId # ZAP API expects string for contextId
    )

    if (-not $TargetUrl -and -not $ContextId) {
        Write-LogMessage -Level ERROR -Message "Either TargetUrl or ContextId must be specified for Active Scan."
        return $null
    }

    $scanTarget = if ($TargetUrl) {"URL '$TargetUrl'"} else {"Context ID '$ContextId'"}
    Write-LogMessage -Level INFO -Message "Starting Active Scan for $scanTarget..."

    Write-LogMessage -Level INFO -Message "Attempting to start Active Scan via API for $scanTarget."

    try {
        $headers = @{"X-ZAP-API-Key" = $ZapApiKey}
        $uri = "$ZapApiUrl/JSON/ascan/action/scan/"

        # Build request parameters
        $params = @{}
        if ($TargetUrl) {
            $params["url"] = $TargetUrl
        } elseif ($ContextId) {
            $params["contextId"] = $ContextId
            # For context scanning, you might also need RootUrl, but the /ascan/action/scan/ API doesn't have this parameter directly.
            # ZAP usually uses URLs already known from the session/Spider, or you can use ascan/action/scanAsUser for scanning within a user's context.
            # For now, we'll stick to the basic call by ContextId.
        }
        # Other parameters can be added if needed (e.g., recurse, scanPolicyName, method, postData, justInScope, failOnStartError, excludeList)
        # $params["scanPolicyName"] = "Default Policy"

        # Send POST request (although ZAP API often accepts GET for action)
        # POST is preferred for more reliable parameter passing, especially with long URLs or POST data.
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $params -Headers $headers -TimeoutSec 60

        # Check API response
        if ($response -and $null -ne $response.scan) {
            $scanId = $response.scan
            Write-LogMessage -Level INFO -Message "Active Scan started with ID: $scanId"
            return $scanId # Return scan ID
        } else {
            Write-LogMessage -Level ERROR -Message "Error starting Active Scan for $scanTarget. API response: $($response | Out-String)"
            return $null
        }
    }
    catch {
        Write-LogMessage -Level ERROR -Message "Error calling ZAP API to start Active Scan: $($_.Exception.Message)"
        return $null
    }
}

#> {{.SYNOPSIS}}
#> Waits for an Active Scan in OWASP ZAP to complete.
#>
#> {{.DESCRIPTION}}
#> Periodically polls the ZAP API for the status of an Active Scan
#> by its ID and waits for it to finish (status 100%).
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.PARAMETER ScanId}}
#> ID of the Active Scan to track.
#>
#> {{.PARAMETER DelaySeconds}}
#> Delay in seconds between status checks. Defaults to 10 seconds.
#>
#> {{.PARAMETER TimeoutSeconds}}
#> Maximum wait time in seconds. Defaults to 7200 seconds (2 hours).
#>
#> {{.EXAMPLE}}
#> $activeScanId = Start-ZapActiveScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -TargetUrl "http://testphp.vulnweb.com/"
#> if ($activeScanId) {
#>     Wait-ZapActiveScanComplete -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -ScanId $activeScanId
#> }
#>
#> {{.NOTES}}
#> Requires ZAP to be running and API accessible.
#>
function Wait-ZapActiveScanComplete {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZapApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey,

        [Parameter(Mandatory=$true)]
        [string]$ScanId,

        [Parameter(Mandatory=$false)]
        [int]$DelaySeconds = 10, # Active Scan usually takes longer, increasing default delay

        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 7200 # Active Scan can run for a long time, increasing default timeout
    )

    Write-LogMessage -Level INFO -Message "Waiting for Active Scan with ID '$ScanId' to complete..."

    $startTime = Get-Date
    $status = "-1" # Initially unknown status

    while ($status -ne "100") {
        $elapsedTime = (Get-Date) - $startTime

        if ($elapsedTime.TotalSeconds -ge $TimeoutSeconds) {
            Write-LogMessage -Level ERROR -Message "Timeout ($TimeoutSeconds sec.) reached waiting for Active Scan with ID '$ScanId'. Current status: $status%"
            return $false
        }

        try {
            $headers = @{"X-ZAP-API-Key" = $ZapApiKey}
            # Endpoint to get Active Scan status: /JSON/ascan/view/status/
            $uri = "$ZapApiUrl/JSON/ascan/view/status/?scanId=$ScanId"

            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 15 # Short timeout for polling

            if ($response -and $null -ne $response.status) {
                $status = $response.status
            } else {
                # Could add retry logic or termination for repeated API status errors
            }
        }
        catch {
            # Polling errors can be temporary, log them as Warning
            Write-LogMessage -Level WARNING -Message "Error getting status for Active Scan with ID '$ScanId': $($_.Exception.Message)"
            # Continue attempts if it's a temporary network error or ZAP is loading
        }

        if ($status -ne "100") {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    Write-LogMessage -Level INFO -Message "Spider scan with ID '$ScanId' completed (100%)."
    return $true
}

#> {{.SYNOPSIS}}
#> Retrieves a list of vulnerabilities (alerts) from OWASP ZAP.
#>
#> {{.DESCRIPTION}}
#> Sends a request to the OWASP ZAP API to get a list of all findings
#> in the current session.
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.EXAMPLE}}
#> $alerts = Get-ZapAlerts -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY"
#> $alerts | Format-Table Risk, Confidence, Name, Url
#>
#> {{.NOTES}}
#> Requires ZAP to be running and API accessible.
#> Returns an array of objects representing the vulnerabilities.
#>
function Get-ZapAlerts {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZapApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey
    )

    Write-LogMessage -Level INFO -Message "Retrieving vulnerability list from ZAP API..."

    try {
        $headers = @{"X-ZAP-API-Key" = $ZapApiKey}
        # Endpoint to get alerts: /JSON/core/view/alerts/
        # Parameters count and start can be used for pagination, but for simplicity we get all by default.
        $uri = "$ZapApiUrl/JSON/core/view/alerts/"

        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 60

        # Check API response. ZAP API for alerts returns an object with an 'alerts' field.
        if ($response -and $null -ne $response.alerts) {
            Write-LogMessage -Level INFO -Message "Retrieved $($response.alerts.Count) vulnerabilities."
            return $response.alerts # Return array of vulnerabilities
        } else {
            Write-LogMessage -Level INFO -Message "No vulnerabilities found or API response is empty."
            return @() # Return empty array if no vulnerabilities or empty response
        }
    }
    catch {
        Write-LogMessage -Level ERROR -Message "Error calling ZAP API to get vulnerabilities: $($_.Exception.Message)"
        return $null # Return null in case of error
    }
}

#> {{.SYNOPSIS}}
#> Generates a scan report in OWASP ZAP.
#>
#> {{.DESCRIPTION}}
#> Sends a request to the OWASP ZAP API to generate a report based on the results
#> of the current scan session in the specified format and saves it to a file.
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.PARAMETER ReportPath}}
#> Full path to the file where the report will be saved (e.g., C:\Reports\zap_scan_report.html).
#> The file extension should match the report format.
#>
#> {{.PARAMETER ReportFormat}}
#> Report format (e.g., 'html', 'json', 'xml', 'sarif').
#>
#> {{.EXAMPLE}}
#> Export-ZapReport -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -ReportPath "C:\temp\my_zap_report.html" -ReportFormat "html"
#>
#> {{.NOTES}}
#> Requires ZAP to be running and API accessible, and the scan to be completed.
#> Ensure the user running ZAP has write permissions to the specified ReportPath directory.
#>
function Export-ZapReport {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZapApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey,

        [Parameter(Mandatory=$true)]
        [string]$ReportPath,

        [Parameter(Mandatory=$true)]
        [string]$ReportFormat
    )

    Write-LogMessage -Level INFO -Message "Generating ZAP report in '$ReportFormat' format to file '$ReportPath'..."

    try {
        $headers = @{"X-ZAP-API-Key" = $ZapApiKey}
        # Endpoint for report generation: /JSON/reports/action/generate/
        $reportUri = "$ZapApiUrl/JSON/reports/action/generate/"
        
        # Ensure the report directory exists
        $reportDir = Split-Path -Path $ReportPath -Parent
        if (-not (Test-Path -Path $reportDir)) {
            New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        }

        # Prepare the request body
        $body = @{
            title = "ZAP Scan Report"
            template = "traditional-html"
            reportDir = $reportDir
            reportFileName = Split-Path -Path $ReportPath -Leaf
            display = $true
        }

        Write-LogMessage -Level INFO -Message "Sending report generation request to ZAP API..."
        
        $response = Invoke-RestMethod -Uri $reportUri -Method Post -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded" -TimeoutSec 120
        
        if ($response.generate) {
            Write-LogMessage -Level INFO -Message "Report generated successfully at: $($response.generate)"
            return $true
        } else {
            Write-LogMessage -Level ERROR -Message "Failed to generate report. Response: $($response | ConvertTo-Json)"
            return $false
        }
    }
    catch {
        Write-LogMessage -Level ERROR -Message "Error generating report: $($_.Exception.Message)"
        if ($_.ErrorDetails) {
            Write-LogMessage -Level ERROR -Message "Error details: $($_.ErrorDetails.Message)"
        }
        return $false
    }
}

#> {{.SYNOPSIS}}
#> Helper function for logging messages with a timestamp.
#>
#> {{.DESCRIPTION}}
#> Formats and outputs messages of different levels (INFO, WARNING, ERROR)
#> with the current timestamp.
#>
#> {{.PARAMETER Level}}
#> Message level (INFO, WARNING, ERROR).
#>
#> {{.PARAMETER Message}}
#> Text message to output.
#>
#> {{.EXAMPLE}}
#> Write-LogMessage -Level INFO -Message "Operation completed successfully."
#>
#> {{.EXAMPLE}}
#> Write-LogMessage -Level ERROR -Message "Failed to connect to ZAP API."
#>
function Write-LogMessage {
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level,

        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "INFO" {
            Write-Host $formattedMessage
        }
        "WARNING" {
            Write-Warning $formattedMessage
        }
        "ERROR" {
            Write-Error $formattedMessage
        }
    }
}

#> {{.SYNOPSIS}}
#> Main orchestrator script for running a full OWASP ZAP scan cycle.
#>
#> {{.DESCRIPTION}}
#> Launches OWASP ZAP in headless mode, performs Spider and Active scans,
#> waits for their completion, generates a report, and stops ZAP.
#>
#> {{.PARAMETER PathToZap}}
#> Full path to the zap.bat executable.
#>
#> {{.PARAMETER ZapApiUrl}}
#> Base URL of the ZAP API (e.g., http://localhost:8080).
#>
#> {{.PARAMETER ZapApiKey}}
#> API Key for request authentication.
#>
#> {{.PARAMETER TargetUrls}}
#> Array of URLs of target web applications to scan.
#>
#> {{.PARAMETER ReportPath}}
#> Full path to the file where the report will be saved.
#>
#> {{.PARAMETER ReportFormat}}
#> Report format (e.g., 'html', 'json', 'xml', 'sarif').
#>
#> {{.PARAMETER SpiderDelaySeconds}}
#> Delay in seconds between Spider status checks (defaults to 5).
#>
#> {{.PARAMETER SpiderTimeoutSeconds}}
#> Maximum wait time for Spider in seconds (defaults to 3600).
#>
#> {{.PARAMETER ActiveScanDelaySeconds}}
#> Delay in seconds between Active Scan status checks (defaults to 10).
#>
#> {{.PARAMETER ActiveScanTimeoutSeconds}}
#> Maximum wait time for Active Scan in seconds (defaults to 7200).
#>
#> {{.PARAMETER LogFilePath}}
#> Optional path to a log file.
#>
#> {{.EXAMPLE}}
#> Invoke-ZapScan -PathToZap "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -ZapApiUrl "http://localhost:8080" -ZapApiKey "YOUR_API_KEY" -TargetUrls @("https://adss.arcelormittal.com.ua/", "https://another-site.com/") -ReportPath "C:\temp\ZAP Scan\multi_site_scan_report.html" -ReportFormat "html" -LogFilePath "C:\logs\zap_scan.log"
#>
#> {{.NOTES}}
#> Ensure ZAP is installed and API Key is configured.
#>
function Invoke-ZapScan {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$PathToZap,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiUrl,

        [Parameter(Mandatory=$true)]
        [string]$ZapApiKey,

        [Parameter(Mandatory=$true)]
        [string[]]$TargetUrls,

        [Parameter(Mandatory=$true)]
        [string]$ReportPath,

        [Parameter(Mandatory=$true)]
        [string]$ReportFormat,

        [Parameter(Mandatory=$false)]
        [int]$SpiderDelaySeconds = 5,

        [Parameter(Mandatory=$false)]
        [int]$SpiderTimeoutSeconds = 3600,

        [Parameter(Mandatory=$false)]
        [int]$ActiveScanDelaySeconds = 10,

        [Parameter(Mandatory=$false)]
        [int]$ActiveScanTimeoutSeconds = 7200,

        [Parameter(Mandatory=$false)]
        [string]$LogFilePath # Optional path to a log file
    )

    Write-LogMessage -Level INFO -Message "Entering Invoke-ZapScan function."

    Write-LogMessage -Level INFO -Message "Starting full ZAP scan cycle for target URLs..."

    # 1. Launch ZAP in headless mode
    Write-LogMessage -Level INFO -Message "Step 1: Launching ZAP..."
    Start-ZapScan -PathToZap $PathToZap -ApiPort $($ZapApiUrl -split ":")[-1] # Extract port from URL

    # Give ZAP some time to start
    Start-Sleep -Seconds 10

    # Check if ZAP API is available
    try {
        Invoke-RestMethod -Uri "$ZapApiUrl/JSON/core/view/version/" -Method Get -Headers @{"X-ZAP-API-Key" = $ZapApiKey} -TimeoutSec 5 | Out-Null
        Write-LogMessage -Level INFO -Message "ZAP API is available."
    } catch {
        Write-LogMessage -Level ERROR -Message "Failed to connect to ZAP API at '$ZapApiUrl'. Ensure ZAP is running and the port is accessible."
        Write-LogMessage -Level ERROR -Message "Scan process aborted."
        try { Stop-ZapScan -ZapApiUrl $ZapApiUrl -ZapApiKey $ZapApiKey } catch { Write-LogMessage -Level WARNING -Message "Failed to stop ZAP after API connection failure."}
        return $false
    }

    # Process each target URL
    foreach ($targetUrl in $TargetUrls) {
        Write-LogMessage -Level INFO -Message "Starting scan for target URL: $targetUrl"

        # 2. Start Spider scan
        Write-LogMessage -Level INFO -Message "Step 2: Starting Spider scan..."
        $spiderScanId = Start-ZapSpiderScan -TargetUrl $targetUrl -ZapApiKey $ZapApiKey

        if (-not $spiderScanId) {
            Write-LogMessage -Level ERROR -Message "Failed to start Spider scan for $targetUrl. Skipping to next URL."
            continue
        }

        # 3. Wait for Spider scan to complete
        Write-LogMessage -Level INFO -Message "Step 3: Waiting for Spider scan to complete..."
        $spiderScanComplete = Wait-ZapSpiderScanComplete -ZapApiUrl $ZapApiUrl -ZapApiKey $ZapApiKey -ScanId $spiderScanId -DelaySeconds $SpiderDelaySeconds -TimeoutSeconds $SpiderTimeoutSeconds

        if (-not $spiderScanComplete) {
            Write-LogMessage -Level ERROR -Message "Spider scan did not complete within the expected time for $targetUrl. Skipping to next URL."
            continue
        }

        # 4. Start Active Scan
        Write-LogMessage -Level INFO -Message "Step 4: Starting Active Scan..."
        $activeScanId = Start-ZapActiveScan -ZapApiUrl $ZapApiUrl -ZapApiKey $ZapApiKey -TargetUrl $targetUrl

        if (-not $activeScanId) {
            Write-LogMessage -Level ERROR -Message "Failed to start Active Scan for $targetUrl. Skipping to next URL."
            continue
        }

        # 5. Wait for Active Scan to complete
        Write-LogMessage -Level INFO -Message "Step 5: Waiting for Active Scan to complete..."
        $activeScanComplete = Wait-ZapActiveScanComplete -ZapApiUrl $ZapApiUrl -ZapApiKey $ZapApiKey -ScanId $activeScanId -DelaySeconds $ActiveScanDelaySeconds -TimeoutSeconds $ActiveScanTimeoutSeconds

        if (-not $activeScanComplete) {
            Write-LogMessage -Level ERROR -Message "Active Scan did not complete within the expected time for $targetUrl. Skipping to next URL."
            continue
        }
    }

    # 6. Retrieve vulnerability list for all scanned URLs
    Write-LogMessage -Level INFO -Message "Step 6: Retrieving vulnerability list..."
    $alerts = Get-ZapAlerts -ZapApiUrl $ZapApiUrl -ZapApiKey $ZapApiKey

    if ($null -ne $alerts) {
        Write-LogMessage -Level INFO -Message "Retrieved $($alerts.Count) vulnerabilities."
    } else {
         Write-LogMessage -Level WARNING -Message "Failed to retrieve vulnerability list or none found."
    }

    # 7. Generate report
    Write-LogMessage -Level INFO -Message "Step 7: Generating report..."
    $reportGenerated = Export-ZapReport -ZapApiUrl $ZapApiUrl -ZapApiKey $ZapApiKey -ReportPath $ReportPath -ReportFormat $ReportFormat

    if (-not $reportGenerated) {
         Write-LogMessage -Level ERROR -Message "Failed to generate report. Check the path and permissions."
    } else {
         Write-LogMessage -Level INFO -Message "Report successfully generated to '$ReportPath'."
    }

    # 8. Stop ZAP
    Write-LogMessage -Level INFO -Message "Step 8: Stopping ZAP..."
    Stop-ZapScan -ZapApiUrl $ZapApiUrl -ZapApiKey $ZapApiKey

    Write-LogMessage -Level INFO -Message "Full ZAP scan cycle completed for all target URLs."
    return $true
}

# Example usage with multiple URLs:
Invoke-ZapScan `
    -PathToZap "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat" `
    -ZapApiUrl "http://localhost:8080" `
    -ZapApiKey "u2vmihv29mvurstgr2iniv0ndp" `
    -TargetUrls @("https://adss.arcelormittal.com.ua/", "http://krr-www-itinfo.europe.mittalco.com/") `
    -ReportPath "C:\temp\ZAP Scan\multi_site_scan_report.html" `
    -ReportFormat "html" 