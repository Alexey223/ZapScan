Import-Module Pester -ErrorAction Stop

Describe 'Start-ZapScan.ps1 Module' {
    # Source the functions from the main script file
    BeforeAll {
        . $PSScriptRoot\Start-ZapScan.ps1
    }

    Context 'Start-ZapScan Function' {
        It 'Should check for ZAP executable existence' {
            # TODO: Add a test case for Start-ZapScan
            # This test should mock Test-Path and verify the function's behavior
            # Mock Test-Path to return false, verify Write-LogMessage is called with ERROR level and the function returns
            Mock Test-Path { return $false }
            Mock Write-LogMessage

            Start-ZapScan -PathToZap "C:\fake\zap.bat" -ApiPort 8080

            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }
            # In Pester 5+, you might check the function's return value or lack thereof if it explicitly returns nothing
            # For simplicity here, we focus on the logging and not proceeding.
        }

        It 'Should call Start-Process with correct arguments when executable exists' {
            # Mock Test-Path to return true, mock Start-Process to capture arguments
            Mock Test-Path { return $true }
            Mock Start-Process {
                Param($FilePath, $ArgumentList, $NoNewWindow)
                # Capture arguments passed to Start-Process
                $Script:CapturedFilePath = $FilePath
                $Script:CapturedArgumentList = $ArgumentList
                $Script:CapturedNoNewWindow = $NoNewWindow
            }
            Mock Write-LogMessage # Mock logging to prevent console output during test

            $zapPath = "C:\path\to\real\zap.bat"
            $apiPort = 8081

            Start-ZapScan -PathToZap $zapPath -ApiPort $apiPort

            # Assert that Start-Process was called exactly once
            Assert-MockCalled Start-Process -Exactly 1

            # Assert that Start-Process was called with the correct parameters
            $Script:CapturedFilePath | Should -Be $zapPath
            $Script:CapturedArgumentList | Should -Contain "-daemon"
            $Script:CapturedArgumentList | Should -Contain "-port $apiPort"
            $Script:CapturedNoNewWindow | Should -BeTrue
        }

        # TODO: Add more test cases for Start-ZapScan (e.g., default ApiPort)
    }

    Context 'Stop-ZapScan Function' {
        It 'Should call Invoke-RestMethod with correct parameters' {
            # Mock Invoke-RestMethod to ensure it's called with the right arguments
            Mock Invoke-RestMethod {
                Param($Uri, $Method, $Headers, $TimeoutSec)
                # Capture arguments
                $Script:CapturedUri = $Uri
                $Script:CapturedMethod = $Method
                $Script:CapturedHeaders = $Headers
                $Script:CapturedTimeout = $TimeoutSec
            }
            Mock Write-LogMessage # Mock logging

            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"

            Stop-ZapScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey

            # Assert that Invoke-RestMethod was called exactly once
            Assert-MockCalled Invoke-RestMethod -Exactly 1

            # Assert that Invoke-RestMethod was called with the correct parameters
            $Script:CapturedUri | Should -Be "$apiUrl/JSON/core/action/shutdown/"
            $Script:CapturedMethod | Should -Be 'Get'
            $Script:CapturedHeaders['X-ZAP-API-Key'] | Should -Be $apiKey
            $Script:CapturedTimeout | Should -Be 30
        }

        It 'Should log error and warning messages on API call failure' {
            # Mock Invoke-RestMethod to throw an exception
            Mock Invoke-RestMethod { throw "Simulated API Error" }
            # Mock Write-LogMessage to verify calls
            Mock Write-LogMessage

            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"

            Stop-ZapScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey

            # Assert that Write-LogMessage was called with ERROR and WARNING levels
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'WARNING' }
        }
    }

    Context 'Start-ZapSpiderScan Function' {
        It 'Should call Invoke-RestMethod with correct parameters and return scan ID on success' {
            # Mock Invoke-RestMethod to return a successful response
            $mockScanId = "12345"
            Mock Invoke-RestMethod {
                Param($Uri, $Method, $Headers, $TimeoutSec)
                # Capture arguments
                $Script:CapturedUri = $Uri
                $Script:CapturedMethod = $Method
                $Script:CapturedHeaders = $Headers
                $Script:CapturedTimeout = $TimeoutSec
                # Return a dummy response object
                return [PSCustomObject]@{ scan = $mockScanId }
            }
            Mock Write-LogMessage # Mock logging

            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $targetUrl = "http://test.com/path with spaces"
            $escapedUrl = [uri]::EscapeDataString($targetUrl)

            $result = Start-ZapSpiderScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey -TargetUrl $targetUrl

            # Assert that Invoke-RestMethod was called correctly
            Assert-MockCalled Invoke-RestMethod -Exactly 1
            $Script:CapturedUri | Should -Be "$apiUrl/JSON/spider/action/scan/?url=$escapedUrl"
            $Script:CapturedMethod | Should -Be 'Get'
            $Script:CapturedHeaders['X-ZAP-API-Key'] | Should -Be $apiKey
            $Script:CapturedTimeout | Should -Be 60

            # Assert that Write-LogMessage was called for the INFO message
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Запуск Spider сканирования для '$targetUrl'..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Spider сканирование запущено с ID: $mockScanId" }

            # Assert that the function returned the scan ID
            $result | Should -Be $mockScanId
        }

        It 'Should log error and return null if API response is missing scan ID' {
            # Mock Invoke-RestMethod to return a response without a scan ID
            Mock Invoke-RestMethod {
                return [PSCustomObject]@{ otherField = "some value" }
            }
            Mock Write-LogMessage # Mock logging

            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $targetUrl = "http://test.com"

            $result = Start-ZapSpiderScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey -TargetUrl $targetUrl

            # Assert that Write-LogMessage was called with ERROR level
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }

            # Assert that the function returned null
            $result | Should -BeNull
        }

        It 'Should log error and return null on API call failure' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $targetUrl = "http://test.com"

            Mock Invoke-RestMethod { throw "Simulated API Exception" }
            Mock Write-LogMessage # Mock logging

            # Act
            $result = Start-ZapSpiderScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey -TargetUrl $targetUrl

            # Assert
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }

            # Assert that the function returned null
            $result | Should -BeNull
        }
    }

    Context 'Wait-ZapSpiderScanComplete Function' {
        It 'Should wait until status is 100 and return true' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $scanId = "spiderScan1"
            $delaySeconds = 1
            $timeoutSeconds = 60 # Keep timeout short for test

            # Mock Invoke-RestMethod to return status 50 on first call, then 100 on second call
            $callCount = 0
            Mock Invoke-RestMethod {
                $callCount++
                if ($callCount -eq 1) {
                    return [PSCustomObject]@{ status = "50" }
                } else {
                    return [PSCustomObject]@{ status = "100" }
                }
            }
            # Mock Start-Sleep to do nothing
            Mock Start-Sleep {}
            # Mock Write-LogMessage and Write-Host to verify output
            Mock Write-LogMessage
            Mock Write-Host

            # Act
            $result = Wait-ZapSpiderScanComplete -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ScanId $scanId -DelaySeconds $delaySeconds -TimeoutSeconds $timeoutSeconds

            # Assert
            # Verify Invoke-RestMethod was called at least twice (once for 50, once for 100)
            Assert-MockCalled Invoke-RestMethod -Times (Exactly 2) -ParameterFilter { Uri -eq "$apiUrl/JSON/spider/view/status/?scanId=$scanId" -and Method -eq 'Get' -and Headers['X-ZAP-API-Key'] -eq $apiKey }

            # Verify initial and final log messages
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Ожидание завершения Spider сканирования с ID '$scanId'..." }
            Assert-MockCalled Write-Host -Minimum 2 -ParameterFilter { Message -like "*Spider Scan ID '$scanId' статус:*" }
            Assert-MockCalled Write-Host -Exactly 1 -ParameterFilter { Message -eq "Spider сканирование с ID '$scanId' завершен (100%)." }

            # Verify return value
            $result | Should -BeTrue
        }

        It 'Should return false and log error if timeout is reached' {
             # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $scanId = "spiderScan2"
            $delaySeconds = 1
            $timeoutSeconds = 5 # Keep timeout short

            # Mock Get-Date to simulate time passing
            $currentTime = Get-Date
            $mockedDateCalls = 0
            Mock Get-Date {
                $mockedDateCalls++
                # Simulate time passing to exceed timeout quickly
                return $currentTime.AddSeconds($mockedDateCalls * $delaySeconds + $timeoutSeconds)
            }

            # Mock Invoke-RestMethod to always return status less than 100
            Mock Invoke-RestMethod { return [PSCustomObject]@{ status = "99" } }
            # Mock Start-Sleep to do nothing
            Mock Start-Sleep {}
            # Mock Write-LogMessage and Write-Host
            Mock Write-LogMessage
            Mock Write-Host

            # Act
            $result = Wait-ZapSpiderScanComplete -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ScanId $scanId -DelaySeconds $delaySeconds -TimeoutSeconds $timeoutSeconds

            # Assert
            # Verify Invoke-RestMethod was called at least once before timeout
            Assert-MockCalled Invoke-RestMethod -Minimum 1 -ParameterFilter { Uri -eq "$apiUrl/JSON/spider/view/status/?scanId=$scanId" }

            # Verify initial log message and timeout error message
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Ожидание завершения Spider сканирования с ID '$scanId'..." }
             # Check for the timeout error message with the correct scan ID and timeout value
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR'; Message -like "Превышено время ожидания ($timeoutSeconds сек.) завершения Spider сканирования с ID '$scanId'.*" }

            # Verify status updates were written to host
            Assert-MockCalled Write-Host -Minimum 1 -ParameterFilter { Message -like "*Spider Scan ID '$scanId' статус:*" }

            # Verify return value
            $result | Should -BeFalse
        }
        
         It 'Should log a warning on API polling failure but continue' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $scanId = "spiderScan3"
            $delaySeconds = 1
            $timeoutSeconds = 10 # Keep timeout short

            # Mock Get-Date to allow loop to run a few times before potential timeout
             $currentTime = Get-Date
            $mockedDateCalls = 0
            Mock Get-Date {
                $mockedDateCalls++
                return $currentTime.AddSeconds($mockedDateCalls * $delaySeconds)
            }

            # Mock Invoke-RestMethod to throw an exception on the first call, then return status 100 on the second
            $callCount = 0
            Mock Invoke-RestMethod {
                $callCount++
                if ($callCount -eq 1) {
                    throw "Simulated polling error"
                } else {
                    return [PSCustomObject]@{ status = "100" }
                }
            }
            # Mock Start-Sleep to do nothing
            Mock Start-Sleep {}
            # Mock Write-LogMessage and Write-Host
            Mock Write-LogMessage
            Mock Write-Host

            # Act
            $result = Wait-ZapSpiderScanComplete -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ScanId $scanId -DelaySeconds $delaySeconds -TimeoutSeconds $timeoutSeconds

            # Assert
            # Verify Invoke-RestMethod was called at least twice (error then success)
            Assert-MockCalled Invoke-RestMethod -Minimum 2 -ParameterFilter { Uri -eq "$apiUrl/JSON/spider/view/status/?scanId=$scanId" }

            # Verify initial and final log messages
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Ожидание завершения Spider сканирования с ID '$scanId'..." }
            Assert-MockCalled Write-Host -Exactly 1 -ParameterFilter { Message -eq "Spider сканирование с ID '$scanId' завершен (100%)." }

            # Verify the warning log message for the polling error
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'WARNING'; Message -like "Ошибка при получении статуса Spider сканирования с ID '$scanId':*" }
            
             # Verify status updates were written to host (at least once after the error and before completion)
            Assert-MockCalled Write-Host -Minimum 1 -ParameterFilter { Message -like "*Spider Scan ID '$scanId' статус:*" }

            # Verify return value is true as it eventually succeeded
            $result | Should -BeTrue
        }
    }

    Context 'Start-ZapActiveScan Function' {
        It 'Should call Invoke-RestMethod with correct parameters for URL scan and return scan ID' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $targetUrl = "http://test.com/activescan"
            $mockScanId = "activeScan1"

            Mock Invoke-RestMethod {
                Param($Uri, $Method, $Headers, $TimeoutSec, $Body)
                $Script:CapturedUri = $Uri
                $Script:CapturedMethod = $Method
                $Script:CapturedHeaders = $Headers
                $Script:CapturedTimeout = $TimeoutSec
                $Script:CapturedBody = $Body # Capture body for POST
                return [PSCustomObject]@{ scan = $mockScanId }
            }
            Mock Write-LogMessage # Mock logging

            # Act
            $result = Start-ZapActiveScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey -TargetUrl $targetUrl

            # Assert
            Assert-MockCalled Invoke-RestMethod -Exactly 1
            # Active Scan uses POST with URL as parameter
            $Script:CapturedUri | Should -Be "$apiUrl/JSON/ascan/action/scan/"
            $Script:CapturedMethod | Should -Be 'Post'
            $Script:CapturedHeaders['X-ZAP-API-Key'] | Should -Be $apiKey
            $Script:CapturedTimeout | Should -Be 60
            $Script:CapturedBody.url | Should -Be $targetUrl

            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Запуск Active сканирования для '$targetUrl'..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Active Scan запущен с ID: $mockScanId" }

            $result | Should -Be $mockScanId
        }

        It 'Should call Invoke-RestMethod with correct parameters for Context ID scan and return scan ID' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $contextId = "1"
            $mockScanId = "activeScan2"

            Mock Invoke-RestMethod {
                Param($Uri, $Method, $Headers, $TimeoutSec, $Body)
                $Script:CapturedUri = $Uri
                $Script:CapturedMethod = $Method
                $Script:CapturedHeaders = $Headers
                $Script:CapturedTimeout = $TimeoutSec
                $Script:CapturedBody = $Body # Capture body for POST
                return [PSCustomObject]@{ scan = $mockScanId }
            }
            Mock Write-LogMessage # Mock logging

            # Act
            $result = Start-ZapActiveScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ContextId $contextId

            # Assert
            Assert-MockCalled Invoke-RestMethod -Exactly 1
            $Script:CapturedUri | Should -Be "$apiUrl/JSON/ascan/action/scan/"
            $Script:CapturedMethod | Should -Be 'Post'
            $Script:CapturedHeaders['X-ZAP-API-Key'] | Should -Be $apiKey
            $Script:CapturedTimeout | Should -Be 60
            $Script:CapturedBody.contextId | Should -Be $contextId

            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Запуск Active сканирования для контекста с ID '$contextId'..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Active Scan запущен с ID: $mockScanId" }

            $result | Should -Be $mockScanId
        }

        It 'Should log error and return null if API response is missing scan ID' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $targetUrl = "http://test.com"

            Mock Invoke-RestMethod {
                return [PSCustomObject]@{ otherField = "some value" }
            }
            Mock Write-LogMessage # Mock logging

            # Act
            $result = Start-ZapActiveScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey -TargetUrl $targetUrl

            # Assert
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }
            $result | Should -BeNull
        }

         It 'Should log error and return null on API call failure' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $targetUrl = "http://test.com"

            Mock Invoke-RestMethod { throw "Simulated API Exception" }
            Mock Write-LogMessage # Mock logging

            # Act
            $result = Start-ZapActiveScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey -TargetUrl $targetUrl

            # Assert
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }
            $result | Should -BeNull
        }

        It 'Should log error and return null if neither TargetUrl nor ContextId are provided' {
             # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"

            Mock Write-LogMessage # Mock logging

            # Act
            $result = Start-ZapActiveScan -ZapApiUrl $apiUrl -ZapApiKey $apiKey # Missing required parameters

            # Assert
            # Verify that Invoke-RestMethod was NOT called
            Assert-MockCalled Invoke-RestMethod -Times 0
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }
            $result | Should -BeNull
        }
    }

    Context 'Wait-ZapActiveScanComplete Function' {
         It 'Should wait until status is 100 and return true' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $scanId = "activeScanWait1"
            $delaySeconds = 1
            $timeoutSeconds = 60 # Keep timeout short for test

            # Mock Invoke-RestMethod to return status 50 on first call, then 100 on second call
            $callCount = 0
            Mock Invoke-RestMethod {
                $callCount++
                if ($callCount -eq 1) {
                    return [PSCustomObject]@{ status = "50" }
                } else {
                    return [PSCustomObject]@{ status = "100" }
                }
            }
            # Mock Start-Sleep to do nothing
            Mock Start-Sleep {}
            # Mock Write-LogMessage and Write-Host to verify output
            Mock Write-LogMessage
            Mock Write-Host

            # Act
            $result = Wait-ZapActiveScanComplete -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ScanId $scanId -DelaySeconds $delaySeconds -TimeoutSeconds $timeoutSeconds

            # Assert
            Assert-MockCalled Invoke-RestMethod -Times (Exactly 2) -ParameterFilter { Uri -eq "$apiUrl/JSON/ascan/view/status/?scanId=$scanId" -and Method -eq 'Get' -and Headers['X-ZAP-API-Key'] -eq $apiKey }

            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Ожидание завершения Active сканирования с ID '$scanId'..." }
            Assert-MockCalled Write-Host -Minimum 2 -ParameterFilter { Message -like "*Active Scan ID '$scanId' статус:*" }
            Assert-MockCalled Write-Host -Exactly 1 -ParameterFilter { Message -eq "Active сканирование с ID '$scanId' завершен (100%)." }

            $result | Should -BeTrue
        }

        It 'Should return false and log error if timeout is reached' {
             # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $scanId = "activeScanWait2"
            $delaySeconds = 1
            $timeoutSeconds = 5 # Keep timeout short

            # Mock Get-Date to simulate time passing
            $currentTime = Get-Date
            $mockedDateCalls = 0
            Mock Get-Date {
                $mockedDateCalls++
                # Simulate time passing to exceed timeout quickly
                return $currentTime.AddSeconds($mockedDateCalls * $delaySeconds + $timeoutSeconds)
            }

            # Mock Invoke-RestMethod to always return status less than 100
            Mock Invoke-RestMethod { return [PSCustomObject]@{ status = "99" } }
            # Mock Start-Sleep to do nothing
            Mock Start-Sleep {}
            # Mock Write-LogMessage and Write-Host
            Mock Write-LogMessage
            Mock Write-Host

            # Act
            $result = Wait-ZapActiveScanComplete -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ScanId $scanId -DelaySeconds $delaySeconds -TimeoutSeconds $timeoutSeconds

            # Assert
            Assert-MockCalled Invoke-RestMethod -Minimum 1 -ParameterFilter { Uri -eq "$apiUrl/JSON/ascan/view/status/?scanId=$scanId" }

            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Ожидание завершения Active сканирования с ID '$scanId'..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR'; Message -like "*timed out after*" }

            $result | Should -BeFalse
        }

         It 'Should log error and return false on API call failure' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $scanId = "activeScanWait3"
            $delaySeconds = 1
            $timeoutSeconds = 10

            Mock Invoke-RestMethod { throw "Simulated API Exception during wait" }
            Mock Start-Sleep {}
            Mock Write-LogMessage
            Mock Write-Host

            # Act
            $result = Wait-ZapActiveScanComplete -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ScanId $scanId -DelaySeconds $delaySeconds -TimeoutSeconds $timeoutSeconds

            # Assert
             Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Ожидание завершения Active сканирования с ID '$scanId'..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }

            $result | Should -BeFalse
        }
    }

    Context 'Get-ZapAlerts Function' {
        It 'Should call Invoke-RestMethod with correct parameters and return alerts on success' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $mockAlerts = @(
                @{ alert = "SQL Injection"; risk = "High" },
                @{ alert = "XSS"; risk = "Medium" }
            )

            Mock Invoke-RestMethod {
                 Param($Uri, $Method, $Headers, $TimeoutSec)
                $Script:CapturedUri = $Uri
                $Script:CapturedMethod = $Method
                $Script:CapturedHeaders = $Headers
                $Script:CapturedTimeout = $TimeoutSec
                return [PSCustomObject]@{ alerts = $mockAlerts }
            }
            Mock Write-LogMessage

            # Act
            $result = Get-ZapAlerts -ZapApiUrl $apiUrl -ZapApiKey $apiKey

            # Assert
            Assert-MockCalled Invoke-RestMethod -Exactly 1
            $Script:CapturedUri | Should -Be "$apiUrl/JSON/core/view/alerts/"
            $Script:CapturedMethod | Should -Be 'Get'
            $Script:CapturedHeaders['X-ZAP-API-Key'] | Should -Be $apiKey
            $Script:CapturedTimeout | Should -Be 60

            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Получение списка уязвимостей..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Получено 2 уязвимостей." }

            $result | Should -Be $mockAlerts
        }

        It 'Should log info and return empty array if no alerts are found' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"

            Mock Invoke-RestMethod {
                 return [PSCustomObject]@{ alerts = @() }
            }
            Mock Write-LogMessage

            # Act
            $result = Get-ZapAlerts -ZapApiUrl $apiUrl -ZapApiKey $apiKey

            # Assert
            Assert-MockCalled Invoke-RestMethod -Exactly 1
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Получение списка уязвимостей..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Получено 0 уязвимостей." }

            $result | Should -Be @()
        }

         It 'Should log error and return null on API call failure' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"

            Mock Invoke-RestMethod { throw "Simulated API Exception during alerts" }
            Mock Write-LogMessage

            # Act
            $result = Get-ZapAlerts -ZapApiUrl $apiUrl -ZapApiKey $apiKey

            # Assert
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Получение списка уязвимостей..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }

            $result | Should -BeNull
        }
    }

    Context 'Generate-ZapReport Function' {
        It 'Should call Invoke-RestMethod with correct parameters and return true on success' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $reportPath = "C:\temp\report.html"
            $reportFormat = "html"

            Mock Invoke-RestMethod {
                 Param($Uri, $Method, $Headers, $TimeoutSec)
                $Script:CapturedUri = $Uri
                $Script:CapturedMethod = $Method
                $Script:CapturedHeaders = $Headers
                $Script:CapturedTimeout = $TimeoutSec
                # Simulate successful response (ZAP API for generate doesn't return much on success, just status 200)
                return $null # Or a dummy object if needed, but null is common for actions
            }
            # Mock Test-Path for the report file destination directory
            Mock Test-Path { return $true } # Assume directory exists for simplicity
            Mock Write-LogMessage

            # Act
            $result = Generate-ZapReport -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ReportPath $reportPath -ReportFormat $reportFormat

            # Assert
            Assert-MockCalled Invoke-RestMethod -Exactly 1
            # Note: Report path needs escaping for the URL
            $escapedReportPath = [uri]::EscapeDataString($reportPath)
            $Script:CapturedUri | Should -Be "$apiUrl/JSON/core/action/generate/?path=$escapedReportPath&format=$reportFormat"
            $Script:CapturedMethod | Should -Be 'Get'
            $Script:CapturedHeaders['X-ZAP-API-Key'] | Should -Be $apiKey
            $Script:CapturedTimeout | Should -Be 300 # Report generation can take longer

            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Генерация отчета формата '$reportFormat' в '$reportPath'..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Отчет успешно сгенерирован." }

            $result | Should -BeTrue # Assuming successful API call means success
        }

         It 'Should log error and return false on API call failure' {
            # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $reportPath = "C:\temp\report.html"
            $reportFormat = "html"

            Mock Invoke-RestMethod { throw "Simulated API Exception during report generation" }
            Mock Test-Path { return $true }
            Mock Write-LogMessage

            # Act
            $result = Generate-ZapReport -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ReportPath $reportPath -ReportFormat $reportFormat

            # Assert
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Генерация отчета формата '$reportFormat' в '$reportPath'..." }
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR' }

            $result | Should -BeFalse
        }

         It 'Should log error and return false if report directory does not exist' {
             # Arrange
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $reportPath = "C:\nonexistent\report.html"
            $reportFormat = "html"

            Mock Test-Path { return $false } # Simulate directory not existing
            # Mock Invoke-RestMethod - should not be called
            Mock Invoke-RestMethod {}
            Mock Write-LogMessage

            # Act
            $result = Generate-ZapReport -ZapApiUrl $apiUrl -ZapApiKey $apiKey -ReportPath $reportPath -ReportFormat $reportFormat

            # Assert
            Assert-MockCalled Test-Path -Exactly 1
            Assert-MockCalled Invoke-RestMethod -Times 0 # Invoke-RestMethod should NOT be called
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'ERROR'; Message -like "*родительская директория не существует*" }

            $result | Should -BeFalse
        }
    }

    Context "Invoke-ZapScan Function - Failure in Start-ZapScan" {
        Mock -CommandName Start-ZapScan -MockWith {
            throw "Simulated Start-ZapScan failure"
        }

        It "Should throw when Start-ZapScan fails" {
            { Invoke-ZapScan -ZapApiUrl "http://localhost:8080" -TargetUrl "http://test.com" } | Should -Throw "Simulated Start-ZapScan failure"
        }

        # Assert that Start-ZapScan was called once before the throw
        Assert-MockCalled Start-ZapScan -Times 1
    }

    Context "Invoke-ZapScan Function - Failure in ZAP API check" {
        # Mock Start-ZapScan to succeed
        Mock -CommandName Start-ZapScan -MockWith { return $true }

        # Mock Invoke-RestMethod for the version check to fail
        Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like "*/JSON/core/view/version/*" } -MockWith {
            throw "Simulated ZAP API check failure"
        }

        It "Should throw when ZAP API check fails after successful Start-ZapScan" {
            # Invoke-ZapScan and assert that it throws an exception
            { Invoke-ZapScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "testapikey" -TargetUrl "http://test.com" } | Should -Throw "Simulated ZAP API check failure"
        }

        # Assert that Start-ZapScan and the failing API check were called
        Assert-MockCalled Start-ZapScan -Times 1
        Assert-MockCalled Invoke-RestMethod -ParameterFilter { $Uri -like "*/JSON/core/view/version/*" } -Times 1
    }

    Context "Invoke-ZapScan Function - Failure in Start-ZapSpiderScan" {
        # Mock previous steps to succeed
        Mock -CommandName Start-ZapScan -MockWith { return $true }
        # Mock Invoke-RestMethod for the version check to succeed
        Mock -CommandName Invoke-RestMethod -ParameterFilter { $Uri -like "*/JSON/core/view/version/*" } -MockWith { return @{ version = "2.14.0" } }

        # Mock Start-ZapSpiderScan to fail
        Mock -CommandName Start-ZapSpiderScan -MockWith {
            throw "Simulated Start-ZapSpiderScan failure"
        }

        It "Should throw when Start-ZapSpiderScan fails" {
            # Invoke-ZapScan and assert that it throws an exception
            { Invoke-ZapScan -ZapApiUrl "http://localhost:8080" -ZapApiKey "testapikey" -TargetUrl "http://test.com" } | Should -Throw "Simulated Start-ZapSpiderScan failure"
        }

        # Assert that the necessary functions were called before the failure
        Assert-MockCalled Start-ZapScan -Times 1
        Assert-MockCalled Invoke-RestMethod -ParameterFilter { $Uri -like "*/JSON/core/view/version/*" } -Times 1
        Assert-MockCalled Start-ZapSpiderScan -Times 1
    }

    Context 'Invoke-ZapScan Function' {
        It 'Should perform a full scan cycle on success' {
            # Arrange
            $zapPath = "C:\path\to\zap.bat"
            $apiUrl = "http://localhost:8080"
            $apiKey = "testapikey"
            $targetUrl = "http://test.com"
            $reportPath = "C:\reports\report.html"
            $reportFormat = "html"
            $spiderScanId = "spider123"
            $activeScanId = "ascan456"
            $mockAlerts = @(
                @{ Risk = 'High'; Name = 'Test Alert'; Url = 'http://test.com' }
            )

            # Mock all internal function calls
            Mock Start-ZapScan { Write-Output "Start-ZapScan Called" } # Simulate call
            Mock Stop-ZapScan { Write-Output "Stop-ZapScan Called" } # Simulate call
            # Mock Invoke-RestMethod for the version check
            Mock Invoke-RestMethod {
                Param($Uri, $Method, $Headers, $TimeoutSec)
                 if ($Uri -like "*/JSON/core/view/version/*") {
                    return [PSCustomObject]@{ version = "ZAP 2.11.1" } # Simulate successful API check
                 } elseif ($Uri -like "*/JSON/spider/action/scan/*") {
                     return [PSCustomObject]@{ scan = $spiderScanId }
                 } elseif ($Uri -like "*/JSON/spider/view/status/*") {
                     # Simulate spider scan completion after one poll
                     $Script:SpiderStatusCallCount = ($Script:SpiderStatusCallCount + 1) % 2 # Toggle 0 and 1
                     if ($Script:SpiderStatusCallCount -eq 1) { return [PSCustomObject]@{ status = "50" } } else { return [PSCustomObject]@{ status = "100" } }
                 } elseif ($Uri -like "*/JSON/ascan/action/scan/*") {
                     return [PSCustomObject]@{ scan = $activeScanId }
                 } elseif ($Uri -like "*/JSON/ascan/view/status/*") {
                      # Simulate ascan completion after one poll
                     $Script:AscanStatusCallCount = ($Script:AscanStatusCallCount + 1) % 2 # Toggle 0 and 1
                     if ($Script:AscanStatusCallCount -eq 1) { return [PSCustomObject]@{ status = "75" } } else { return [PSCustomObject]@{ status = "100" } }
                 } elseif ($Uri -like "*/JSON/core/view/alerts/*") {
                     return [PSCustomObject]@{ alerts = $mockAlerts }
                 } elseif ($Uri -like "*/JSON/core/action/generate/*") {
                     # Simulate successful report generation
                     return $null
                 } elseif ($Uri -like "*/JSON/core/action/shutdown/*") {
                     # Simulate successful shutdown
                     return $null
                 }
                 throw "Unexpected API call: $Uri"
            }
            # Mock functions called internally by Invoke-ZapScan steps
            Mock Start-ZapSpiderScan { Param($ZapApiUrl, $ZapApiKey, $TargetUrl); return $spiderScanId }
            Mock Wait-ZapSpiderScanComplete { Param($ZapApiUrl, $ZapApiKey, $ScanId, $DelaySeconds, $TimeoutSeconds); $ScanId | Should -Be $spiderScanId; return $true }
            Mock Start-ZapActiveScan { Param($ZapApiUrl, $ZapApiKey, $TargetUrl, $ContextId); $TargetUrl | Should -Be $targetUrl; return $activeScanId }
            Mock Wait-ZapActiveScanComplete { Param($ZapApiUrl, $ZapApiKey, $ScanId, $DelaySeconds, $TimeoutSeconds); $ScanId | Should -Be $activeScanId; return $true }
            Mock Get-ZapAlerts { Param($ZapApiUrl, $ZapApiKey); return $mockAlerts }
            Mock Generate-ZapReport { Param($ZapApiUrl, $ZapApiKey, $ReportPath, $ReportFormat); $ReportPath | Should -Be $reportPath; $ReportFormat | Should -Be $reportFormat; return $true }
            Mock Write-LogMessage
            Mock Start-Sleep {}

            # Initialize call count variables for polling mocks
            $Script:SpiderStatusCallCount = 0
            $Script:AscanStatusCallCount = 0

            # Act
            $result = Invoke-ZapScan -PathToZap $zapPath -ZapApiUrl $apiUrl -ZapApiKey $apiKey -TargetUrl $targetUrl -ReportPath $reportPath -ReportFormat $reportFormat -SpiderDelaySeconds 1 -SpiderTimeoutSeconds 10 -ActiveScanDelaySeconds 1 -ActiveScanTimeoutSeconds 10

            # Assert
            # Verify function call order and parameters
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Message -eq "Запуск полного цикла ZAP сканирования для '$targetUrl'..." }
            Assert-MockCalled Start-ZapScan -Exactly 1 -ParameterFilter { PathToZap -eq $zapPath; ApiPort -eq 8080 }
            Assert-MockCalled Start-Sleep -Exactly 1 -ParameterFilter { Seconds -eq 10 }
            Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter { Uri -eq "$apiUrl/JSON/core/view/version/" -and Headers['X-ZAP-API-Key'] -eq $apiKey } -After (Assert-MockCalled Start-Sleep)
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Message -eq "ZAP API доступен." } -After (Assert-MockCalled Invoke-RestMethod -ParameterFilter { Uri -like "$apiUrl/JSON/core/view/version/*" })
            Assert-MockCalled Start-ZapSpiderScan -Exactly 1 -ParameterFilter { ZapApiUrl -eq $apiUrl; ZapApiKey -eq $apiKey; TargetUrl -eq $targetUrl } -After (Assert-MockCalled Invoke-RestMethod -ParameterFilter { Uri -like "$apiUrl/JSON/core/view/version/*" })
            Assert-MockCalled Wait-ZapSpiderScanComplete -Exactly 1 -ParameterFilter { ScanId -eq $spiderScanId; DelaySeconds -eq 1; TimeoutSeconds -eq 10 } -After (Assert-MockCalled Start-ZapSpiderScan)
            Assert-MockCalled Start-ZapActiveScan -Exactly 1 -ParameterFilter { ZapApiUrl -eq $apiUrl; ZapApiKey -eq $apiKey; TargetUrl -eq $targetUrl } -After (Assert-MockCalled Wait-ZapSpiderScanComplete)
            Assert-MockCalled Wait-ZapActiveScanComplete -Exactly 1 -ParameterFilter { ScanId -eq $activeScanId; DelaySeconds -eq 1; TimeoutSeconds -eq 10 } -After (Assert-MockCalled Start-ZapActiveScan)
            Assert-MockCalled Get-ZapAlerts -Exactly 1 -ParameterFilter { ZapApiUrl -eq $apiUrl; ZapApiKey -eq $apiKey } -After (Assert-MockCalled Wait-ZapActiveScanComplete)
            Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Получено $($mockAlerts.Count) уязвимостей." } -After (Assert-MockCalled Get-ZapAlerts)
            Assert-MockCalled Generate-ZapReport -Exactly 1 -ParameterFilter { ZapApiUrl -eq $apiUrl; ZapApiKey -eq $apiKey; ReportPath -eq $reportPath; ReportFormat -eq $reportFormat } -After (Assert-MockCalled Get-ZapAlerts)
             Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Level -eq 'INFO'; Message -eq "Отчет успешно сгенерирован в '$reportPath'." } -After (Assert-MockCalled Generate-ZapReport)
            Assert-MockCalled Stop-ZapScan -Exactly 1 -ParameterFilter { ZapApiUrl -eq $apiUrl; ZapApiKey -eq $apiKey } -After (Assert-MockCalled Generate-ZapReport)
             Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter { Message -eq "Полный цикл ZAP сканирования завершен." } -After (Assert-MockCalled Stop-ZapScan)


            # Verify return value
            $result | Should -BeTrue

             # Clean up script variables used for mock state
            Remove-Variable -Name SpiderStatusCallCount -Scope Script
            Remove-Variable -Name AscanStatusCallCount -Scope Script
        }

        # TODO: Add tests for failure scenarios at each step:
        # It 'Should return false and stop if Start-ZapScan fails' { ... }
        # It 'Should return false and stop if ZAP API check fails' { ... }
        # It 'Should return false and stop if Start-ZapSpiderScan fails' { ... }
        # It 'Should return false and stop if Wait-ZapSpiderScanComplete fails' { ... }
        # It 'Should return false and stop if Start-ZapActiveScan fails' { ... }
        # It 'Should return false and stop if Wait-ZapActiveScanComplete fails' { ... }
        # It 'Should log warning but continue if Get-ZapAlerts fails or finds nothing' { ... }
        # It 'Should log error but continue if Generate-ZapReport fails' { ... }
    }

    It "should return $false, log an error, and stop ZAP if Wait-ZapActiveScanComplete fails" {
        # Arrange
        $MockStartZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockTestPath = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockInvokeRestMethodApiCheck = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapSpiderScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapSpiderScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapActiveScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapActiveScanCompleteFunc = New-MockObject -Type System.Management.Automation.ProxyCommand # Renamed to avoid conflict with the context name
        $MockStopZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWriteLogMessage = New-MockObject -Type System.Management.Automation.ProxyCommand

        Mock Start-ZapScan -MockWith $MockStartZapScan -Verifiable
        Mock Test-Path -MockWith $MockTestPath -Verifiable
        Mock Invoke-RestMethod -MockWith $MockInvokeRestMethodApiCheck -Verifiable -ParameterFilter {$uri -like "*/core/view/version/"}
        Mock Start-ZapSpiderScan -MockWith $MockStartZapSpiderScan -Verifiable
        Mock Wait-ZapSpiderScanComplete -MockWith $MockWaitZapSpiderScanComplete -Verifiable
        Mock Start-ZapActiveScan -MockWith $MockStartZapActiveScan -Verifiable
        Mock Wait-ZapActiveScanComplete -MockWith $MockWaitZapActiveScanCompleteFunc -Verifiable
        Mock Stop-ZapScan -MockWith $MockStopZapScan -Verifiable
        Mock Write-LogMessage -MockWith $MockWriteLogMessage -Verifiable

        $ZapPath = "C:\path\to\zap.exe"
        $TargetUrl = "http://test.com"
        $ZapApiUrl = "http://localhost:8080"

        $MockStartZapScan.MockResult = $true # Assume ZAP starts successfully
        $MockTestPath.MockResult = $true # Assume ZAP executable exists
        $MockInvokeRestMethodApiCheck.MockResult = @{ version = "2.11.1" } # Assume API is available
        $MockStartZapSpiderScan.MockResult = 1 # Assume spider scan starts successfully, returning scan ID 1
        $MockWaitZapSpiderScanComplete.MockResult = $true # Assume spider scan completes successfully
        $MockStartZapActiveScan.MockResult = 2 # Assume active scan starts successfully, returning scan ID 2
        $MockWaitZapActiveScanCompleteFunc.MockResult = $false # Simulate active scan failure

        # Act
        $result = Invoke-ZapScan -ZapPath $ZapPath -TargetUrl $TargetUrl -ZapApiUrl $ZapApiUrl

        # Assert
        $result | ShouldBe $false

        Assert-MockCalled Start-ZapScan -Exactly 1 -ParameterFilter {$PathToZap -eq $ZapPath}
        Assert-MockCalled Test-Path -Exactly 1 -ParameterFilter {$Path -eq $ZapPath}
        Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {$uri -like "*/core/view/version/"}
        Assert-MockCalled Start-ZapSpiderScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapSpiderScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Start-ZapActiveScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapActiveScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Stop-ZapScan -Exactly 1
        Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter {$Message -like "*Active scan failed or timed out*" -and $Level -eq "Error"}
    }

    It "should return $false, log an error, and stop ZAP if Start-ZapActiveScan fails" {
        # Arrange
        $MockStartZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockTestPath = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockInvokeRestMethodApiCheck = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapSpiderScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapSpiderScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapActiveScanFunc = New-MockObject -Type System.Management.Automation.ProxyCommand # Renamed to avoid conflict
        $MockStopZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWriteLogMessage = New-MockObject -Type System.Management.Automation.ProxyCommand

        Mock Start-ZapScan -MockWith $MockStartZapScan -Verifiable
        Mock Test-Path -MockWith $MockTestPath -Verifiable
        Mock Invoke-RestMethod -MockWith $MockInvokeRestMethodApiCheck -Verifiable -ParameterFilter {$uri -like "*/core/view/version/"}
        Mock Start-ZapSpiderScan -MockWith $MockStartZapSpiderScan -Verifiable
        Mock Wait-ZapSpiderScanComplete -MockWith $MockWaitZapSpiderScanComplete -Verifiable
        Mock Start-ZapActiveScan -MockWith $MockStartZapActiveScanFunc -Verifiable
        Mock Stop-ZapScan -MockWith $MockStopZapScan -Verifiable
        Mock Write-LogMessage -MockWith $MockWriteLogMessage -Verifiable

        $ZapPath = "C:\path\to\zap.exe"
        $TargetUrl = "http://test.com"
        $ZapApiUrl = "http://localhost:8080"

        $MockStartZapScan.MockResult = $true # Assume ZAP starts successfully
        $MockTestPath.MockResult = $true # Assume ZAP executable exists
        $MockInvokeRestMethodApiCheck.MockResult = @{ version = "2.11.1" } # Assume API is available
        $MockStartZapSpiderScan.MockResult = 1 # Assume spider scan starts successfully, returning scan ID 1
        $MockWaitZapSpiderScanComplete.MockResult = $true # Assume spider scan completes successfully
        $MockStartZapActiveScanFunc.MockResult = $null # Simulate active scan failure

        # Act
        $result = Invoke-ZapScan -ZapPath $ZapPath -TargetUrl $TargetUrl -ZapApiUrl $ZapApiUrl

        # Assert
        $result | ShouldBe $false

        Assert-MockCalled Start-ZapScan -Exactly 1 -ParameterFilter {$PathToZap -eq $ZapPath}
        Assert-MockCalled Test-Path -Exactly 1 -ParameterFilter {$Path -eq $ZapPath}
        Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {$uri -like "*/core/view/version/"}
        Assert-MockCalled Start-ZapSpiderScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapSpiderScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Start-ZapActiveScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Stop-ZapScan -Exactly 1
        Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter {$Message -like "*Failed to start Active Scan*" -and $Level -eq "Error"}
        # Ensure Wait-ZapActiveScanComplete, Get-ZapAlerts, Generate-ZapReport were not called after Start-ZapActiveScan failed
        Assert-MockCalled Wait-ZapActiveScanComplete -Times 0
        Assert-MockCalled Get-ZapAlerts -Times 0
        Assert-MockCalled Generate-ZapReport -Times 0
    }

    It "should return $false, log an error, and stop ZAP if Get-ZapAlerts fails" {
        # Arrange
        $MockStartZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockTestPath = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockInvokeRestMethodApiCheck = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapSpiderScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapSpiderScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapActiveScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapActiveScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockGetZapAlertsFunc = New-MockObject -Type System.Management.Automation.ProxyCommand # Renamed to avoid conflict
        $MockGenerateZapReport = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStopZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWriteLogMessage = New-MockObject -Type System.Management.Automation.ProxyCommand

        Mock Start-ZapScan -MockWith $MockStartZapScan -Verifiable
        Mock Test-Path -MockWith $MockTestPath -Verifiable
        Mock Invoke-RestMethod -MockWith $MockInvokeRestMethodApiCheck -Verifiable -ParameterFilter {$uri -like "*/core/view/version/"}
        Mock Start-ZapSpiderScan -MockWith $MockStartZapSpiderScan -Verifiable
        Mock Wait-ZapSpiderScanComplete -MockWith $MockWaitZapSpiderScanComplete -Verifiable
        Mock Start-ZapActiveScan -MockWith $MockStartZapActiveScan -Verifiable
        Mock Wait-ZapActiveScanComplete -MockWith $MockWaitZapActiveScanComplete -Verifiable
        Mock Get-ZapAlerts -MockWith $MockGetZapAlertsFunc -Verifiable
        Mock Generate-ZapReport -MockWith $MockGenerateZapReport -Verifiable
        Mock Stop-ZapScan -MockWith $MockStopZapScan -Verifiable
        Mock Write-LogMessage -MockWith $MockWriteLogMessage -Verifiable

        $ZapPath = "C:\path\to\zap.exe"
        $TargetUrl = "http://test.com"
        $ZapApiUrl = "http://localhost:8080"
        $ReportPath = "C:\reports\report.html"
        $ReportFormat = "html"

        $MockStartZapScan.MockResult = $true # Assume ZAP starts successfully
        $MockTestPath.MockResult = $true # Assume ZAP executable exists
        $MockInvokeRestMethodApiCheck.MockResult = @{ version = "2.11.1" } # Assume API is available
        $MockStartZapSpiderScan.MockResult = 1 # Assume spider scan starts successfully
        $MockWaitZapSpiderScanComplete.MockResult = $true # Assume spider scan completes successfully
        $MockStartZapActiveScan.MockResult = 2 # Assume active scan starts successfully
        $MockWaitZapActiveScanComplete.MockResult = $true # Assume active scan completes successfully
        $MockGetZapAlertsFunc.MockResult = $null # Simulate failure to get alerts

        # Act
        $result = Invoke-ZapScan -ZapPath $ZapPath -TargetUrl $TargetUrl -ZapApiUrl $ZapApiUrl -ReportPath $ReportPath -ReportFormat $ReportFormat

        # Assert
        # The function should still attempt to generate a report and stop ZAP, but the overall result should indicate failure due to missing alerts
        $result | ShouldBe $false

        Assert-MockCalled Start-ZapScan -Exactly 1 -ParameterFilter {$PathToZap -eq $ZapPath}
        Assert-MockCalled Test-Path -Exactly 1 -ParameterFilter {$Path -eq $ZapPath}
        Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {$uri -like "*/core/view/version/"}
        Assert-MockCalled Start-ZapSpiderScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapSpiderScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Start-ZapActiveScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapActiveScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Get-ZapAlerts -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        # Should log an error for failing to get alerts, but continue
        Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter {$Message -like "*Failed to retrieve alerts*" -and $Level -eq "Error"}
        # Report generation and Stop-ZapScan should still be called
        Assert-MockCalled Generate-ZapReport -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl -and $ReportPath -eq $ReportPath -and $ReportFormat -eq $ReportFormat}
        Assert-MockCalled Stop-ZapScan -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
    }

    It "should return $false, log an error, and continue if Get-ZapAlerts fails" {
        # Arrange
        $MockStartZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockTestPath = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockInvokeRestMethodApiCheck = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapSpiderScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapSpiderScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapActiveScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapActiveScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockGetZapAlertsFunc = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockGenerateZapReport = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStopZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWriteLogMessage = New-MockObject -Type System.Management.Automation.ProxyCommand

        Mock Start-ZapScan -MockWith $MockStartZapScan -Verifiable
        Mock Test-Path -MockWith $MockTestPath -Verifiable
        Mock Invoke-RestMethod -MockWith $MockInvokeRestMethodApiCheck -Verifiable -ParameterFilter {$uri -like "*/core/view/version/"}
        Mock Start-ZapSpiderScan -MockWith $MockStartZapSpiderScan -Verifiable
        Mock Wait-ZapSpiderScanComplete -MockWith $MockWaitZapSpiderScanComplete -Verifiable
        Mock Start-ZapActiveScan -MockWith $MockStartZapActiveScan -Verifiable
        Mock Wait-ZapActiveScanComplete -MockWith $MockWaitZapActiveScanComplete -Verifiable
        Mock Get-ZapAlerts -MockWith $MockGetZapAlertsFunc -Verifiable
        Mock Generate-ZapReport -MockWith $MockGenerateZapReport -Verifiable
        Mock Stop-ZapScan -MockWith $MockStopZapScan -Verifiable
        Mock Write-LogMessage -MockWith $MockWriteLogMessage -Verifiable

        $ZapPath = "C:\path\to\zap.exe"
        $TargetUrl = "http://test.com"
        $ZapApiUrl = "http://localhost:8080"
        $ReportPath = "C:\reports\report.html"
        $ReportFormat = "html"

        $MockStartZapScan.MockResult = $true # Assume ZAP starts successfully
        $MockTestPath.MockResult = $true # Assume ZAP executable exists
        $MockInvokeRestMethodApiCheck.MockResult = @{ version = "2.11.1" } # Assume API is available
        $MockStartZapSpiderScan.MockResult = 1 # Assume spider scan starts successfully
        $MockWaitZapSpiderScanComplete.MockResult = $true # Assume spider scan completes successfully
        $MockStartZapActiveScan.MockResult = 2 # Assume active scan starts successfully
        $MockWaitZapActiveScanComplete.MockResult = $true # Assume active scan completes successfully
        $MockGetZapAlertsFunc.MockResult = $null # Simulate failure to get alerts

        # Act
        $result = Invoke-ZapScan -ZapPath $ZapPath -TargetUrl $TargetUrl -ZapApiUrl $ZapApiUrl -ReportPath $ReportPath -ReportFormat $ReportFormat

        # Assert
        # The function should still attempt to generate a report and stop ZAP, but the overall result should indicate failure due to missing alerts
        $result | ShouldBe $false

        Assert-MockCalled Start-ZapScan -Exactly 1 -ParameterFilter {$PathToZap -eq $ZapPath}
        Assert-MockCalled Test-Path -Exactly 1 -ParameterFilter {$Path -eq $ZapPath}
        Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {$uri -like "*/core/view/version/"}
        Assert-MockCalled Start-ZapSpiderScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapSpiderScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Start-ZapActiveScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapActiveScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Get-ZapAlerts -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        # Should log an error for failing to get alerts, but continue
        Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter {$Message -like "*Failed to retrieve alerts*" -and $Level -eq "Error"}
        # Report generation and Stop-ZapScan should still be called
        Assert-MockCalled Generate-ZapReport -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl -and $ReportPath -eq $ReportPath -and $ReportFormat -eq $ReportFormat}
        Assert-MockCalled Stop-ZapScan -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
    }

    It "should log info but continue if Get-ZapAlerts returns an empty array" {
        # Arrange
        $MockStartZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockTestPath = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockInvokeRestMethodApiCheck = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapSpiderScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapSpiderScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapActiveScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapActiveScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockGetZapAlertsFunc = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockGenerateZapReport = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStopZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWriteLogMessage = New-MockObject -Type System.Management.Automation.ProxyCommand

        Mock Start-ZapScan -MockWith $MockStartZapScan -Verifiable
        Mock Test-Path -MockWith $MockTestPath -Verifiable
        Mock Invoke-RestMethod -MockWith $MockInvokeRestMethodApiCheck -Verifiable -ParameterFilter {$uri -like "*/core/view/version/"}
        Mock Start-ZapSpiderScan -MockWith $MockStartZapSpiderScan -Verifiable
        Mock Wait-ZapSpiderScanComplete -MockWith $MockWaitZapSpiderScanComplete -Verifiable
        Mock Start-ZapActiveScan -MockWith $MockStartZapActiveScan -Verifiable
        Mock Wait-ZapActiveScanComplete -MockWith $MockWaitZapActiveScanComplete -Verifiable
        Mock Get-ZapAlerts -MockWith $MockGetZapAlertsFunc -Verifiable
        Mock Generate-ZapReport -MockWith $MockGenerateZapReport -Verifiable
        Mock Stop-ZapScan -MockWith $MockStopZapScan -Verifiable
        Mock Write-LogMessage -MockWith $MockWriteLogMessage -Verifiable

        $ZapPath = "C:\path\to\zap.exe"
        $TargetUrl = "http://test.com"
        $ZapApiUrl = "http://localhost:8080"
        $ReportPath = "C:\reports\report.html"
        $ReportFormat = "html"

        $MockStartZapScan.MockResult = $true
        $MockTestPath.MockResult = $true
        $MockInvokeRestMethodApiCheck.MockResult = @{ version = "2.11.1" }
        $MockStartZapSpiderScan.MockResult = 1
        $MockWaitZapSpiderScanComplete.MockResult = $true
        $MockStartZapActiveScan.MockResult = 2
        $MockWaitZapActiveScanComplete.MockResult = $true
        $MockGetZapAlertsFunc.MockResult = @() # Simulate empty alerts array

        # Act
        $result = Invoke-ZapScan -ZapPath $ZapPath -TargetUrl $TargetUrl -ZapApiUrl $ZapApiUrl -ReportPath $ReportPath -ReportFormat $ReportFormat

        # Assert
        # The function should log info about 0 alerts and continue, potentially returning true if report generation and stop succeed.
        # However, since the overall goal is security scanning and no alerts were found (even if gracefully handled), returning $false might be more appropriate to signal the scan didn't find anything or failed to retrieve findings.
        # Let's assume returning $false is the desired behavior for this scenario too.
        $result | ShouldBe $false

        Assert-MockCalled Start-ZapScan -Exactly 1 -ParameterFilter {$PathToZap -eq $ZapPath}
        Assert-MockCalled Test-Path -Exactly 1 -ParameterFilter {$Path -eq $ZapPath}
        Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {$uri -like "*/core/view/version/"}
        Assert-MockCalled Start-ZapSpiderScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapSpiderScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Start-ZapActiveScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapActiveScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Get-ZapAlerts -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        # Should log info about finding 0 alerts
        Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter {$Message -like "*Получено 0 уязвимостей*" -and $Level -eq "Info"}
        # Report generation and Stop-ZapScan should still be called
        Assert-MockCalled Generate-ZapReport -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl -and $ReportPath -eq $ReportPath -and $ReportFormat -eq $ReportFormat}
        Assert-MockCalled Stop-ZapScan -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
    }

    It "should return $false, log an error, and stop ZAP if Generate-ZapReport fails" {
        # Arrange
        $MockStartZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockTestPath = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockInvokeRestMethodApiCheck = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapSpiderScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapSpiderScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockStartZapActiveScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWaitZapActiveScanComplete = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockGetZapAlerts = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockGenerateZapReportFunc = New-MockObject -Type System.Management.Automation.ProxyCommand # Renamed to avoid conflict
        $MockStopZapScan = New-MockObject -Type System.Management.Automation.ProxyCommand
        $MockWriteLogMessage = New-MockObject -Type System.Management.Automation.ProxyCommand

        Mock Start-ZapScan -MockWith $MockStartZapScan -Verifiable
        Mock Test-Path -MockWith $MockTestPath -Verifiable
        Mock Invoke-RestMethod -MockWith $MockInvokeRestMethodApiCheck -Verifiable -ParameterFilter {$uri -like "*/core/view/version/"}
        Mock Start-ZapSpiderScan -MockWith $MockStartZapSpiderScan -Verifiable
        Mock Wait-ZapSpiderScanComplete -MockWith $MockWaitZapSpiderScanComplete -Verifiable
        Mock Start-ZapActiveScan -MockWith $MockStartZapActiveScan -Verifiable
        Mock Wait-ZapActiveScanComplete -MockWith $MockWaitZapActiveScanComplete -Verifiable
        Mock Get-ZapAlerts -MockWith $MockGetZapAlerts -Verifiable
        Mock Generate-ZapReport -MockWith $MockGenerateZapReportFunc -Verifiable
        Mock Stop-ZapScan -MockWith $MockStopZapScan -Verifiable
        Mock Write-LogMessage -MockWith $MockWriteLogMessage -Verifiable

        $ZapPath = "C:\path\to\zap.exe"
        $TargetUrl = "http://test.com"
        $ZapApiUrl = "http://localhost:8080"
        $ReportPath = "C:\reports\report.html"
        $ReportFormat = "html"
        $mockAlerts = @({ Risk = 'High'; Name = 'Test Alert'; Url = 'http://test.com' })

        $MockStartZapScan.MockResult = $true # Assume ZAP starts successfully
        $MockTestPath.MockResult = $true # Assume ZAP executable exists
        $MockInvokeRestMethodApiCheck.MockResult = @{ version = "2.11.1" } # Assume API is available
        $MockStartZapSpiderScan.MockResult = 1 # Assume spider scan starts successfully
        $MockWaitZapSpiderScanComplete.MockResult = $true # Assume spider scan completes successfully
        $MockStartZapActiveScan.MockResult = 2 # Assume active scan starts successfully
        $MockWaitZapActiveScanComplete.MockResult = $true # Assume active scan completes successfully
        $MockGetZapAlerts.MockResult = $mockAlerts # Assume alerts are retrieved successfully
        $MockGenerateZapReportFunc.MockResult = $false # Simulate report generation failure

        # Act
        $result = Invoke-ZapScan -ZapPath $ZapPath -TargetUrl $TargetUrl -ZapApiUrl $ZapApiUrl -ReportPath $ReportPath -ReportFormat $ReportFormat

        # Assert
        # The function should log an error for report generation but still attempt to stop ZAP. The overall result should indicate failure.
        $result | ShouldBe $false

        Assert-MockCalled Start-ZapScan -Exactly 1 -ParameterFilter {$PathToZap -eq $ZapPath}
        Assert-MockCalled Test-Path -Exactly 1 -ParameterFilter {$Path -eq $ZapPath}
        Assert-MockCalled Invoke-RestMethod -Exactly 1 -ParameterFilter {$uri -like "*/core/view/version/"}
        Assert-MockCalled Start-ZapSpiderScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapSpiderScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Start-ZapActiveScan -Exactly 1 -ParameterFilter {$TargetUrl -eq $TargetUrl -and $ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Wait-ZapActiveScanComplete -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Get-ZapAlerts -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
        Assert-MockCalled Generate-ZapReport -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl -and $ReportPath -eq $ReportPath -and $ReportFormat -eq $ReportFormat}
        # Should log an error for report generation failure
        Assert-MockCalled Write-LogMessage -Exactly 1 -ParameterFilter {$Message -like "*Failed to generate report*" -and $Level -eq "Error"}
        # Stop-ZapScan should still be called
        Assert-MockCalled Stop-ZapScan -Exactly 1 -ParameterFilter {$ZapApiUrl -eq $ZapApiUrl}
    }
} 