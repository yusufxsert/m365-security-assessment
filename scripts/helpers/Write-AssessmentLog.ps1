#Requires -Version 7.0

<#
.SYNOPSIS
    Writes a color-coded log message to the console and optionally to a file.

.DESCRIPTION
    Provides consistent, timestamped logging for the assessment framework.
    Console output is color-coded by severity level. File logging is thread-safe
    via a named mutex, making it safe for use inside ForEach-Object -Parallel blocks.

.PARAMETER Message
    The log message to write.

.PARAMETER Level
    Log level: INFO, WARN, ERROR, DEBUG, or SUCCESS.
    Defaults to INFO.

.PARAMETER LogPath
    Optional. If provided, the message is also appended to this file.

.EXAMPLE
    Write-AssessmentLog -Message "Starting identity checks" -Level INFO

.EXAMPLE
    Write-AssessmentLog -Message "CA policy gap detected" -Level WARN -LogPath C:\Reports\assessment.log

.EXAMPLE
    Write-AssessmentLog -Message "Connection failed" -Level ERROR
#>
function Write-AssessmentLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG', 'SUCCESS')]
        [string]$Level = 'INFO',

        [string]$LogPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix    = "[$timestamp]"

    $colorMap = @{
        INFO    = 'Cyan'
        WARN    = 'Yellow'
        ERROR   = 'Red'
        DEBUG   = 'Gray'
        SUCCESS = 'Green'
    }

    $levelPad  = $Level.PadRight(7)   # aligns columns: "SUCCESS" is longest at 7 chars
    $consoleLine = "$prefix $levelPad $Message"
    Write-Host $consoleLine -ForegroundColor $colorMap[$Level]

    if ($LogPath) {
        $fileLine = "$prefix [$Level] $Message"

        # Named mutex ensures only one thread writes at a time (safe for -Parallel)
        $mutexName = 'Global\M365AssessmentLogMutex'
        $mutex     = $null
        try {
            $mutex = [System.Threading.Mutex]::new($false, $mutexName)
            $acquired = $mutex.WaitOne(5000)   # 5-second timeout
            try {
                Add-Content -Path $LogPath -Value $fileLine -Encoding UTF8 -ErrorAction Stop
            }
            finally {
                if ($acquired) { $mutex.ReleaseMutex() }
            }
        }
        catch [System.IO.IOException] {
            # File write failure is non-fatal; console message already written
            Write-Host "[$timestamp] [WARN]   Log file write failed: $_" -ForegroundColor Yellow
        }
        catch {
            Write-Host "[$timestamp] [WARN]   Log mutex error: $_" -ForegroundColor Yellow
        }
        finally {
            if ($mutex) { $mutex.Dispose() }
        }
    }
}
