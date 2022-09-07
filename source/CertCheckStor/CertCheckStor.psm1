<#
#>

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

########
# Script Vars
$script:SessionId = [Guid]::NewGuid()
$script:SessionName = ""

<#
#>
Function New-NormalisedUri
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $UriObj,

        [Parameter(Mandatory=$false)]
        [switch]$AsString = $false
    )

    process
    {
        # If it's not a URI, attempt to convert to Uri directly
        $uri = $UriObj
        if ($uri.GetType().FullName -ne "System.Uri")
        {
            try {
                $uri = [Uri]::New($uri)
            } catch {
                # Could not convert to Uri directly
            }
        }

        # If it's still not a URI, attempt to convert to Uri with a https:// prefix
        if ($uri.GetType().FullName -ne "System.Uri")
        {
            try {
                $uri = [Uri]::New("https://" + $uri)
            } catch {
                # Could not convert with https:// prefix
            }
        }

        # If it's still not a URI, then fail the normalisation
        if ($uri.GetType().FullName -ne "System.Uri")
        {
            Write-Error ("Failed to convert object to uri directly or with https:// prefix: {0}" -f $uri)
        }

        # Ensure the URI is lowercase and the path is absent
        $tempUri = [Uri]::New($uri.AbsoluteUri.ToLower())
        $uri = [Uri]::New(("{0}://{1}:{2}" -f $tempUri.Scheme, $tempUri.Host, $tempUri.Port))

        # Pass the Uri on
        if ($AsString)
        {
            $uri.ToString()
        } else {
            $uri
        }
    }
}

<#
#>
Function Get-MemberValue
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Obj,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Property,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Default
    )

    process
    {
        if (($Obj | Get-Member).Name -contains $Property)
        {
            $Obj.$Property
        } elseif ($PSBoundParameters.Keys -contains "Default")
        {
            $Default
        } else {
            Write-Error "Property ($Property) not found and no default value"
        }
    }
}

<#
#>
Function Reset-CertCheckStorSessionId
{
    [CmdletBinding()]
    param()

    process
    {
        $script:SessionId = [Guid]::NewGuid()
    }
}

<#
#>
Function Get-CertCheckStorSessionId
{
    [CmdletBinding()]
    param()

    process
    {
        $script:SessionId
    }
}

<#
#>
Function Get-CertCheckStorSessionName
{
    [CmdletBinding()]
    param()

    process
    {
        $script:SessionName
    }
}

<#
#>
Function Set-CertCheckStorSessionName
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    process
    {
        $script:SessionName = $Name
    }
}

<#
#>
Function Add-CertCheckStorCertificate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Partition = "certificates",

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Subject,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Issuer,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [DateTime]$NotBefore,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [DateTime]$NotAfter
    )

    process
    {
        $tableArgs = @{
            Table = $Table
            PartitionKey = $Partition
            RowKey = $Thumbprint
            Property = @{
                Thumbprint = $Thumbprint
                Subject = $Subject
                Issuer = $Issuer
                NotBefore = $NotBefore.ToUniversalTime().ToString("o")
                NotAfter = $NotAfter.ToUniversalTime().ToString("o")
            }
            UpdateExisting = $true
        }

        # Update the object
        Add-AzTableRow @tableArgs | Out-Null
    }
}

<#
#>
Function Get-CertCheckStorCertificate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Partition = "certificates",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint = ""
    )

    process
    {
        $tableArgs = @{
            Table = $Table
            PartitionKey = $Partition
        }

        # Retrieve a particular entry, if specified
        if (![string]::IsNullOrEmpty($Thumbprint))
        {
            $tableArgs["RowKey"] = $Thumbprint
        }

        # Retrieve the object
        $result = Get-AzTableRow @tableArgs

        # Transform the object in to something deterministic
        $result | ForEach-Object {
            $obj = $_

            try {
                [PSCustomObject]@{
                    Thumbprint = $obj.Thumbprint
                    Subject = $obj.Subject
                    Issuer = $obj.Issuer
                    NotBefore = [DateTime]::Parse($obj.NotBefore).ToUniversalTime()
                    NotAfter = [DateTime]::Parse($obj.NotAfter).ToUniversalTime()
                    # TableTimestamp is a DateTimeOffset
                    Modified = $obj.TableTimestamp.DateTime.ToUniversalTime()
                }
            } catch {
                Write-Warning ("Could not transform data for entry: " + $_)
                Write-Warning ("Entry: " + ($obj | ConvertTo-Json))
            }
        }
    }
}

<#
#>
Function Add-CertCheckStorUsage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Table,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[0-9a-zA-Z_-]+$")]
        [string]$UsageType,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$UsedBy
    )

    process
    {
        # Generate an id from the thumbprint and usage information
        $rowKey = "{0}:{1}" -f $Thumbprint, $UsedBy
        $rowkey = [System.Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes($rowKey))

        # Make sure we have a valid session name set
        if ([string]::IsNullOrEmpty($script:SessionName))
        {
            Write-Error "SessionName not set"
        }

        # Generate parameters for Add-AzTableRow call
        $tableArgs = @{
            Table = $Table
            PartitionKey = $UsageType
            RowKey = $rowKey
            Property = @{
                Thumbprint = $Thumbprint
                UsedBy = $UsedBy
                Seen = ([DateTime]::UtcNow.ToString("o"))
                SessionId = $script:SessionId
                SessionName = $script:SessionName
            }
            UpdateExisting = $true
        }

        # Update the object
        Add-AzTableRow @tableArgs | Out-Null
    }
}

<#
#>
Function Get-CertCheckStorUsage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[0-9a-zA-Z_-]+$")]
        [string]$UsageType = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint = ""
    )

    process
    {
        $tableArgs = @{
            Table = $Table
        }

        # Retrieve a particular entry, if specified
        if (![string]::IsNullOrEmpty($UsageType))
        {
            $tableArgs["PartitionKey"] = $UsageType
        }

        # Retrieve the object
        $result = Get-AzTableRow @tableArgs

        # Transform the object in to something deterministic
        $result | ForEach-Object {
            $obj = $_

            try {
                [PSCustomObject]@{
                    Thumbprint = $obj.Thumbprint
                    UsageType = $obj.PartitionKey
                    UsedBy = $obj.UsedBy
                    Seen = [DateTime]::Parse($obj.Seen).ToUniversalTime()
                    SessionId = $obj.SessionId
                    SessionName = $obj.SessionName
                    # TableTimestamp is a DateTimeOffset
                    Modified = $obj.TableTimestamp.DateTime.ToUniversalTime()
                }
            } catch {
                Write-Warning ("Could not transform data for entry: " + $_)
                Write-Warning ("Entry: " + ($obj | ConvertTo-Json))
            }
        }
    }
}

<#
#>
Function Remove-CertCheckStorStaleUsage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Table
    )

    process
    {
        # Make sure we have a valid session name set
        if ([string]::IsNullOrEmpty($script:SessionName))
        {
            Write-Error "SessionName not set"
        }

        $tableArgs = @{
            Table = $Table
        }

        # Retrieve the objects
        $removeCount = 0
        $result = Get-AzTableRow @tableArgs | Where-Object {
            $_.SessionName -eq $script:SessionName -and $_.SessionId -ne $script:SessionId
        } | ForEach-Object { $removeCount++ } | Remove-AzTableRow
    }
}

<#
#>
Function Add-CertCheckStorEndpoint
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Table,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[0-9a-zA-Z_-]+$")]
        [string]$Perspective,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Uri]$Connection,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Sni,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Thumbprint = "",

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [bool]$Connected,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Addresses = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$LocallyTrusted = $false
    )

    process
    {
        # Generate an id from the thumbprint and usage information
        $rowKey = "{0}:{1}" -f $Connection, $Sni
        $rowkey = [System.Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes($rowKey))

        # Generate parameters for Add-AzTableRow call
        $tableArgs = @{
            Table = $Table
            PartitionKey = $Perspective
            RowKey = $rowKey
            Property = @{
                Connection = (New-NormalisedUri $Connection).AbsoluteUri
                Sni = $Sni
                Thumbprint = $Thumbprint
                Connected = $Connected
                Addresses = $Addresses
                LocallyTrusted = $LocallyTrusted
            }
            UpdateExisting = $true
        }

        # Update the object
        Add-AzTableRow @tableArgs | Out-Null
    }
}

<#
#>
Function Get-CertCheckStorEndpoint
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[0-9a-zA-Z_-]+$")]
        [string]$Perspective
    )

    process
    {
        $tableArgs = @{
            Table = $Table
        }

        # Retrieve a particular entry, if specified
        if (![string]::IsNullOrEmpty($Perspective))
        {
            $tableArgs["PartitionKey"] = $Perspective
        }

        # Retrieve the object
        $result = Get-AzTableRow @tableArgs

        # Transform the object in to something deterministic
        $result | ForEach-Object {
            $obj = $_

            try {
                $connection = Get-MemberValue -Obj $obj -Property Connection -Default ""

                # Check for no content in 'Connection' and try 'Uri' instead
                if ([string]::IsNullOrEmpty($connection))
                {
                    $connection = Get-MemberValue -Obj $obj -Property Uri -Default ""
                }

                # Check if we had any success with the connection
                if ([string]::IsNullOrEmpty($connection))
                {
                    Write-Error "Connection info could not be found"
                }

                $connectionUri = [Uri]::New($connection)

                [PSCustomObject]@{
                    Connection = $connectionUri
                    Sni = (Get-MemberValue -Obj $obj -Property Sni -Default $connectionUri.Host)
                    Thumbprint = (Get-MemberValue -Obj $obj -Property Thumbprint -Default "")
                    Perspective = $obj.PartitionKey
                    Connected = [bool](Get-MemberValue -Obj $obj -Property Connected -Default $false)
                    Addresses = [string](Get-MemberValue -Obj $obj -Property Addresses -Default "")
                    LocallyTrusted = [bool](Get-MemberValue -Obj $obj -Property LocallyTrusted -Default $false)
                    # TableTimestamp is a DateTimeOffset
                    Modified = $obj.TableTimestamp.DateTime.ToUniversalTime()
                }
            } catch {
                Write-Warning ("Could not transform data for entry: " + $_)
                Write-Warning ("Entry: " + ($obj | ConvertTo-Json))
            }
        }
    }
}
