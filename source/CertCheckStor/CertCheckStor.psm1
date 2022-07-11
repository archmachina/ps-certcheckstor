<#
#>

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

<#
#>
Function New-NormalisedUri
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([System.Uri])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Obj
    )

    process
    {
        $tempUri = [Uri](([Uri]$Obj).AbsoluteUri.ToLower())
        $uri = [Uri]::New(("{0}://{1}:{2}" -f $tempUri.Scheme, $tempUri.Host, $tempUri.Port))

        $uri
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
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
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

        # Generate parameters for Add-AzTableRow call
        $tableArgs = @{
            Table = $Table
            PartitionKey = $UsageType
            RowKey = $rowKey
            Property = @{
                Thumbprint = $Thumbprint
                UsedBy = $UsedBy
                Seen = ([DateTime]::UtcNow.ToString("o"))
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
