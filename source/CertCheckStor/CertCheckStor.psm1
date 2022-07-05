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
        [ValidateNotNullOrEmpty()]
        [DateTime]$NotBefore,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
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
                NotBefore = $NotBefore.ToString("o")
                NotAfter = $NotAfter.ToString("o")
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
                    NotBefore = [DateTime]::Parse($obj.NotBefore)
                    NotAfter = [DateTime]::Parse($obj.NotAfter)
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

        [Parameter(Mandatory=$false)]
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
                    UsedBy = $obj.UsedBy
                    Seen = [DateTime]::Parse($obj.Seen)
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
        [ValidateNotNullOrEmpty()]
        [Uri]$Connection,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Sni,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [bool]$Connected,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Addresses,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [bool]$LocallyTrusted
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

        [Parameter(Mandatory=$true)]
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
                [PSCustomObject]@{
                    Connection = [Uri]::New($obj.Connection)
                    Sni = $obj.Sni
                    Thumbprint = $obj.Thumbprint
                    Connected = $obj.Connected
                    Addresses = $Addresses
                    LocallyTrusted = [bool]$LocallyTrusted
                }
            } catch {
                Write-Warning ("Could not transform data for entry: " + $_)
                Write-Warning ("Entry: " + ($obj | ConvertTo-Json))
            }
        }
    }
}
