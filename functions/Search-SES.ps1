function Search-SES {
    [CmdletBinding()]
    param (
        # The Observable that you are querying for
        [Parameter(Mandatory = $true)]
        [string]
        $Query,
        # Token used for authentication
        [Parameter(Mandatory = $false)]
        [string]
        $Token = $SES_TOKEN,
        # Observable type
        [Parameter(Mandatory = $false)]
        [ValidateSet('ipv4', 'ipv6', 'fqdn', 'url', 'email')]
        [String]
        $ObservableType,
        # Switch that logs the query in SES.
        [Parameter(Mandatory = $false)]
        [switch]
        $LogQuery,
        # A layer 4 protocol. Ex: icmp, tcp, udp
        [Parameter(Mandatory = $false)]
        [string]
        $Protocol,
        # The country code to filter on
        [Parameter(Mandatory=$false)]
        [string]
        $CountryCode,
        # The ASN to filter on
        [Parameter(Mandatory = $false)]
        [int]
        $ASN,
        # The confidence (or greater) to filter on
        [Parameter(Mandatory = $false)]
        [int]
        $Confidence,
        # The group(s) to filter on (Multiple accepted as OR)
        [Parameter(Mandatory = $false)]
        [string[]]
        $Group,
        # The tag(s) to filter on (Multiple accepted as OR)
        [Parameter(Mandatory = $false)]
        [string[]]
        $Tags,
        # The provider(s) to filter on (Multiple accepted as AND)
        [Parameter(Mandatory = $false)]
        [string[]]
        $Provider,
        # The application(s) to filter on (Multiple accepted as AND)
        [Parameter(Mandatory = $false)]
        [string[]]
        $Application,
        # Text description of the observable
        [Parameter(Mandatory = $false)]
        [string]
        $Description,
        # Reported timestamp, (YYYY-MM-DDTHH:MM:SSZ) - Greater than or equal to
        [Parameter(Mandatory = $false)]
        [string]
        $ReportTime,
        # A filter to limit results, (YYYY-MM-DDTHH:MM:SSZ) - Less than or equal to
        [Parameter(Mandatory = $false)]
        [string]
        $ReportTimeEnd,
        # First seen machine generated timestamp, (YYYY-MM-DDTHH:MM:SSZ) - Greater than or equal to
        [Parameter(Mandatory = $false)]
        [string]
        $FirstTime,
        #Last seen machine generated timestamp, (YYYY-MM-DDTHH:MM:SSZ) - Less than or equal to
        [Parameter(Mandatory = $false)]
        [string]
        $LastTime,
        # Limits the results returned. Defailt limit is 10.
        [Parameter(Mandatory = $false)]
        [int]
        $ResultSize=10,
        # The host you are sending your query to.
        [Parameter(Mandatory=$false)]
        [string]
        $SESRemote="https://feeds.ses.ren-isac.net",
        # Writes the response out to host as a table
        [Parameter(Mandatory=$false)]
        [switch]
        $OutTable
    )

    begin {
        $sessdkVersion = "1.0"
        $Call = @{
            Headers       = @{
                "Accept"        = 'application/vnd.cif.v0+json'
                "User-Agent"    = 'ri-sessdk-pwsh/{0}' -f $sessdkVersion
                "Authorization" = 'Token token={0}' -f $Token
                "Content-Type"  = 'application/json'
            }
            Method        = "GET"
            Uri           = "{0}/observables?q={1}&limit={2}" -f $SESRemote, $Query, $ResultSize
            ErrorAction   = "STOP"
            ErrorVariable = "CallError"
        }
        $QueryResults = New-Object -TypeName System.collections.arraylist
        if($PSBoundParameters.ContainsKey('ObservableType')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "otype",$ObservableType
        }
        if($PSBoundParameters.ContainsKey('LogQuery')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "nolog",0
        } else {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "nolog",1
        }
        if($PSBoundParameters.ContainsKey('Protocol')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "protocol",$Protocol
        }
        if($PSBoundParameters.ContainsKey('ASN')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "asn",$ASN
        }
        if($PSBoundParameters.ContainsKey('Confidence')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "confidence",$Confidence
        }
        if($PSBoundParameters.ContainsKey('Group')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "group",($Group -join ',')
        }
        if($PSBoundParameters.ContainsKey('Tags')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "tags",($Tags -join ',')
        }
        if($PSBoundParameters.ContainsKey('Provider')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "provider",($Provider -join ',')
        }
        if($PSBoundParameters.ContainsKey('Application')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "application",($Application -join ',')
        }
        if($PSBoundParameters.ContainsKey('Description')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "description",$Description
        }
        if($PSBoundParameters.ContainsKey('ReportTime')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "reporttime",$ReportTime
        }
        if($PSBoundParameters.ContainsKey('ReportTimeEnd')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "reporttimeend",$ReportTimeEnd
        }
        if($PSBoundParameters.ContainsKey('FirstTime')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "firsttime",$FirstTime
        }
        if($PSBoundParameters.ContainsKey('LastTime')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "lasttime",$LastTime
        }
        if($PSBoundParameters.ContainsKey('CountryCode')) {
            $Call.Uri = $Call.Uri + "&{0}={1}" -f "cc",$CountryCode
        }
        Write-Verbose -Message "Calling $($Call.uri)"
    }

    process {
        try {
            $Ret = Invoke-WebRequest @Call
            foreach ($record in ($ret.content|ConvertFrom-Json)){
                $QueryResults.add($record)|Out-Null
            }
        }
        catch [System.Net.WebException] {
            Write-Error $_
        }
    }

    end {
        if ($OutTable) {
            $QueryResults|Select-Object tlp, group, lasttime, reporttime, observable, otype, confidence, tags|Format-Table
        }
        else {
            return $QueryResults
        }
    }
}