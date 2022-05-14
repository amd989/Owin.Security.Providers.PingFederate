$root = $env:APPVEYOR_BUILD_FOLDER
$version = [System.Reflection.AssemblyName]::GetAssemblyName("$root\Owin.Security.Providers.PingFederate\bin\Release\Owin.Security.Providers.PingFederate.dll").Version
$versionStr = "{0}.{1}.{2}" -f ($version.Major, $version.Minor, $version.Build)

Write-Host "Setting .nuspec version tag to $versionStr"

$content = (Get-Content $root\.nuget\Owin.Security.Providers.PingFederate.nuspec) 
$content = $content -replace '\$version\$',$versionStr

$content | Out-File $root\.nuget\Owin.Security.Providers.PingFederate.compiled.nuspec

& $root\.nuget\NuGet.exe pack $root\.nuget\Owin.Security.Providers.PingFederate.compiled.nuspec