---
layout: post
title: A technical analysis of Eset device blocker driver
---

Information Gathering

First thing I noticed after installing ESET Internel Security and running `fltmc filters` on command line is that it installed 2 mini-filter drivers named `eamonm` and `edevmonm`, looking at their `.INF` files we can see a small description about them:
`ServiceDescription = "Eset file on-access scanner"` for `eamonm`
`ServiceDesc = "Eset device blocker"` for `edevmonm`

![fltmc_filters]({{ site.baseurl }}/images/fltmc_filters.png)


In this post (which will probably be in parts) I will try to review the `edevmonm` driver.

I continued to look at the `edevmonm.inf` and found that it regiters itself as a filter driver for a number of device class GUIDs:

```
[EDEVMON.ClassAddReg]
;
; Change {setup-ClassGUID} to the string form of the ClassGUID that you are installing the filter on.
;
; Change UpperFilters to LowerFilters if this is a lower class filter.
;
HKLM, System\CurrentControlSet\Control\Class\{4D36E967-E325-11CE-BFC1-08002BE10318}, UpperFilters, 0x00010008, %ServiceName%		; Disk drives
HKLM, System\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}, UpperFilters, 0x00010008, %ServiceName%		; DVD/CD-ROM drives
HKLM, System\CurrentControlSet\Control\Class\{4D36E980-E325-11CE-BFC1-08002BE10318}, UpperFilters, 0x00010008, %ServiceName%		; Floppy disk drives
HKLM, System\CurrentControlSet\Control\Class\{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}, UpperFilters, 0x00010008, %ServiceName%		; Imaging devices 
HKLM, System\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}, LowerFilters, 0x00010008, %ServiceName%		; Universal Serial Bus controllers
HKLM, System\CurrentControlSet\Control\Class\{E0CBF06C-CD8B-4647-BB8A-263B43F0F974}, LowerFilters, 0x00010008, %ServiceName%		; Bluetooth Radios
HKLM, System\CurrentControlSet\Control\Class\{F12D3CF8-B11D-457E-8641-BE2AF2D6D204}, UpperFilters, 0x00010008, %ServiceName%		; Bluetooth USB (BlueSoleil)
HKLM, System\CurrentControlSet\Control\Class\{50DD5230-BA8A-11D1-BF5D-0000F805F530}, UpperFilters, 0x00010008, %ServiceName%		; Smart card readers
HKLM, System\CurrentControlSet\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}, UpperFilters, 0x00010008, %ServiceName%		; Modems
HKLM, System\CurrentControlSet\Control\Class\{4D36E978-E325-11CE-BFC1-08002BE10318}, LowerFilters, 0x00010008, %ServiceName%		; Ports (COM & LPT)
HKLM, System\CurrentControlSet\Control\Class\{EEC5AD98-8080-425F-922A-DABF3DE3F69A}, UpperFilters, 0x00010008, %ServiceName%		; WPD
;; HKLM, System\CurrentControlSet\Control\Class\{4D36E96C-E325-11CE-BFC1-08002BE10318}, UpperFilters, 0x00010008, %ServiceName%		; MEDIA
HKLM, System\CurrentControlSet\Control\Class\{CA3E7AB9-B4C3-4AE6-8251-579EF933890F}, UpperFilters, 0x00010008, %ServiceName%		; Camera
```

I also noticed that this driver uses traditional filesystem minifilter api:
![flt_imports]({{ site.baseurl }}/images/flt_imports.png)

Looking at the drivers mounted to my webcam, I can also see it there:
![camera_filter]({{ site.baseurl }}/images/camera_filter.png)

So this is quite weird for me; A file-system minifilter driver that is also mounted on other devices such as the Webcam? I had to dig deeper and understand this.

ESET Internet Security has a webcam protection feature:
![webcam_feature]({{ site.baseurl }}/images/webcam_feature.png)

Opening the `Camera` application on windows pop this message:
![webcam_attempt]({{ site.baseurl }}/images/webcam_attempt.png)


While the image we see on the Camera application display is black, so they must replace the stream that is getting from the Camera device itself to the application.

Looking at strings I found some function names which led me to a function I named `getSystemRoutines`:

```c
PVOID getSystemRoutines()
{
  PVOID temp;
  UNICODE_STRING DestinationString;
  __int64 MajorVersion;

  LODWORD(MajorVersion) = 0;
  RtlInitUnicodeString(&DestinationString, L"PsGetVersion");
  krnPsGetVersion = MmGetSystemRoutineAddress(&DestinationString);
  RtlInitUnicodeString(&DestinationString, L"WmiTraceMessage");
  krnWmiTraceMessage = MmGetSystemRoutineAddress(&DestinationString);
  RtlInitUnicodeString(&DestinationString, L"WmiQueryTraceInformation");
  temp = MmGetSystemRoutineAddress(&DestinationString);
  krnWmiQueryTraceInformation = temp;
  mysteriousVarFromGetSystemsRoutine = 2;
  if ( krnPsGetVersion )
    temp = krnPsGetVersion(&MajorVersion, 0i64, 0i64, 0i64);
  if ( MajorVersion >= 6 )
  {
    RtlInitUnicodeString(&DestinationString, L"EtwRegisterClassicProvider");
    temp = MmGetSystemRoutineAddress(&DestinationString);
    krnEtwRegisterClassicProvider = temp;
    if ( temp )
    {
      RtlInitUnicodeString(&DestinationString, L"EtwUnregister");
      temp = MmGetSystemRoutineAddress(&DestinationString);
      mysteriousVarFromGetSystemsRoutine = 4;
    }
  }
  return temp;
}
```


XRefing `MmGetSystemRoutineAddress` yields another interesting function:

```c
PVOID WdmlibIointexInit()
{
  PVOID result; // rax
  UNICODE_STRING DestinationString; // [rsp+20h] [rbp-18h]

  RtlInitUnicodeString(&DestinationString, L"IoCreateDeviceSecure");
  krnIoCreateDeviceSecure = MmGetSystemRoutineAddress(&DestinationString);
  if ( !krnIoCreateDeviceSecure )
    krnIoCreateDeviceSecure = sub_FFFFF80B9BE42940;
  RtlInitUnicodeString(&DestinationString, L"IoValidateDeviceIoControlAccess");
  result = MmGetSystemRoutineAddress(&DestinationString);
  krnIoValidateDeviceIoControlAccess = result;
  byte_FFFFF80B9BE403D8 = 1;
  return result;
}
```

So the call to `IoCreateDeviceSecure` probably creates the device that this drivers attaches as a filter to the other devices such as my webcam. Xrefing the function-pointer to `IoCreateDeviceSecure` leads to some information about the device it opens, I eventually traced the call to the function and ended up looking at `AddDevice` function: `DriverObject->DriverExtension->AddDevice = addDevice;` at `edevmon+0x54D0`.

The AddDevice function
So this function is called whenever a device that's in this driver responsibility, so there must be a call to `IoAttachDeviceToDeviceStack` somewhere down this path.



The easiest way to make your first post is to edit this one. Go into /_posts/ and update the Hello World markdown file. For more instructions head over to the [Jekyll Now repository](https://github.com/barryclark/jekyll-now) on GitHub.