---
layout: post
title: A technical analysis of Eset device blocker driver
---

Information Gathering

First thing I noticed after installing ESET Internel Security and running `fltmc filters` on command line is that it installed 2 mini-filter drivers named `eamonm` and `edevmonm`, looking at their `.INF` files we can see a small description about them:
`ServiceDescription = "Eset file on-access scanner"` for `eamonm`
`ServiceDesc = "Eset device blocker"` for `edevmonm`

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


![_config.yml]({{ site.baseurl }}/images/config.png)

The easiest way to make your first post is to edit this one. Go into /_posts/ and update the Hello World markdown file. For more instructions head over to the [Jekyll Now repository](https://github.com/barryclark/jekyll-now) on GitHub.