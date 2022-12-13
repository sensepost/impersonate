# Impersonate

## Description

This repo contains the toolings that was developped while writing the following blog post https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/. The blog post contains all necesary information to understand how the token manipulation internal mechanism works and how we can use it to our advantage.

## Content

This repo contains four tools:
- A standalone binary (Impersonate/) that you can use to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively
- The CrackMapExec python module (impersonate.py) with the embedded Impersonate binary 
- The embedded CrackMapExec binary (CME_module/) which is the same as the Impersonate.exe binary without printf's 
- The list_tokens.c C++ code that is presented on the blog post

## Impersonate.exe usage

The Impersonate.exe tool contains three modules:
- Impersonate list: which will list available tokens
![image](https://user-images.githubusercontent.com/23189983/207414707-7851b866-f3dd-4a17-8195-6c24f13ceb91.png)
- Impersonate exec: which will allow you running commands impersonating a user
- Impersonate adduser: which will allow you elevating your privileges to domain admin

## Compilation instructions

In order to compile the projects you will have to switch the Runtime library options to Multi-threaded Debug (/MtD) in the project properties.

