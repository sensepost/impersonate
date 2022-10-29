# Impersonate

## Description

This repo contains the toolings that was developped while writing the following blog post [ LINK ]. The blog post contains all necesary information to understand how the token manipulation internal mechanism works and how we can use it to our advantage.

## Content

This repo contains four tools:
- A standalone binary (Impersonate/) that you can use to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively
- The CrackMapExec python module (impersonate.py) with the embedded Impersonate binary 
- The embedded CrackMapExec binary (CME_module/) which is the same as the Impersonate.exe binary without printf's 
- The list_tokens.c C++ code that is presented on the blog post

## Impersonate.exe usage

The Impersonate.exe tool contains three modules:
- Impersonate list: which will list available tokens
- Impersonate exec: which will allow you running commands impersonating a user
- Impersonate adduser: which will allow you elevating your privileges to domain admin

## Compilation instructions

In order to compile the projects you will have to switch the Runtime library options to Multi-threaded Debug (/MtD) in the project properties.

