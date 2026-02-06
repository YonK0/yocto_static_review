# Yocto Static Review

Simple Automated analysis tool for Yocto Project recipes. Check best practices, and style guide compliance.

## Features

**Static Analyzer** (`yocto_static_analysis.py`):

-   Security issues (hardcoded passwords, AUTOREV)
-   Path validation (absolute vs relative paths)
-   Layer organization (apps in BSP layers)
-   Code duplication detection

**Recipe Style Checker** (`yocto_style_checker.py`):
From: https://docs.yoctoproject.org/contributor-guide/recipe-style-guide.html
-   Recipe naming conventions
-   Variable formatting (tabs, spaces, quotes)
-   License fields (LICENSE, LIC_FILES_CHKSUM)
-   Patch tags (Upstream-Status, CVE)

## Usage

bash

```bash
Example 1 : python main.py /path/to/yocto_project meta-layer-name
Example 2 : python main.py /path/to/yocto_project meta-layer-bsp meta-layer-distro
```
