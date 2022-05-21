# zap-scripts
Zed Attack Proxy Scripts for finding CVEs and Secrets.

## Building

This project uses Gradle to build the ZAP add-on, simply run:

```bash
./gradlew build
```

in the main directory of the project, the add-on will be placed in the directory `build/zapAddOn/bin/`.

## Usage

The easiest way to use this repo in ZAP is to add the directory to
the scripts directory in ZAP (under Options -> Scripts).

however, you can also build the add on and install it (under File -> Load Addon File...).

## License

This software is distributed under the MIT License.

## Credits

The scripts under the `active` directory are mostly ported from the amazing [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository, so huge shoutout to [projectdiscovery](https://github.com/projectdiscovery) and the community.

`secret-finder.js` uses regex patterns from the awesome [gitleaks](https://github.com/zricethezav/gitleaks) project.

## LEGAL NOTICE

THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.

## Get Involved

**Please, send us pull requests!**
