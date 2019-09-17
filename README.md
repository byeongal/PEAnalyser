# PEAnalyser
PEAnalyser is an open source software analyzing PE files. It is programmed using Python 3. To program this, the following projects were referred to.

* [Pefile](https://github.com/erocarrera/pefile)
* [PeFrame](https://github.com/guelfoweb/peframe)
* ExeInfo

## Requirement
To use this program, you need to install some programs. I upload requirement.sh.
```bash
$ chmod +x requirement.sh
$ sudo ./requirement.sh
$ pip3 install -r requirement.txt
```

## Usage
```python
from PEAnalyser import PEAnalyser
peanalyser = PEAnalyser('1a096a1650ec2ea3897228329610298f.vir')
peanalyser.dump_json('1a096a1650ec2ea3897228329610298f.json')
```