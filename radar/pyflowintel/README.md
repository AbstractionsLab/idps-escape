# PyFlowintel

[PyFlowintel](https://github.com/AbstractionsLab/PyFlowintel) is a Python library for interacting with [Flowintel](https://github.com/flowintel/flowintel) instances through their REST API. Flowintel is an open-source platform for security case management.

The current version of RADAR uses an initial minimal version of PyFlowintel as a standalone, self-contained piece of code in the `radar_ar.py` file under `scenarios/active_responses`. This initial implementation code has been then further developed as part of project CyFORT and released as [PyFlowintel](https://github.com/AbstractionsLab/PyFlowintel). 

In the next release, this `pyflowintel` folder will be removed and its functionality will be provided by the [DECIPHER service](https://github.com/AbstractionsLab/satrap-dl/blob/main/decipher/README.md) (a subsystem of [SATRAP-DL](https://github.com/AbstractionsLab/satrap-dl)), which will in turn import PyFlowintel as a library in its code.