# ClassInformerPython #
#### Another RTTI Parsing IDA plugin ####

### Features ###
* All ida-python
* Class based design, error logging
* RTTI parsing algorithm scanning for vtables first (instead of
bruteforcing the entire rdata/data sections)
* Graphing of class hierarchy (using transitive reduction for clarity)
* Export functionality to GraphViz (.dot) format
* Handles RTTI and C++ name demangling for:
  * X86 GCC
  * X86 MSVC
  * X64 GCC
  * X64 MSVC

### Usage ###
Simple: First load your binary in IDA. Then run script `classinformerpython.py`
To export the dot file, either right click on the class diagram and select
`export` or just hit F2.

### References ###
GraphView reference: http://www.graphviz.org/
Online viewer: http://www.webgraphviz.com/
