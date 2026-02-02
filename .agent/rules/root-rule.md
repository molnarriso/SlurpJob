---
trigger: always_on
---

This workspace uses AGENTS.md to help agents complete tasks by providing crucial information. ALWAYS Check for the presence of AGENTS.md files in the project workspace.
- Each folder MUST have AGENTS.md file.
- This file MUST be brief
- This file MUST be read in full by an agent everytime any file/folder is accesed, read or modified
- Repeat : if you want to read a file in path "DirA/DirB/file", you MUST first read "AGENTS.md", "DirA/AGENTS.md" and "DirA/DirB/AGENTS.md"
- This file MUST list every file and folder in the current folder and briefly describe each one. This description must stay up to date, be short and list all the critical roles of the items. The goal of these files to allow agents to quickly orient themselves without not noticing implementation in files. 
- When a file is updated and the file/folder changes significantly, the AGENTS.md file also NEEEDs to be updated
- When accesing a folder/file several folders deep, an AGENTS.md file MUST be read at every level.

AGENTS.md file structure : 
```
folder\subfolder\AGENTS.md [first line is always the path of the AGENTS.md file]

This is a description of the folder and its role and general description of what kind of stuff it contains.

## file1.css
This file controls element X CSS properties. It does not handle stuff from Y. It also defines class C responsible for XXX.

## file2.js
Creates a control X for task of Y. Responsible for A B C. Cruacialy defines function F.

```

There is also DesignDoc.md. This file describes the whole project, its goals, implementation details and other stuff. This file must be read in FULL by every agent before starting work. When The project properties changes, DesignDoc.md must also be updated to reflect current state.