# microsoftSnortRule
MS Login Pshing

These are detection rules based around a mailicous 
The two other files in this repositries contain the rules for zeek and snort

```regex
function\s+\w+\(\w+, \w+\) \{\s+let \w+ = '';\s+\w+ = atob\(\w+\);\s+let \w+ = \w+\.length;\s+\s+for \(let i = 0; i < \w+\.length; i\+\+\) \{\s+\w+ \+= String\.fromCharCode\(\w+\.charCodeAt\(i\) \^ \w+\.charCodeAt\(i % \w+\)\);\s+\}\s+\s+return \w+;\s+\}
```
