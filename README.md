Use `osqueryd` to update the Munki `ConditionalItems.plist`. 
You can run the binary as a munki preflight script.
This utility assumes osquery is already running in your environment. 

# Usage

```
Usage of ./osquery-condition:
  -queries string
    	path to line delimited query file
  -socket string
    	path to osqueryd socket (default "/var/osquery/osquery.em")
```

Example: 

```
sudo ./osquery-condition -queries ./sample_queries
sudo cat '/Library/Managed Installs/ConditionalItems.plist'
```

# Creating queries

To create queries for osqueryd to run, write them in a text file, *one line per query*.
Your queries are expected to return key/value pairs as results. 
For example, `select * from system_info;` would return a list of key/values. When updating the `ConditionalItems.plist` file, all the keys will be prefixed with `osquery_`.

