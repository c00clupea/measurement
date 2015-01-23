Measurement

This is a Measurementtool for the C00clupea Honeypot.

This tool will show the same like htop or any other tool which depends on procfs.

However, when you want to know how much memory your application will use, every measurement based on procfs is the wrong way....

Use valgrind for this purpose.

However when you want to see what the user is able to see, you can use this tool.

Use c00clupeaperf -m 100000 -c 100000 -t -v -a "100,200" "rate,rate1" -n -e "mylog_id_%s_type_%s.log" "sampleid" "somecommand" for some nice stats