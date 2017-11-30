## Description ##  
This program can be used to give users access to files they do not have regular permissions for. An admin could use it to give certain users the ability to move files on a file-by-file basis. Each file gets a `.access` file to go with it. For example, if your file is `source.txt` then there would be a `source.txt.access` file in the directory with it. This file contains a list of names and permissions separated by whitespace. One name and permission per line. Comment lines begin with `#`. The admin sets up the `.access` files and the users run `get` and `put`.  


## Type of permissions ##  
• r - read  
• w - write  
• b - both  
`get` needs write permissions and `put` needs read permissions.  


## Example usage ##  
`./get somePath/src.ext dst.ext`  
`./put src.ext somePath/dst.ext`  

Note that the type of file should not matter.  


## Required file properties ##  

#### Both programs fail silently when any of these are true: ####
• ACL file does not exist  
• ACL file is a symbolic link  
• Existence of a malformed entry  
• basename.ext is not an ordinary file  
• Protection for basename.ext.access allows any world or group access (via the standard UNIX file protections)  

#### Using get requires the following: ####
• Source is owned by the effective uid of the executing process,  
• The effective uid of the executing process has read access to source  
• The file source.access exists and indicates read access for the real uid of the executing process,  
• The real uid of the executing process can write the file destination.  

#### Using put requires the following: ####
• The effective uid of the executing process owns destination  
• The effective uid of the executing process has write access to the file destination  
• The file destination.access exists and indicates write access for the real uid of the executing process  
• The real uid of the executing process may read source  


## Notes ##  
• This program functions by temporarily setting the effective user id (the user) to the real user id (the admin) in order to check the properties of the files and then quickly change back before moving the file.  
• In `get` the source is protected. In `put`, the destination is protected  
• If the file does not already exist in the destination, it will be created with permission 0400.
