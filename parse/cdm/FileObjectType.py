FileObjectType = [
    'FILE_OBJECT_BLOCK',       # block special file
    'FILE_OBJECT_CHAR',        # character special file
    'FILE_OBJECT_DIR',         # directory
    'FILE_OBJECT_FILE',        # regular file
    'FILE_OBJECT_LINK',        # link
    'FILE_OBJECT_NAMED_PIPE',  # named pipe
    'FILE_OBJECT_PEFILE',      # PE file
    'FILE_OBJECT_UNIX_SOCKET'  # UNIX socket
]

file_object_type = {}
for i, item in enumerate(FileObjectType):
    file_object_type[item] = i