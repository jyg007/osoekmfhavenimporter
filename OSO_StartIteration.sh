#!/bin/bash

SOURCE="INPUTBRIGDEOSMSGS.PREITERATION"
DEST="INPUTBRIGDEOSMSGS"

    # Check if file has data (size > 0)
    if [[ -s "$SOURCE" ]]; then
        
        # 1. 'cat' the content into the destination file.
        # This reads the current state of the file safely.
        cat "$SOURCE" > "$DEST"
        
        # 2. Atomic Truncation. 
        # This empties the file without deleting the file entry from the folder.
        # If a Python script is currently writing to it, the pointer 
        # usually stays valid, and the file just starts growing from 0 again.
        : > "$SOURCE"
      fi 
