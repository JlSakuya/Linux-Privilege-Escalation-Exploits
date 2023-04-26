#Note: make sure you have liburing-dev installed on your system
FILE_1 := poc_inode_locking
FILE_2 := poc_userfaultfd

FILES := $(FILE_1).c $(FILE_2).c

all: $(FILES)
	gcc $(FILE_1).c -static -l:liburing.a -o $(FILE_1).o
	gcc $(FILE_2).c -static -l:liburing.a -o $(FILE_2).o

