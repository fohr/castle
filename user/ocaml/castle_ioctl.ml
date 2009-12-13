
external castle_ioctl : Unix.file_descr -> int32 -> int32 = "castle_ioctl"

let cmd = Int32.of_string (Sys.argv.(1));;

let fh = Unix.openfile "/proc/xen/privcmd" [Unix.O_RDWR] 0;;

let result = castle_ioctl fh cmd;;

Printf.printf "result: %i"