
external castle_ioctl : Unix.file_descr -> int32 -> int64 -> int32 = "castle_ioctl"

let cmd = Int32.of_string (Sys.argv.(1))

let arg = Int64.of_string (Sys.argv.(2))

let fh = Unix.openfile "/dev/castle/control" [Unix.O_RDWR] 0;;

let result = castle_ioctl fh cmd arg;;

Printf.printf "result: %i"