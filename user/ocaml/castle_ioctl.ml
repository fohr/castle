
external castle_ioctl : Unix.file_descr -> int32 -> int64 -> int32 = "castle_ioctl"

let castle_ctrl_cmd_ret = Int32.of_int 117  

let return ~value =
	let fh = Unix.openfile "/dev/castle/control" [Unix.O_RDWR] 0 in
	let result = castle_ioctl fh castle_ctrl_cmd_ret value in
	  Unix.close fh;
	  result
	 	